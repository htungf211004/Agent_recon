"""An IP root can only inherit a leaked hostname through matching Gateway DNS evidence."""

import json

import httpx
import pytest

from src.contracts.recon_assets import AssetRelation, AssetScopeStatus
from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.asset_extraction import record_candidate
from src.recon.asset_verification import AssetVerifier
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, HttpFetchParams, ReconPlan
from src.recon.origin_recon import OriginReconCoordinator
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


@pytest.mark.parametrize("answer,expected_dispatch", [("127.0.0.1", True), ("192.0.2.8", False)])
def test_ip_leaked_hostname_requires_matching_dns(tmp_path, answer, expected_dispatch):
    task, boundary = admit_target("127.0.0.1", "ip-dns")
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    calls = []

    def respond(request):
        calls.append((request.url.host, request.headers.get("host"), request.url.path))
        return httpx.Response(200, stream=httpx.ByteStream(b"<html>ok</html>"),
                              headers={"content-type": "text/html"})

    class Dns:
        def execute(self, request):
            return AdapterOutput(status="success", raw_output=json.dumps({
                "host": request.parameters.host, "addresses": [answer]}).encode())

    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(respond)))
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(httpx.MockTransport(respond)))
    registry.register(Capability.DNS_RESOLVE, Dns())
    gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    service = ReconService(repository, gateway)
    root = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                                HttpFetchParams(port=80, scheme="http", path="/", method="GET",
                                                max_body_bytes=16384))
    service.run(ReconPlan(task_id=task.id, actions=(root,)))
    root_result = repository.get_tool_result(root.request.id)
    assert root_result.status == "success", root_result.message
    evidence = root_result.evidence_id
    record_candidate(repository, task, boundary, "http://127.0.0.1:80/", evidence,
                     "https://api.example.test:443/v1", AssetRelation.HTML_REFERENCE)
    AssetVerifier(repository, service).verify(task)
    OriginReconCoordinator(repository, service).run(repository.get_task(task.id))
    assets = repository.list_assets(task.id)
    target = next(asset for asset in assets if asset.canonical_value.endswith("/v1"))
    assert (target.scope_status == AssetScopeStatus.IN_SCOPE) == expected_dispatch
    assert any(binding.host == "api.example.test" for binding in repository.list_bindings(task.id)) == expected_dispatch
    observation = repository.list_dns_observations(task.id)[0]
    with pytest.raises(ValueError, match="digest"):
        repository.save_dns_observation(task.id, observation, b"{}")
    assert any(host == "api.example.test:443" for _, host, _ in calls) == expected_dispatch
    if expected_dispatch:
        assert any(path == "/robots.txt" and host == "api.example.test:443" for _, host, path in calls), (
            [call for call in calls if "api.example" in call[1]],
            [(asset.canonical_value, asset.verification_status) for asset in assets if "api.example" in asset.canonical_value])
    before = list(calls)
    AssetVerifier(repository, service).verify(repository.get_task(task.id))
    OriginReconCoordinator(repository, service).run(repository.get_task(task.id))
    assert calls == before
