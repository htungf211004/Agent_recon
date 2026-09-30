import hashlib
import json

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.asset_verification import AssetVerifier
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, HttpFetchParams, ReconPlan
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import HttpResponseMetadata


def test_derived_host_is_evidence_bound_and_stales_old_actions(tmp_path):
    dispatched = []
    class Dns:
        def execute(self, request):
            dispatched.append(("dns", request.parameters.host))
            return AdapterOutput(status="success", raw_output=json.dumps({
                "host": request.parameters.host, "addresses": ["127.0.0.2"]}).encode())
    class Http:
        def execute(self, request):
            dispatched.append(("http", request.target_host, request.target_ip, request.parameters.path))
            body = b"ok"
            return AdapterOutput(status="success", raw_output=body,
                                 http_response=HttpResponseMetadata(status_code=200, content_type="text/plain",
                                     body_size=2, body_sha256=hashlib.sha256(body).hexdigest(), truncated=False))
    task, boundary = admit_target("example.test", "derived", pinned_addresses=("127.0.0.1",))
    repository = ReconRepository(tmp_path / "db.sqlite")
    repository.save_task(task)
    repository.save_authorization(boundary)
    registry = CapabilityRegistry()
    registry.register(Capability.DNS_RESOLVE, Dns())
    registry.register(Capability.HTTP_FETCH, Http())
    policy = PolicyService(repository)
    gateway = ToolExecutionGateway(policy=policy, registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    service = ReconService(repository, gateway)
    old = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                               HttpFetchParams(port=443, scheme="https", path="/old")).request
    discovery = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                                      HttpFetchParams(port=443, scheme="https", path="/", max_body_bytes=16384))
    service.run(ReconPlan(task_id=task.id, actions=(discovery,)))
    evidence = repository.get_tool_result(discovery.request.id).evidence_id
    for kind, value in ((AssetType.HOST, "api.example.test"),
                        (AssetType.PATH, "https://api.example.test/v1")):
        repository.upsert_asset(DiscoveredAsset(
            run_id=task.run_id, task_id=task.id, root_target="example.test", asset_type=kind,
            canonical_value=value, relation=AssetRelation.HTML_REFERENCE, discovered_from="https://example.test/",
            discovery_evidence_refs=(evidence,), scope_status=AssetScopeStatus.IN_SCOPE,
            verification_status=AssetVerificationStatus.CLASSIFIED))
    AssetVerifier(repository, service).verify(task)
    binding = repository.get_binding(task.id, "api.example.test", "https", 443)
    assert binding and binding.address == "127.0.0.2"
    assert len(repository.list_dns_observations(task.id)) == 1
    assert ("dns", "api.example.test") in dispatched
    assert any(row[:3] == ("http", "api.example.test", "127.0.0.2") for row in dispatched)
    assert policy.decide(old).allowed is False
    changed = repository.get_task(task.id)
    assert changed.scope_version != task.scope_version
    assert repository.get_authorization(task.id) == boundary
    before = list(dispatched)
    AssetVerifier(repository, service).verify(changed)
    assert dispatched == before
