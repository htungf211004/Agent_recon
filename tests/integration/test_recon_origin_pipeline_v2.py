"""A derived hostname runs the same recursive discovery pipeline as its root."""

import json

import httpx
import pytest

from src.contracts.recon_assets import AssetScopeStatus, AssetVerificationStatus
from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.agent import ReconAgent
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.llm_planner import DeterministicReconPlanner
from src.recon.models import Capability
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.urls import request_url
from src.recon.wordlists import load_wordlist


@pytest.mark.parametrize("browser_available", [False, True])
def test_root_to_subdomain_recursive_discovery_and_mandatory_content_without_llm(tmp_path, browser_available):
    task, boundary = admit_target("example.test", "origin-pipeline", pinned_addresses=("127.0.0.1",))
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    calls = []

    def response(request):
        host = request.headers.get("host")
        path = request.url.path
        calls.append((request.method, host, path))
        if request.url.scheme != "http" or request.url.port not in {None, 80}:
            raise httpx.ConnectError("closed")
        if host == "example.test:80" and path == "/":
            body = '<a href="http://api.example.test:80/">API</a><a href="http://outside.test:80/private">External</a>'
        elif host == "api.example.test:80" and path == "/":
            body = '<html><a href="/from-html">HTML path</a><script src="/app.js"></script></html>'
        elif host == "api.example.test:80" and path == "/robots.txt":
            body = "User-agent: *\nDisallow: /internal\n"
        elif host == "api.example.test:80" and path == "/app.js":
            body = "fetch('/js-route')"
        elif path == "/hidden":
            body = '<html><a href="/from-hidden">Hidden page link</a></html>'
        elif path in {"/internal", "/from-html", "/from-hidden", "/js-route"}:
            body = "ok"
        else:
            return httpx.Response(404, stream=httpx.ByteStream(b"missing"),
                                  headers={"content-type": "text/plain"})
        return httpx.Response(200, stream=httpx.ByteStream(body.encode()),
                              headers={"content-type": "text/html" if body.startswith("<") else "text/plain"})

    class Dns:
        def execute(self, request):
            return AdapterOutput(status="success", raw_output=json.dumps({
                "host": request.parameters.host, "addresses": ["127.0.0.1"]}).encode())

    class Content:
        def supports(self, _request):
            return True

        def execute(self, request):
            wordlist = load_wordlist(request.parameters.wordlist_id)
            url = request_url(request.target_ip, request.parameters.scheme, request.parameters.port,
                              "/hidden", target_host=request.target_host)
            return AdapterOutput(status="success", raw_output=json.dumps({
                "wordlist_id": wordlist.id, "wordlist_sha256": wordlist.sha256,
                "method": "HEAD", "candidates": [{"url": url, "status_code": 200}]}).encode())

    class Browser:
        def execute(self, request):
            calls.append(("BROWSER", request.target_host, request.parameters.path))
            return AdapterOutput(status="success", raw_output=json.dumps({
                "parent_request_id": request.id, "stop_reason": "converged"}).encode())

    registry = CapabilityRegistry()
    transport = httpx.MockTransport(response)
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(transport))
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(transport))
    registry.register(Capability.DNS_RESOLVE, Dns())
    registry.register(Capability.CONTENT_DISCOVERY, Content())
    if browser_available:
        registry.register(Capability.BROWSER_EXPLORE, Browser())
    gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    engine = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))
    agent = AdaptiveReconAgent(engine, DeterministicReconPlanner())
    result = agent.run(task.id)
    sources = repository.list_sources(task.id)
    assert any(source.url == "http://api.example.test:80/internal" and source.status == "PARSED" for source in sources)
    assert any(source.url == "http://api.example.test:80/from-html" and source.status == "PARSED" for source in sources)
    assert any(source.url == "http://api.example.test:80/js-route" and source.status == "PARSED" for source in sources)
    assert any(source.url == "http://api.example.test:80/from-hidden" and source.status == "PARSED" for source in sources)
    assert any(asset.canonical_value.endswith("/internal") and asset.verification_status == AssetVerificationStatus.VERIFIED
               for asset in repository.list_assets(task.id))
    assert any(asset.scope_status == AssetScopeStatus.OUT_OF_SCOPE and "outside.test" in asset.canonical_value
               for asset in repository.list_assets(task.id))
    assert not any(host and "outside.test" in host for _, host, _ in calls)
    assert any(item.status == "COMPLETE" for item in repository.list_origin_work(task.id))
    assert any(row.capability == Capability.CONTENT_DISCOVERY for row in result.tool_results)
    assert any(row.capability == Capability.BROWSER_EXPLORE for row in result.tool_results) == browser_available
    assert result.worker_status == "COMPLETED"
    # V3 records the missing mandatory local/provider capabilities as partial
    # coverage even when the original V2 browser and content path succeeds.
    assert result.coverage_outcome == ("PARTIAL" if browser_available else "LIMITED"), result.coverage.limitations
    before = list(calls)
    agent.run(task.id)
    assert calls == before
