"""A bare domain discovers its HTTP origin when HTTPS is unavailable."""

import httpx

from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.discovery import EndpointDiscovery
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.sensing import ReconSensing
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def test_default_domain_profile_probes_http_with_pinned_host(tmp_path):
    task, boundary = admit_target("example.test", "http-only", pinned_addresses=("127.0.0.1",))
    assert {80, 443, 8080, 8443}.issubset(set(task.scope.allowed_ports))
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    seen = []

    def respond(request):
        seen.append((request.url.scheme, request.url.host, request.headers.get("host")))
        if request.url.scheme == "http" and request.url.port is None:
            return httpx.Response(200)
        raise httpx.ConnectError("closed")

    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(httpx.MockTransport(respond)))
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(
        lambda request: httpx.Response(200 if request.url.scheme == "http" else 404,
                                      stream=httpx.ByteStream(b"ok"), headers={"content-type": "text/plain"}))))
    gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    service = ReconService(repository, gateway)
    engine = type("Engine", (), {"repository": repository, "service": service})()
    sensing = ReconSensing(engine)
    sensing.web_service_discovery(task.id)
    assert ("http", "127.0.0.1", "example.test:80") in seen
    assert any(origin.startswith("http://example.test:80/") for origin in sensing.verified_origins(task))
    EndpointDiscovery(repository, ReconPlanner(), service).run(task, sensing.verified_origins(task))
    assert any(source.url == "http://example.test:80/robots.txt" and source.status == "PARSED"
               for source in repository.list_sources(task.id))
