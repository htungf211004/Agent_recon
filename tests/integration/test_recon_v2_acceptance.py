"""Local V2 root, descendant, API and external-sink acceptance without live LLM."""

import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Thread

from src.contracts.recon_assets import AssetScopeStatus, AssetVerificationStatus
from src.contracts.recon_manual_review import api_manual_review
from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.agent import ReconAgent
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.llm_planner import LLMReconPlanner
from src.recon.models import Capability, Scope, WebOrigin
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.rag.models import KnowledgeChunk
from src.recon.rag.retriever import InMemoryKnowledgeRetriever
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from tests.test_recon_adaptive_planning import STOP, FakeModel


def test_root_only_input_discovers_verifies_and_never_dispatches_external(tmp_path):
    calls, sink_calls = [], []
    class Sink(BaseRequestHandler):
        def handle(self):
            sink_calls.append(True)
    sink = ThreadingTCPServer(("127.0.0.1", 0), Sink)
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            calls.append((self.command, self.headers.get("Host"), self.path))
            port = self.server.server_port
            pages = {
                "/": ("text/html", f'<html><a href="/admin">Admin</a><a href="http://api.example.test:{port}/v1">API</a>'
                      f'<a href="http://cdn.thirdparty.test:{sink.server_address[1]}/thing">CDN</a>'
                      '<script src="/app.js"></script></html>'),
                "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /hidden\nSitemap: /sitemap.xml"),
                "/sitemap.xml": ("application/xml", f"<urlset><url><loc>http://example.test:{port}/api</loc></url></urlset>"),
                "/openapi.json": ("application/json", json.dumps({"openapi": "3.0.0", "info": {"title": "Lab", "version": "1"},
                                   "paths": {"/declared": {"get": {}}, "/mutate": {"post": {}}}})),
                "/app.js": ("application/javascript", "fetch('/api');//# sourceMappingURL=app.js.map"),
                "/.git/HEAD": ("text/plain", "ref: refs/heads/main"),
                "/app.js.map": ("application/json", "{}"),
                "/admin": ("text/html", "<html>admin</html>"),
                "/api": ("application/json", "{}"),
                "/v1": ("application/json", "{}"),
            }
            mime, body = pages.get(self.path, ("text/plain", "missing"))
            raw = body.encode()
            self.send_response(404 if body == "missing" else 200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [Thread(target=s.serve_forever, daemon=True) for s in (server, sink)]
    for thread in threads:
        thread.start()
    try:
        port = server.server_port
        task, boundary = admit_target("example.test", "v2-local", pinned_addresses=("127.0.0.1",))
        task = task.model_copy(update={"scope": Scope(
            allowed_ips=("127.0.0.1",), allowed_ports=(port,), allowed_paths=("/",),
            capabilities=(Capability.DNS_RESOLVE, Capability.HTTP_PROBE, Capability.HTTP_FETCH),
            web_origin=WebOrigin(host="example.test", scheme="http", port=port, pinned_ip="127.0.0.1"))})
        repository = ReconRepository(tmp_path / "recon.db")
        repository.save_task(task)
        repository.save_authorization(boundary)
        class Dns:
            def execute(self, request):
                return AdapterOutput(status="success", raw_output=json.dumps({
                    "host": request.parameters.host, "addresses": ["127.0.0.1"]}).encode())
        registry = CapabilityRegistry()
        registry.register(Capability.DNS_RESOLVE, Dns())
        registry.register(Capability.HTTP_PROBE, HttpProbeAdapter())
        registry.register(Capability.HTTP_FETCH, HttpFetchAdapter())
        gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                       evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
        service = ReconService(repository, gateway)
        engine = ReconAgent(repository, ReconPlanner(), service)
        excerpt = "Prioritize evidence-backed routes."
        chunk = KnowledgeChunk(knowledge_id="method", namespace="attack_surface_methodology", source_id="fixture",
                               title="Local method", excerpt=excerpt,
                               content_hash=hashlib.sha256(excerpt.encode()).hexdigest(), version="1")
        model = FakeModel(STOP)
        agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="v2-local"),
                                   retriever=InMemoryKnowledgeRetriever((chunk,)),
                                   execution_mode="deterministic_fallback")
        result = agent.run(task.id)
        assets = repository.asset_inventory(task.id).assets
        assert any(a.canonical_value.endswith("/admin") and a.verification_status == AssetVerificationStatus.VERIFIED
                   and a.verification_evidence_refs for a in assets)
        assert any(a.canonical_value == "api.example.test" and a.scope_status == AssetScopeStatus.IN_SCOPE for a in assets)
        assert repository.get_binding(task.id, "api.example.test", "http", port)
        assert any("cdn.thirdparty.test" in a.canonical_value and a.scope_status == AssetScopeStatus.OUT_OF_SCOPE
                   for a in assets)
        assert any(a.canonical_value.endswith("/openapi.json") for a in assets)
        assert api_manual_review(assets)
        assert any(entry.canonical_path == "/declared" for entry in result.attack_surface_inventory.entries)
        assert not any(path in {"/declared", "/mutate"} or method == "POST" for method, _, path in calls)
        assert sink_calls == []
        assert model.contexts[0]["knowledge_refs"][0]["knowledge_id"] == "method"
        assert result.worker_status == "COMPLETED"
        before = list(calls)
        assert agent.run(task.id).worker_status == "COMPLETED"
        assert calls == before
    finally:
        for target in (server, sink):
            target.shutdown()
            target.server_close()
        for thread in threads:
            thread.join(timeout=5)
