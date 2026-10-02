"""The default agent chooses typed tools before any target I/O, then replans from evidence."""

import json

import httpx

from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.agent import ReconAgent
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.llm_planner import LLMReconPlanner
from src.recon.models import Capability, Scope, WebOrigin
from src.recon.offline_analysis import OfflineEvidenceAdapter
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def test_llm_tool_evidence_replan_and_signal_blocks_early_stop(tmp_path):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        pages = {
            "/": ("text/html", b'<html><script src="/app.js"></script></html>'),
            "/app.js": ("application/javascript", b'//# sourceMappingURL=app.js.map'),
            "/app.js.map": ("application/json", b'{"version":3,"sources":["app.js"],"names":[],"mappings":""}'),
        }
        mime, body = pages.get(request.url.path, ("text/plain", b"missing"))
        return httpx.Response(200 if request.url.path in pages else 404,
            headers={"content-type": mime, "server": "Test/1"},
            stream=httpx.ByteStream(b"" if request.method == "HEAD" else body))

    task, boundary = admit_target("example.test", "autonomous-lab", pinned_addresses=("127.0.0.1",))
    port = 8000
    task = task.model_copy(update={"scope": Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port,),
        allowed_paths=("/",), capabilities=(Capability.HTTP_PROBE, Capability.HTTP_FETCH,
            Capability.SOURCEMAP_ANALYZE),
        web_origin=WebOrigin(host="example.test", scheme="http", port=port, pinned_ip="127.0.0.1"))})
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    registry = CapabilityRegistry()
    transport = httpx.MockTransport(handler)
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(transport))
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(transport))
    gateway = ToolExecutionGateway(PolicyService(repository), registry,
        EvidenceStore(tmp_path / "evidence", repository), repository)
    registry.register(Capability.SOURCEMAP_ANALYZE, OfflineEvidenceAdapter(gateway.evidence))
    engine = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))

    class Model:
        def __init__(self):
            self.contexts = []

        def invoke(self, messages):
            context = json.loads(messages[1][1])
            self.contexts.append(context)
            index = len(self.contexts)
            if index == 1:
                assert calls == [] and repository.list_tool_results(task.id) == ()
            asset = next(row["asset_id"] for row in context["assets"] if row["value"] == "example.test")
            if index == 4:
                assert any(s["kind"] == "SOURCE_MAP_REFERENCE" for s in context["residual_signals"])
                kind = "stop"
                params = {"reason_code": "COVERAGE_SUFFICIENT"}
            elif index == 6:
                assert any(s["kind"] == "UNANALYZED_SOURCE_MAP" for s in context["residual_signals"])
                kind = "evidence_capability"
                source = next(row for row in context["evidence"] if row["path"] == "/app.js.map")
                params = {"capability": "sourcemap_analyze", "evidence_ref": source["evidence_ref"],
                          "parameters": {"profile": "sourcemap_metadata"}}
            elif index == 7:
                assert not any(s["kind"] in {"SOURCE_MAP_REFERENCE", "UNANALYZED_SOURCE_MAP"}
                               for s in context["residual_signals"])
                kind, params = "stop", {"reason_code": "NO_SAFE_SUPPORTED_ACTION"}
            else:
                path = {2: "/", 3: "/app.js", 5: "/app.js.map"}.get(index)
                kind, params = "target_capability", {"asset_id": asset,
                    "parameters": {"kind": "http_probe", "port": port, "scheme": "http"} if index == 1
                    else {"kind": "http_fetch", "port": port, "scheme": "http", "path": path,
                          "max_body_bytes": 65536}}
            return {"proposals": [{"kind": kind, **params, "priority": 1, "rationale": "cover observed gap"}]}

    model = Model()
    agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="autonomous-lab"))
    result = agent.run(task.id)
    assert len(model.contexts) == 7
    assert "inconsistent_stop_coverage" in agent.store.rounds(task.id)[3]["rejections"]
    assert calls == [("HEAD", "/"), ("GET", "/"), ("GET", "/app.js"), ("GET", "/app.js.map")]
    assert any(row.capability == Capability.SOURCEMAP_ANALYZE for row in result.tool_results)
    assert result.execution_mode == "llm" and result.stop_reason == "model_stop"
    assert result.coverage_score >= model.contexts[0]["coverage_score"]
    assert any(row.category == "SOURCE_MAP_REFERENCE" for row in result.attack_surface_candidates)
    assert all(row.evidence_refs and all(repository.get_evidence(ref) for ref in row.evidence_refs)
               for row in result.attack_surface_candidates)
    assert agent.run(task.id).attack_surface_candidates == result.attack_surface_candidates
    assert len(model.contexts) == 7 and len(calls) == 4
