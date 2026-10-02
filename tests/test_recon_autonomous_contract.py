"""Coverage and capability conversion checks for the autonomous controller."""

from datetime import UTC, datetime, timedelta

import httpx

from src.contracts.recon_planning import ChecklistSummary, ReconPlanningDecision, ReconPlanningLimits
from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter
from src.recon.coverage_evaluator import score_coverage
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.loop_projection import ensure_root_asset
from src.recon.models import Capability, HttpFetchParams, HttpProbeParams, ReconPlan, ReconTask, Scope
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.proposal_validator import ReconProposalValidator
from src.recon.residual_signals import ReconResidualSignal, may_stop
from src.recon.scope.admission import admit_target, normalize_target_input
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def test_coverage_score_exact_and_residual_blocks_ninety_percent():
    rows = (ChecklistSummary(id="PT_01-STT-02", status="COMPLETE", reason="verified"),
            ChecklistSummary(id="PT_01-STT-11", status="COMPLETE", reason="verified"),
            ChecklistSummary(id="PT_01-STT-13", status="BLOCKED", reason="adapter unavailable"))
    score = score_coverage(rows)
    assert score.score == 92.86 and score.mandatory_resolved
    assert may_stop(rows, ())
    signal = ReconResidualSignal(signal_id="map", kind="UNANALYZED_SOURCE_MAP",
        source_evidence_refs=("ev-1",), priority=1, suggested_capabilities=("sourcemap_analyze",))
    assert not may_stop(rows, (signal,))


def test_universal_target_normalization_preserves_root_and_explicit_path():
    assert normalize_target_input("example.com") == normalize_target_input("https://example.com/")
    assert normalize_target_input("example.com:8080").port == 8080
    assert normalize_target_input("[::1]:8080").root.value == "::1"
    task, boundary = admit_target("https://example.com/app", "url-path",
                                  pinned_addresses=("127.0.0.1",))
    assert boundary.root.value == "example.com"
    assert task.scope.allowed_paths == ("/app",) and task.discovery_seeds == ("/app",)


def test_capability_factory_uses_typed_gateway_requests_and_prerequisites(tmp_path):
    task = ReconTask(id="catalog", run_id="catalog", expires_at=datetime.now(UTC) + timedelta(minutes=5),
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(8000,), allowed_paths=("/",),
            capabilities=(Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.HTTP_FETCH,
                Capability.WHATWEB, Capability.WEB_CRAWL, Capability.GRAPHQL_DISCOVERY,
                Capability.SOURCEMAP_ANALYZE, Capability.EXPOSURE_DISCOVERY)))
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(AuthorizationBoundary(task_id=task.id,
        root=AuthorizedTarget(kind="IP", value="127.0.0.1")))
    ensure_root_asset(repository, task)
    asset = next(row for row in repository.list_assets(task.id) if row.relation == "ROOT")
    registry = CapabilityRegistry()
    transport = httpx.MockTransport(lambda request: httpx.Response(200,
        headers={"content-type": "application/json"},
        stream=httpx.ByteStream(b'{"version":3,"sources":[],"names":[],"mappings":""}')))
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(transport))
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(transport))

    class Stub:
        def execute(self, _request):
            return AdapterOutput(status="success", raw_output=b"{}")

    for cap in (Capability.NMAP_SCAN, Capability.WHATWEB, Capability.WEB_CRAWL,
                Capability.GRAPHQL_DISCOVERY, Capability.SOURCEMAP_ANALYZE,
                Capability.EXPOSURE_DISCOVERY):
        registry.register(cap, Stub())
    gateway = ToolExecutionGateway(PolicyService(repository), registry,
        EvidenceStore(tmp_path / "evidence", repository), repository)
    service = ReconService(repository, gateway)
    validator = ReconProposalValidator(repository, service, ReconPlanningLimits())

    def convert(params):
        decision = ReconPlanningDecision.model_validate({"proposals": [{"kind": "target_capability",
            "asset_id": asset.id, "parameters": params, "priority": 1, "rationale": "cover checklist"}]})
        plan, errors = validator.validate(repository.get_task(task.id), decision, 96)
        return plan, errors

    nmap, errors = convert({"kind": "nmap_scan", "ports": [8000]})
    assert not errors and nmap.actions[0].request.capability == Capability.NMAP_SCAN
    # Web tool prerequisites are checked before execution.
    before, errors = convert({"kind": "web_crawl", "port": 8000})
    assert not before.actions and errors
    probe = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_PROBE,
        HttpProbeParams(port=8000))
    service.run(ReconPlan(task_id=task.id, actions=(probe,)))
    for params, expected in (({"kind": "whatweb", "port": 8000}, Capability.WHATWEB),
            ({"kind": "web_crawl", "port": 8000}, Capability.WEB_CRAWL),
            ({"kind": "graphql_discovery", "port": 8000, "path": "/graphql"}, Capability.GRAPHQL_DISCOVERY),
            ({"kind": "exposure_discovery", "port": 8000, "wordlist_id": "scm-small-v1"},
             Capability.EXPOSURE_DISCOVERY)):
        plan, errors = convert(params)
        assert not errors and plan.actions[0].request.capability == expected
    fetched = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
        HttpFetchParams(port=8000, path="/app.js.map"))
    service.run(ReconPlan(task_id=task.id, actions=(fetched,)))
    decision = ReconPlanningDecision.model_validate({"proposals": [{"kind": "evidence_capability",
        "capability": "sourcemap_analyze", "evidence_ref": repository.get_tool_result(fetched.id).evidence_id,
        "parameters": {"profile": "sourcemap_metadata"}, "priority": 1, "rationale": "analyze map"}]})
    plan, errors = validator.validate(repository.get_task(task.id), decision, 96)
    assert not errors and plan.actions[0].request.capability == Capability.SOURCEMAP_ANALYZE
