from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import httpx
import pytest

from src.recon.agent import ReconAgent
from src.recon.bootstrap import create_recon_service
from src.recon.execution import BudgetContext, ExecutionBudget, ToolRunState
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, PolicyDecision, PolicyOutcome, ToolResult
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import DiscoveryLimits, SourceStatus
from tests.test_recon_day2 import fetch_request, make_task, stack


class Spy:
    def __init__(self):
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return AdapterOutput(status="success")


def runtime(tmp_path, task, clock=None):
    repository = ReconRepository(tmp_path / "recon.db", clock=clock)
    repository.save_task(task)
    registry, adapter = CapabilityRegistry(), Spy()
    registry.register(Capability.HTTP_FETCH, adapter)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository)
    return repository, adapter, gateway


@pytest.mark.parametrize("started", [False, True], ids=["crash-after-claim", "crash-after-dispatch"])
def test_expired_lease_is_durably_failed_without_repeat_execution(tmp_path, started):
    task = make_task()
    ticks = [task.expires_at - timedelta(minutes=4)]
    repository, adapter, gateway = runtime(tmp_path, task, lambda: ticks[0])
    request = fetch_request()
    owner = repository.acquire_tool_run(request)
    if started:
        repository.start_tool_run(owner, request, gateway.policy.decide(request))
        assert repository.get_tool_run(request.id).state == ToolRunState.RUNNING
    assert gateway.execute(request).message == "request already claimed or incomplete"
    ticks[0] += timedelta(seconds=121)
    reopened = ReconRepository(repository.database_path, clock=lambda: ticks[0])
    gateway.results = reopened
    failed = gateway.execute(request)
    assert failed.status == "error" and "lease expired" in failed.message
    assert reopened.get_tool_run(request.id).state == ToolRunState.FAILED
    assert reopened.get_tool_result(request.id) == failed
    assert gateway.execute(request) == failed and adapter.calls == 0
    late = ToolResult(request_id=request.id, task_id=task.id, target_ip=request.target_ip,
                      capability=request.capability, status="success")
    assert reopened.finish_tool_run(owner, late) == failed


def test_completed_restart_replays_and_rejects_id_reuse(tmp_path):
    repository, adapter, gateway = runtime(tmp_path, make_task())
    request = fetch_request()
    original = gateway.execute(request)
    gateway.results = ReconRepository(repository.database_path)
    assert gateway.execute(request) == original
    assert adapter.calls == 1
    with pytest.raises(ValueError, match="different content"):
        gateway.execute(fetch_request(path="/changed"))


def test_owner_finishing_after_expiry_cannot_commit_success(tmp_path):
    task = make_task()
    ticks = [task.expires_at - timedelta(minutes=4)]
    repository, adapter, gateway = runtime(tmp_path, task, lambda: ticks[0])

    def late(request):
        adapter.calls += 1
        ticks[0] += timedelta(seconds=121)
        return AdapterOutput(status="success")

    adapter.execute = late
    result = gateway.execute(fetch_request())
    assert result.status == "error" and "late result rejected" in result.message
    assert repository.get_tool_run(result.request_id).state == ToolRunState.FAILED
    assert gateway.execute(fetch_request()) == result and adapter.calls == 1


def test_direct_gateway_budget_survives_restart(tmp_path):
    task = make_task().model_copy(update={"execution_budget": ExecutionBudget(max_requests=2)})
    repository, adapter, gateway = runtime(tmp_path, task)
    for identifier in ("one", "two"):
        assert gateway.execute(fetch_request(identifier)).status == "success"
    gateway.results = reopened = ReconRepository(repository.database_path)
    gateway.policy = PolicyService(reopened)
    denied = gateway.execute(fetch_request("three"))
    assert denied.status == "denied" and "budget" in denied.message
    assert reopened.get_tool_run("three").state == ToolRunState.DENIED
    assert reopened.get_policy_decision("three").outcome == PolicyOutcome.DENY
    assert reopened.budget_usage(task.id) == adapter.calls == 2


def test_atomic_budget_reservation_under_competing_requests(tmp_path):
    task = make_task().model_copy(update={"execution_budget": ExecutionBudget(max_requests=1)})
    repository, adapter, gateway = runtime(tmp_path, task)
    barrier = Barrier(2)
    original_decide = gateway.policy.decide

    def simultaneous_decisions(request):
        decision = original_decide(request)
        assert decision.allowed  # Both passed preliminary policy before either reserves.
        barrier.wait(timeout=5)
        return decision

    gateway.policy.decide = simultaneous_decisions
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(gateway.execute, (fetch_request("one"), fetch_request("two"))))
    assert sorted(result.status for result in results) == ["denied", "success"]
    assert adapter.calls == repository.budget_usage(task.id) == 1


def test_persisted_rate_limit_and_trusted_budget_context(tmp_path):
    task = make_task().model_copy(update={"execution_budget": ExecutionBudget(max_requests_per_second=1)})
    ticks = [task.expires_at - timedelta(minutes=4)]
    repository, adapter, gateway = runtime(tmp_path, task, lambda: ticks[0])
    assert gateway.execute(fetch_request("one")).status == "success"
    assert "rate" in gateway.execute(fetch_request("two")).message
    ticks[0] += timedelta(seconds=1)
    assert gateway.execute(fetch_request("three")).status == "success"
    spoof = fetch_request("spoof").model_copy(update={"budget_context": BudgetContext(task_id="other")})
    assert gateway.execute(spoof).status == "denied"
    assert adapter.calls == repository.budget_usage(task.id) == 2


@pytest.mark.parametrize("budget,params,reason", [
    (ExecutionBudget(max_timeout_seconds=1), {"timeout_seconds": 2}, "timeout"),
    (ExecutionBudget(max_body_bytes=10), {"max_body_bytes": 11}, "body size"),
])
def test_runtime_resource_limits_deny_before_adapter(tmp_path, budget, params, reason):
    task = make_task().model_copy(update={"execution_budget": budget})
    _, adapter, gateway = runtime(tmp_path, task)
    result = gateway.execute(fetch_request(**params))
    assert result.status == "denied" and reason in result.message
    assert adapter.calls == 0


def test_discovery_limit_is_enforced_for_direct_gateway_callers(tmp_path):
    task = make_task().model_copy(update={"discovery_limits": DiscoveryLimits(max_requests=1)})
    _, adapter, gateway = runtime(tmp_path, task)
    assert gateway.execute(fetch_request("one")).status == "success"
    assert "discovery request budget" in gateway.execute(fetch_request("two")).message
    assert adapter.calls == 1


def test_policy_is_durable_before_dispatch_and_timeout_is_terminal(tmp_path):
    def timeout(request):
        decision = repository.get_policy_decision("fetch-1")
        assert decision.outcome == PolicyOutcome.ALLOW and len(decision.policy_fingerprint) == 64
        assert repository.get_tool_run("fetch-1").state == ToolRunState.RUNNING
        raise httpx.ReadTimeout("timeout")

    repository, _, gateway, _ = stack(tmp_path, make_task(), timeout)
    result = gateway.execute(fetch_request())
    assert result.status == "error"
    assert repository.get_tool_run(result.request_id).state == ToolRunState.TIMED_OUT
    assert gateway.execute(fetch_request()) == result
    approval = PolicyDecision(request_id="future", outcome=PolicyOutcome.REQUIRE_APPROVAL, reason="future policy")
    assert approval.allowed is False


@pytest.mark.parametrize("installed", [False, True])
def test_registry_only_advertises_available_binaries(tmp_path, monkeypatch, installed):
    monkeypatch.setattr("src.recon.bootstrap.which", lambda binary: f"/tools/{binary}" if installed else None)
    _, service = create_recon_service(tmp_path / "recon.db", tmp_path / "evidence")
    available = service.gateway.registry.available_capabilities()
    assert Capability.HTTP_FETCH in available and Capability.HTTP_PROBE in available
    assert (Capability.NMAP_SCAN in available) is installed
    assert (Capability.WHATWEB in available) is installed


def test_discovery_retains_active_claim_and_recovers_it_after_expiry(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/",)})
    repository, _, _, service = stack(tmp_path, task, lambda request: pytest.fail("must not fetch"))
    from src.recon.discovery import EndpointDiscovery

    planner = ReconPlanner()
    discovery = EndpointDiscovery(repository, planner, service)
    discovery._seed(task)
    source = repository.list_sources(task.id)[0]
    request = planner.fetch_plan(task, (source,)).actions[0].request
    owner = repository.acquire_tool_run(request)
    repository.save_source(source.model_copy(update={"request_id": request.id}))
    agent = ReconAgent(repository, planner, service)
    result = agent.run(task.id)
    assert result.coverage.converged is False
    assert repository.list_sources(task.id)[0].status == SourceStatus.PENDING
    repository.clock = lambda: owner.lease_expires_at + timedelta(seconds=1)
    recovered = agent.run(task.id)
    assert recovered.coverage.complete is False
    assert repository.list_sources(task.id)[0].status == SourceStatus.ERROR
    assert repository.get_tool_run(request.id).state == ToolRunState.FAILED
