"""Browser runtime gate, persisted identity and response admission regressions."""

import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest

from src.recon import bootstrap, browser_runtime
from src.recon.agent import ReconAgent
from src.recon.browser import BrowserExploreAdapter, child_request
from src.recon.browser_response import BrowserByteBudget
from src.recon.gateway import AdapterOutput
from src.recon.models import BrowserExploreParams, BrowserLimits, Capability
from src.recon.planner import ReconPlanner
from src.recon.service import ReconService
from tests.test_recon_browser_boundary import FakeRequest, FakeRuntime, stack


@pytest.mark.parametrize("available", [False, True])
def test_bootstrap_advertises_only_usable_chromium(tmp_path, monkeypatch, available):
    monkeypatch.setattr(bootstrap, "chromium_available", lambda: available)
    _, service = bootstrap.create_recon_service(tmp_path / "runtime.db", tmp_path / "evidence")
    assert (Capability.BROWSER_EXPLORE in service.gateway.registry.available_capabilities()) == available


@pytest.mark.parametrize("outcome", [0, 1, OSError(), subprocess.TimeoutExpired("probe", 15)])
def test_runtime_probe_fails_closed(monkeypatch, outcome):
    def run(*_args, **options):
        assert options["timeout"] == 15
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(returncode=outcome)

    monkeypatch.setattr(browser_runtime.subprocess, "run", run)
    assert browser_runtime.chromium_available() is (outcome == 0)


@pytest.mark.parametrize("headers,reason", [
    ({}, "unbounded_response"),
    ({"content-length": "1", "transfer-encoding": "chunked"}, "unbounded_response"),
    ({"content-length": "1", "content-encoding": "gzip"}, "unbounded_response"),
    ({"content-length": "11"}, "response_byte_limit"),
])
def test_unbounded_or_oversized_responses_are_rejected(headers, reason):
    budget = BrowserByteBudget(10, 20)
    assert budget.admit("GET", 200, headers)[1]
    assert budget.used == 0 and budget.stop_reason == reason


def test_response_total_budget_redirect_attachment_and_head():
    budget = BrowserByteBudget(10, 12)
    assert budget.admit("GET", 302, {"location": "http://127.0.0.2/"})[1]
    assert budget.admit("GET", 200, {"content-disposition": "attachment; filename=x"})[1]
    assert budget.admit("HEAD", 200, {"content-length": "999999"}) == (0, "")
    assert budget.admit("GET", 200, {"content-length": "8"}) == (8, "")
    assert budget.admit("GET", 200, {"content-length": "5"})[1]
    assert budget.used == 8 and budget.stop_reason == "total_byte_limit"


def test_page_identity_and_legacy_fingerprints_survive_restart(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    bound = gateway.policy.bind(parent)
    old = json.loads(bound.model_dump_json())
    assert set(old["parameters"]["limits"]) == {"max_requests", "max_runtime_seconds", "max_response_bytes"}
    registry.register(Capability.BROWSER_EXPLORE, SimpleNamespace(execute=lambda _: AdapterOutput(status="success")))
    result = gateway.execute(parent)
    assert repository.get_tool_run(parent.id).request_fingerprint == hashlib.sha256(bound.model_dump_json().encode()).hexdigest()
    assert gateway.execute(type(parent).model_validate(old)) == result
    child = child_request(bound, "http://127.0.0.1:8000/api", "GET", "fetch")
    assert "page_sequence" not in child.parameters.model_dump()
    second = child_request(bound, "http://127.0.0.1:8000/api", "GET", "fetch", 1)
    assert child.id != second.id
    assert gateway.policy.bind(child).action_fingerprint != gateway.policy.bind(second).action_fingerprint
    assert child == child_request(bound, "http://127.0.0.1:8000/api#fragment", "GET", "fetch", 0)


def test_agent_skips_browser_phase_without_capability_or_adapter(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    agent = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))
    assert agent.run(parent.task_id).tool_results == ()
    task = repository.get_task(parent.task_id)
    task = task.model_copy(update={"id": "no-browser", "scope": task.scope.model_copy(update={
        "capabilities": (Capability.BROWSER_REQUEST,),
    })})
    repository.save_task(task)

    def unexpected(_):
        pytest.fail("browser adapter must not execute")

    registry.register(Capability.BROWSER_EXPLORE, SimpleNamespace(execute=unexpected))
    assert agent.run(task.id).tool_results == ()
    assert repository.list_plans(task.id) == ()


def test_runtime_deadline_stops_network_and_fences_replay(tmp_path, monkeypatch):
    repository, registry, gateway, parent = stack(tmp_path)
    ticks = [0.0]
    monkeypatch.setattr("src.recon.browser.time.monotonic", lambda: ticks[0])
    initial = "http://127.0.0.1:8000/"
    runtime = FakeRuntime([FakeRequest(initial, resource_type="document", navigation=True),
                           FakeRequest("http://127.0.0.1:8000/late")],
                          after_continue=lambda: ticks.__setitem__(0, 20.0))
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    result = gateway.execute(parent)
    assert result.status == "error"
    assert runtime.network == [("GET", initial)]
    assert gateway.execute(parent) == result
    summary = json.loads(gateway.evidence.read(result.evidence_id))
    assert summary["stop_reason"] == "cancelled_or_runtime_limit"
    assert repository.list_endpoints(parent.task_id) == ()


def test_child_cannot_forge_page_or_body_budget(tmp_path):
    _, registry, gateway, parent = stack(tmp_path)

    def execute(bound):
        child = child_request(bound, "http://127.0.0.1:8000/api", "GET", "fetch", 1)
        assert gateway.begin_external_dispatch(child).status == "error"
        return AdapterOutput(status="success")

    registry.register(Capability.BROWSER_EXPLORE, SimpleNamespace(execute=execute))
    parent = parent.model_copy(update={"parameters": BrowserExploreParams(port=8000, limits=BrowserLimits(max_pages=1))})
    assert gateway.execute(parent).status == "success"
