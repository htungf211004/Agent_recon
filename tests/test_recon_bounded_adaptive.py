"""Acceptance tests for sequential sensing, typed planning and bounded content discovery."""

import json

import pytest
from pydantic import ValidationError

from scripts.run_recon_live import export_run, scoped_task
from src.contracts.recon_planning import ReconPlanningDecision
from src.recon.adapters import FfufAdapter
from src.recon.checklist import load_checklist, project_checklist
from src.recon.content_discovery import baseline_content, parse_ffuf, project_content
from src.recon.gateway import AdapterOutput
from src.recon.llm_planner import LLMReconPlanner
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    ContentDiscoveryParams,
    NmapScanParams,
    TechnologyObservation,
)
from src.recon.planner import ReconPlanner
from src.recon.sensing import ReconSensing, derive_web_candidates
from src.recon.wordlists import load_wordlist
from tests.test_recon_adaptive_planning import STOP, FakeModel, adaptive, proposal


def mission(**updates):
    task = scoped_task("http://127.0.0.1:8000/", "mission", ports=(22, 8000, 8001),
                       full_profile=True, content_discovery=True)
    return task.model_copy(update={"discovery_seeds": ("/seed",), **updates})


def sensing_stack(tmp_path, nmap_status="success"):
    task = mission()
    agent, model, task, calls = adaptive(tmp_path, [STOP], task=task)
    registry = agent.service.gateway.registry

    class Nmap:
        def execute(self, request):
            calls.append(("NMAP", request.parameters.ports))
            return AdapterOutput(status=nmap_status, raw_output=b"bounded scan evidence", attack_surface=(
                AttackSurfaceEntry(target_ip="127.0.0.1", port=22, service="ssh"),
                AttackSurfaceEntry(target_ip="127.0.0.1", port=8000, service="http"),
            ))

    class Probe:
        def execute(self, request):
            calls.append(("PROBE", request.parameters.port))
            return AdapterOutput(status="success", raw_output=b"HTTP 200", attack_surface=(
                AttackSurfaceEntry(target_ip=request.target_ip, port=request.parameters.port, service="http"),))

    class WhatWeb:
        def execute(self, request):
            calls.append(("WHATWEB", request.parameters.port))
            return AdapterOutput(status="success", raw_output=b"Python", technologies=(
                TechnologyObservation(target_ip=request.target_ip, name="Python", version="3.11", source=Capability.WHATWEB),))

    registry.register(Capability.NMAP_SCAN, Nmap())
    registry.register(Capability.HTTP_PROBE, Probe())
    registry.register(Capability.WHATWEB, WhatWeb())
    return agent, model, task, calls


def test_sequential_sensing_closed_and_nonweb_ports_never_receive_web_tools(tmp_path):
    agent, _, task, calls = sensing_stack(tmp_path)
    agent.run(task.id)
    assert calls[:3] == [("NMAP", (22, 8000, 8001)), ("PROBE", 8000), ("WHATWEB", 8000)]
    assert calls[3:] == [("GET", "/seed")]
    assert all(":8000/" in source.url for source in agent.repository.list_sources(task.id))
    agent.run(task.id)
    assert len(calls) == 4


@pytest.mark.parametrize("stage", ["run_service_discovery", "run_web_service_discovery", "run_technology_fingerprinting"])
def test_bootstrap_stage_restart_reuses_frozen_plan(tmp_path, stage):
    agent, model, task, calls = sensing_stack(tmp_path)
    for method in ("run_service_discovery", "run_web_service_discovery", "run_technology_fingerprinting"):
        getattr(agent.engine, method)(task.id)
        if method == stage:
            break
    before = list(calls)
    getattr(agent.engine, stage)(task.id)
    assert calls == before
    agent.run(task.id)
    assert len(model.contexts) == 1
    assert calls.count(("NMAP", (22, 8000, 8001))) == 1


def test_nmap_failure_falls_back_only_within_authorized_common_ports(tmp_path):
    agent, _, task, _ = sensing_stack(tmp_path, "error")
    agent.engine.run_service_discovery(task.id)
    assert ReconSensing(agent.engine).candidates(task) == (("127.0.0.1", 8000, "http"),)
    assert derive_web_candidates(task, (), {}) == (("127.0.0.1", 22, "http"), ("127.0.0.1", 8000, "http"), ("127.0.0.1", 8001, "http"))


def test_live_scope_explicitly_enables_scans_and_never_expands_ports():
    task = mission()
    assert task.scope.allowed_ports == (22, 8000, 8001)
    assert {Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB} <= set(task.scope.capabilities)
    with pytest.raises(ValueError):
        scoped_task("http://127.0.0.1:8000/", "mission", ports=(8001,), full_profile=True)


def test_policy_denies_nmap_outside_authorized_ports(tmp_path):
    agent, _, task, calls = sensing_stack(tmp_path)
    request = ReconPlanner._action(task, "127.0.0.1", Capability.NMAP_SCAN, NmapScanParams(ports=(443,))).request
    assert agent.service.gateway.execute(request).status == "denied"
    assert calls == []


def test_disabled_capabilities_have_zero_toolruns_and_checklist_is_not_permission(tmp_path):
    agent, model, task, _ = adaptive(tmp_path, [STOP])
    agent.run(task.id)
    assert {r.capability for r in agent.repository.list_tool_results(task.id)} == {Capability.HTTP_FETCH}
    context = model.contexts[0]
    assert context["checklist_version"] == "recon-checklist-v1"
    assert next(c for c in context["checklist"] if c["id"] == "RECON-BROWSER-DYNAMIC")["status"] == "NOT_APPLICABLE"
    assert context["planning"] == {"current_round": 1, "max_rounds": 2, "future_rounds_remaining": 1}
    assert "planning_rounds" not in context["remaining_budget"]


def test_checklist_registry_safe_subset_and_missing_adapters(tmp_path):
    assert len(load_checklist().items) == 10
    assert all(item.risk in {"R0", "R1"} and item.safe_default for item in load_checklist().items)
    agent, _, task, _ = adaptive(tmp_path, [STOP], task=mission())
    statuses = {s.id: s.status for s in project_checklist(task, agent.repository, agent.service)}
    assert statuses["RECON-CONTENT-DISCOVERY"] == "UNSUPPORTED"
    assert statuses["RECON-SERVICE-DISCOVERY"] == "UNSUPPORTED"


@pytest.mark.parametrize("field,value", [("path", "/"), ("target_ip", "127.0.0.1"), ("port", 8000),
                                         ("method", "GET"), ("scheme", "http"), ("query", ""), ("body", "")])
def test_stop_cannot_carry_target_or_execution_parameters(field, value):
    with pytest.raises(ValidationError):
        ReconPlanningDecision.model_validate({"proposals": [{**STOP["proposals"][0], field: value}]})


def test_stop_mixed_with_action_rejected_and_budget_reason_checked(tmp_path):
    with pytest.raises(ValidationError):
        ReconPlanningDecision.model_validate({"proposals": [STOP["proposals"][0], proposal()]})
    agent, _, task, _ = adaptive(tmp_path, [STOP])
    stop = ReconPlanningDecision.model_validate({"proposals": [{**STOP["proposals"][0], "reason_code": "BUDGET_EXHAUSTED"}]})
    plan, errors = agent.validator.validate(task, stop, 8)
    assert not plan.actions and errors == ("inconsistent_stop_budget",)


@pytest.mark.parametrize("extra", [{"wordlist_id": "../../secret"}, {"method": "POST"}, {"headers": {"Host": "elsewhere"}},
                                   {"flags": "-r"}, {"path_prefix": "/FUZZ/"}, {"path_prefix": "/../"}])
def test_content_params_reject_untrusted_controls(extra):
    with pytest.raises(ValidationError):
        ContentDiscoveryParams.model_validate({"port": 8000, "wordlist_id": "web-common-small-v1", **extra})


def content_stack(tmp_path, monkeypatch):
    agent, _, task, calls = adaptive(tmp_path, [STOP], task=mission())
    params = ContentDiscoveryParams(port=8000, wordlist_id="web-common-small-v1")
    request = ReconPlanner._action(task, "127.0.0.1", Capability.CONTENT_DISCOVERY, params).request
    dispatched = []

    def run(command, timeout, **kwargs):
        from pathlib import Path
        dispatched.append(command)
        assert agent.repository.get_policy_decision(request.id).allowed
        assert command[command.index("-X") + 1] == "HEAD"
        assert timeout == 20 and command[command.index("-t") + 1] == "1"
        assert "HTTP_PROXY" not in kwargs["env"] and "-r=false" in command
        Path(command[command.index("-o") + 1]).write_text(json.dumps({"results": [
            {"url": "http://127.0.0.1:8000/hidden", "status": 200},
            {"url": "http://127.0.0.2:8000/hidden", "status": 200}]}))
        return AdapterOutput(status="success")

    monkeypatch.setattr("src.recon.adapters.which", lambda name: "ffuf")
    monkeypatch.setattr("src.recon.adapters._run_fixed", run)
    agent.service.gateway.registry.register(Capability.CONTENT_DISCOVERY, FfufAdapter())
    return agent, task, request, calls, dispatched


def test_ffuf_evidence_candidates_require_separate_http_baseline_and_replay(tmp_path, monkeypatch):
    agent, task, request, calls, dispatched = content_stack(tmp_path, monkeypatch)
    result = agent.service.gateway.execute(request)
    assert result.status == "success" and result.evidence_id
    assert agent.repository.budget_usage(task.id) == load_wordlist(request.parameters.wordlist_id).max_entries
    project_content(agent.repository, agent.service, request)
    inventory = agent.service.snapshot(task.id).attack_surface_inventory
    assert len(inventory.entries) == 1
    assert inventory.entries[0].status != "FUZZ_READY"
    baseline_content(agent.repository, agent.service, task)
    assert calls == [("GET", "/hidden")]
    assert agent.service.snapshot(task.id).attack_surface_inventory.entries[0].status == "FUZZ_READY"
    assert agent.service.gateway.execute(request) == result
    baseline_content(agent.repository, agent.service, task)
    assert len(dispatched) == len(calls) == 1


def test_ffuf_budget_reserves_all_candidates_before_dispatch(tmp_path, monkeypatch):
    agent, task, request, _, dispatched = content_stack(tmp_path, monkeypatch)
    task = task.model_copy(update={"execution_budget": task.execution_budget.model_copy(update={"max_requests": 2})})
    with agent.repository._connect() as conn:
        conn.execute("UPDATE recon_tasks SET payload = ? WHERE id = ?", (task.model_dump_json(), task.id))
    request = ReconPlanner._action(task, "127.0.0.1", Capability.CONTENT_DISCOVERY, request.parameters).request
    assert agent.service.gateway.execute(request).status == "denied"
    assert dispatched == [] and agent.repository.budget_usage(task.id) == 0


@pytest.mark.parametrize("raw", [b"invalid", b'{"results":{}}', b'{"results":[{"url":"http://127.0.0.1:8000/hidden","status":true}]}', b"x" * 262145],
                         ids=["json", "shape", "status", "oversize"])
def test_ffuf_parser_fails_closed(raw):
    task = mission()
    request = ReconPlanner._action(task, "127.0.0.1", Capability.CONTENT_DISCOVERY,
                                   ContentDiscoveryParams(port=8000, wordlist_id="web-common-small-v1")).request
    with pytest.raises((ValueError, TypeError, KeyError)):
        parse_ffuf(raw, request)


def test_provider_failure_preserves_verified_inventory_and_sanitizes_error(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [TimeoutError("api_key=DO_NOT_EXPORT")])
    result = agent.run(task.id)
    assert result.attack_surface_inventory.entries[0].status == "FUZZ_READY"
    assert "adaptive:model_error" in result.coverage.limitations
    assert agent.store.rounds(task.id)[0]["error_code"] == "MODEL_TIMEOUT"
    agent.run(task.id)
    assert len(model.contexts) == len(calls) == 1
    export_run(agent, task.id, tmp_path)
    assert all((tmp_path / name).exists() for name in ("run-manifest.json", "summary.json", "planning.json",
                                                     "inventory.json", "result.json", "evidence-index.json"))
    text = "".join(p.read_text() for p in tmp_path.glob("*.json"))
    assert "DO_NOT_EXPORT" not in text and '"handoff_ready": true' in text


def test_changed_planner_fingerprint_cannot_resume(tmp_path):
    agent, _, task, _ = adaptive(tmp_path, [STOP])
    agent.run(task.id)
    agent.planner = LLMReconPlanner(FakeModel(STOP), planner_id="changed-model")
    with pytest.raises(ValueError, match="configuration"):
        agent.run(task.id)


@pytest.mark.parametrize("checkpoint", ["decide", "validate", "executed"])
def test_restart_after_planning_checkpoint_does_not_repeat_model_or_network(tmp_path, monkeypatch, checkpoint):
    agent, model, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}, STOP])
    original = getattr(agent.store, checkpoint)
    count = 0

    def after_persist(*args, **kwargs):
        nonlocal count
        result = original(*args, **kwargs)
        count += 1
        if count == 1:
            raise RuntimeError("checkpoint crash")
        return result

    monkeypatch.setattr(agent.store, checkpoint, after_persist)
    if checkpoint == "decide":
        assert agent.run(task.id).worker_status == "RUNNING"
    else:
        with pytest.raises(RuntimeError, match="checkpoint crash"):
            agent.run(task.id)
    monkeypatch.setattr(agent.store, checkpoint, original)
    result = agent.run(task.id)
    assert result.worker_status == "COMPLETED"
    assert len(model.contexts) == 2 and calls == [("GET", "/seed"), ("GET", "/new")]


def test_crash_after_empty_stop_executed_does_not_call_model_again(tmp_path, monkeypatch):
    agent, model, task, calls = adaptive(tmp_path, [STOP])
    original = agent.store.stop
    monkeypatch.setattr(agent.store, "stop", lambda *_: (_ for _ in ()).throw(RuntimeError("stop crash")))
    with pytest.raises(RuntimeError, match="stop crash"):
        agent.run(task.id)
    monkeypatch.setattr(agent.store, "stop", original)
    assert agent.run(task.id).worker_status == "COMPLETED"
    assert len(model.contexts) == len(calls) == 1


def test_context_service_and_technology_facts_require_intact_evidence(tmp_path):
    from src.recon.planning_context import assemble_context
    agent, model, task, _ = sensing_stack(tmp_path)
    agent.run(task.id)
    context = model.contexts[0]
    assert any(s["port"] == 22 and s["service"] == "ssh" and s["evidence_ref"] for s in context["services"])
    assert context["technologies"][0]["technology"] == "Python"
    assert context["technologies"][0]["version"] == "3.11"
    ref = context["technologies"][0]["evidence_ref"]
    artifact = agent.repository.get_evidence(ref)
    (agent.service.gateway.evidence.directory / artifact.relative_path).write_bytes(b"corrupted")
    refreshed = assemble_context(task, agent.repository, agent.service, agent.limits, 1, 0)
    assert refreshed.technologies == ()


@pytest.mark.parametrize("scope_update", [{"allowed_ips": ("127.0.0.2",)}, {"allowed_ports": (8001,)},
                                          {"allowed_paths": ("/safe",)}, {"allowed_methods": ("GET",)}])
def test_ffuf_scope_denial_has_zero_dispatch(tmp_path, monkeypatch, scope_update):
    agent, task, request, _, dispatched = content_stack(tmp_path, monkeypatch)
    task = task.model_copy(update={"scope": task.scope.model_copy(update=scope_update)})
    with agent.repository._connect() as connection:
        connection.execute("UPDATE recon_tasks SET payload = ? WHERE id = ?", (task.model_dump_json(), task.id))
    request = ReconPlanner._action(task, "127.0.0.1", Capability.CONTENT_DISCOVERY, request.parameters).request
    assert agent.service.gateway.execute(request).status == "denied"
    assert dispatched == []


@pytest.mark.parametrize("checkpoint", ["ffuf_response", "baseline_response"])
def test_adaptive_ffuf_crash_recovers_without_duplicate_dispatch(tmp_path, monkeypatch, checkpoint):
    from src.recon import adaptive_agent, adaptive_projection
    agent, task, _, calls, dispatched = content_stack(tmp_path, monkeypatch)
    model = FakeModel({"proposals": [{"kind": "content_discovery", "target_ip": "127.0.0.1",
        "port": 8000, "scheme": "http", "path_prefix": "/", "wordlist_id": "web-common-small-v1",
        "rationale": "bounded hidden paths", "priority": 1}]}, STOP)
    agent.planner = LLMReconPlanner(model, planner_id="ffuf-checkpoints")
    target = adaptive_agent if checkpoint == "ffuf_response" else adaptive_projection
    original = target.project_action

    def crash(*_):
        raise RuntimeError("content checkpoint crash")

    monkeypatch.setattr(target, "project_action", crash)
    with pytest.raises(RuntimeError, match="content checkpoint crash"):
        agent.run(task.id)
    assert len(model.contexts) == len(dispatched) == 1
    monkeypatch.setattr(target, "project_action", original)
    result = agent.run(task.id)
    hidden = next(e for e in result.attack_surface_inventory.entries if e.canonical_path == "/hidden")
    assert hidden.status == "FUZZ_READY" and result.worker_status == "COMPLETED"
    assert len(dispatched) == 1 and calls.count(("GET", "/hidden")) == 1
    before = list(calls)
    agent.run(task.id)
    assert calls == before and len(model.contexts) == 2
