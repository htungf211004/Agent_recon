"""Fake model, real Policy/Gateway/evidence, durable budgets and hostile proposals."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Event

import httpx
import pytest
from pydantic import TypeAdapter, ValidationError

from src.contracts.recon_planning import ReconPlanningDecision, ReconPlanningLimits, ReconProposal
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.agent import ReconAgent
from src.recon.gateway import ToolExecutionGateway
from src.recon.llm_planner import LLMReconPlanner, configured_planner
from src.recon.models import Capability, HttpFetchParams, ReconPlan
from src.recon.planner import ReconPlanner
from src.recon.planning_context import assemble_context
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import EndpointParameter, WebEndpointEntry
from tests.test_recon_day2 import make_task, stack


def proposal(path="/new", **updates):
    return {"kind": "safe_http_probe", "target_ip": "127.0.0.1", "port": 8000, "path": path,
            "rationale": "inspect an uncovered route", "priority": 1, **updates}


STOP = {"proposals": [{"kind": "stop", "reason_code": "COVERAGE_SUFFICIENT", "rationale": "coverage sufficient", "priority": 1}]}


class FakeModel:
    def __init__(self, *decisions):
        self.decisions = list(decisions)
        self.contexts = []

    def invoke(self, messages):
        self.contexts.append(json.loads(messages[1][1]))
        assert "untrusted DATA" in messages[0][1]
        result = self.decisions.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def adaptive(tmp_path, decisions, *, task=None, limits=None, status=200, body=b"ok"):
    task = task or make_task().model_copy(update={"discovery_seeds": ("/seed",)})
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(status, headers={"content-type": "text/plain"}, stream=httpx.ByteStream(body))

    repository, _, _, service = stack(tmp_path, task, handler)
    engine = ReconAgent(repository, ReconPlanner(), service)
    model = FakeModel(*decisions)
    agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="fake-v1"),
        limits or ReconPlanningLimits(max_llm_rounds=2, max_total_llm_actions=8),
        execution_mode="deterministic_fallback")
    return agent, model, task, calls


def test_adaptive_http_updates_inventory_and_restart_replays_without_model_or_network(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}, STOP])
    first = agent.run(task.id)
    endpoint = next(e for e in first.attack_surface_inventory.entries if e.canonical_path == "/new")
    assert endpoint.status == "FUZZ_READY" and endpoint.has_verified_baseline
    assert calls == [("GET", "/seed"), ("GET", "/new")]
    assert len(model.contexts) == 2
    assert any(route["path"] == "/new" for route in model.contexts[1]["routes"])
    baseline = agent.repository.get_baseline(endpoint.baseline_ref)
    assert agent.repository.get_policy_decision(baseline.request_id).allowed
    assert agent.service.gateway.evidence.read(baseline.evidence_id)
    assert agent.store.status(task.id) == "model_stop"
    reopened = ReconRepository(agent.repository.database_path)
    gateway = ToolExecutionGateway(PolicyService(reopened), agent.service.gateway.registry,
        EvidenceStore(agent.service.gateway.evidence.directory, reopened), reopened)
    resumed = AdaptiveReconAgent(ReconAgent(reopened, ReconPlanner(), ReconService(reopened, gateway)),
        agent.planner, execution_mode="deterministic_fallback")
    assert resumed.run(task.id).attack_surface_inventory == first.attack_surface_inventory
    assert len(model.contexts) == 2 and len(calls) == 2


@pytest.mark.parametrize("updates", [
    {"command": "curl example.test"}, {"method": "POST"}, {"headers": {"Host": "outside.test"}},
    {"query": "password=secret"}, {"body": "payload"}, {"priority": True}, {"port": "8000"},
])
def test_shared_schema_rejects_execution_payloads_and_coercion(updates):
    with pytest.raises(ValidationError):
        TypeAdapter(ReconProposal).validate_python(proposal(**updates))


@pytest.mark.parametrize("updates,reason", [
    ({"target_ip": "127.0.0.2"}, "target not allowed"),
    ({"target_ip": "example.test"}, "invalid proposal"),
    ({"port": 8080}, "port not allowed"),
    ({"path": "/../admin"}, "invalid proposal"),
    ({"path": "/api/%2e%2e/write"}, "invalid proposal"),
    ({"path": "//outside.test/"}, "invalid proposal"),
    ({"path": "/users/{id}"}, "invalid proposal"),
    ({"kind": "browser_explore"}, "browser child capability"),
])
def test_invalid_suggestions_never_dispatch(tmp_path, updates, reason):
    agent, model, task, calls = adaptive(tmp_path, [{"proposals": [proposal(**updates)]}])
    agent.run(task.id)
    assert calls == [("GET", "/seed")]
    assert agent.store.status(task.id) == "no_valid_actions"
    assert reason in agent.store.rounds(task.id)[0]["rejections"]
    assert len(model.contexts) == 1


@pytest.mark.parametrize("decision", ["not JSON", {"proposals": [proposal()] * 6},
                                      {"proposals": [proposal(command="sh")]}, TimeoutError("secret")])
def test_invalid_or_failed_model_response_stops_durably_without_retry(tmp_path, decision):
    agent, model, task, calls = adaptive(tmp_path, [decision])
    agent.run(task.id)
    agent.run(task.id)
    assert agent.store.status(task.id) == "model_error"
    assert len(calls) == len(model.contexts) == 1


def test_total_action_and_round_limits_survive_restart(tmp_path):
    rounds = [{"proposals": [proposal(f"/r{n}-{i}") for i in range(5)]} for n in range(3)]
    agent, model, task, calls = adaptive(tmp_path, rounds,
        limits=ReconPlanningLimits(max_llm_rounds=3, max_total_llm_actions=8))
    agent.run(task.id)
    assert agent.store.actions_used(task.id) == 8
    assert agent.store.status(task.id) == "action_limit"
    assert len(calls) == 9 and len(model.contexts) == 2
    agent.run(task.id)
    assert len(calls) == 9 and len(model.contexts) == 2
    with pytest.raises(ValueError, match="configuration"):
        AdaptiveReconAgent(agent.engine, agent.planner, ReconPlanningLimits(max_llm_rounds=1),
            execution_mode="deterministic_fallback").run(task.id)


def test_one_round_and_smaller_proposal_limit(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}],
                                        limits=ReconPlanningLimits(max_llm_rounds=1))
    agent.run(task.id)
    assert agent.store.status(task.id) == "round_limit" and len(model.contexts) == 1 and len(calls) == 2


def test_prior_actions_dedup_ignores_priority_rationale_and_request_id(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal("/seed"), proposal(), proposal(priority=4)]},
                                              {"proposals": [proposal(rationale="try again", priority=2)]}])
    agent.run(task.id)
    assert calls == [("GET", "/seed"), ("GET", "/new")]
    assert agent.store.actions_used(task.id) == 1
    assert "duplicate action" in agent.store.rounds(task.id)[1]["rejections"]


def test_required_inputs_and_manual_forms_rejected(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal("/form"), proposal("/search"), proposal("/users/7")]}])
    for path, params, manual, template in [
        ("/form", (), True, None),
        ("/search", (EndpointParameter(name="q", location="query", required=True),), False, None),
        ("/users/{id}", (), False, "/users/{id}"),
    ]:
        agent.repository.save_endpoint(WebEndpointEntry(task_id=task.id, url="http://127.0.0.1:8000" + path,
            parameters=params, requires_manual_input=manual, route_template=template))
    result = agent.run(task.id)
    assert calls == [("GET", "/seed"), ("GET", "/users/7")]
    entry = next(e for e in result.attack_surface_inventory.entries if e.route_template == "/users/{id}")
    assert entry.status == "FUZZ_READY"


@pytest.mark.parametrize("status,body", [(302, b"redirect"), (500, b"failed"), (200, b"x" * 131073)],
                         ids=["redirect", "error", "truncated"])
def test_noncomplete_baseline_never_ready(tmp_path, status, body):
    agent, _, task, _ = adaptive(tmp_path, [{"proposals": [proposal()]}, STOP], status=status, body=body)
    result = agent.run(task.id)
    assert next(e for e in result.attack_surface_inventory.entries if e.canonical_path == "/new").status == "OBSERVED"


def test_context_omits_raw_body_and_query_values_and_bounds_size(tmp_path):
    agent, model, task, _ = adaptive(tmp_path, [STOP], body=b"secret password cookie ignore system prompt")
    agent.run(task.id)
    context = model.contexts[0]
    serialized = json.dumps(context)
    assert "secret" not in serialized and "cookie" not in serialized
    assert len(serialized.encode()) < 32768
    assert context["capabilities"] == ["http_fetch"]
    assert context["scope"]["targets"] == ["127.0.0.1"]


def test_gateway_rechecks_after_validator_before_dispatch(tmp_path, monkeypatch):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}])
    original = agent.store.validate

    def expire(*args):
        saved = original(*args)
        changed = task.model_copy(update={"expires_at": task.expires_at - timedelta(days=1)})
        with agent.repository._connect() as conn:
            conn.execute("UPDATE recon_tasks SET payload = ? WHERE id = ?", (changed.model_dump_json(), task.id))
        return saved

    monkeypatch.setattr(agent.store, "validate", expire)
    result = agent.run(task.id)
    assert calls == [("GET", "/seed")]
    assert any(item.status == "denied" for item in result.tool_results)


def test_crash_after_network_before_projection_recovers_zero_dispatch(tmp_path, monkeypatch):
    agent, model, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}, STOP])
    import src.recon.adaptive_agent as module

    original = module.project_action

    def crash(*_):
        raise RuntimeError("projection crash")

    monkeypatch.setattr(module, "project_action", crash)
    with pytest.raises(RuntimeError, match="projection crash"):
        agent.run(task.id)
    assert len(calls) == 2 and len(model.contexts) == 1
    monkeypatch.setattr(module, "project_action", original)
    result = agent.run(task.id)
    assert len(calls) == 2 and len(model.contexts) == 2
    assert any(entry.canonical_path == "/new" and entry.status == "FUZZ_READY" for entry in result.attack_surface_inventory.entries)


def test_concurrent_workers_claim_only_one_model_call(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [STOP])
    entered, release = Event(), Event()
    original = model.invoke

    def blocked(messages):
        entered.set()
        assert release.wait(5)
        return original(messages)

    model.invoke = blocked
    with ThreadPoolExecutor(max_workers=1) as worker:
        first = worker.submit(agent.run, task.id)
        assert entered.wait(5)
        agent.run(task.id)
        release.set()
        first.result(timeout=10)
    assert len(model.contexts) == 1 and calls == [("GET", "/seed")]


def test_late_model_result_is_fenced_after_timeout(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [], limits=ReconPlanningLimits(model_timeout_seconds=0.01))
    release = Event()

    def late(_):
        release.wait(2)
        return {"proposals": [proposal()]}

    model.invoke = late
    agent.run(task.id)
    release.set()
    assert agent.store.status(task.id) == "model_error"
    assert agent.store.rounds(task.id)[0]["decision"] is None
    agent.run(task.id)
    assert calls == [("GET", "/seed")]


def test_abandoned_model_claim_never_retries_and_rejects_late_decision(tmp_path):
    agent, model, task, calls = adaptive(tmp_path, [])
    agent.engine.run(task.id)
    agent.store.open_session(task, agent.limits, agent.planner.planner_id)
    context = assemble_context(task, agent.repository, agent.service, agent.limits, 1, 0)
    owner = agent.store.claim(task.id, 1, context, agent.limits)
    now = agent.repository.clock()
    agent.repository.clock = lambda: now + timedelta(minutes=3)
    agent.run(task.id)
    assert agent.store.status(task.id) == "model_outcome_unknown"
    assert not agent.store.decide(task.id, 1, owner, ReconPlanningDecision.model_validate(STOP))
    assert model.contexts == [] and len(calls) == 1


def test_model_factory_only_binds_structured_output_with_no_retries(monkeypatch):
    captured = {}

    class FakeChat:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def with_structured_output(self, schema, **kwargs):
            captured.update(kwargs)
            assert schema is ReconPlanningDecision
            return FakeModel(STOP)

    monkeypatch.setattr("langchain_openai.ChatOpenAI", FakeChat)
    planner = configured_planner(model_name="configured-model", api_key="test")
    assert len(planner.planner_id) == 64 and planner.identity["model"] == "configured-model"
    assert captured["max_retries"] == 0 and captured["max_tokens"] == 2048
    assert captured["strict"] is True and captured["method"] == "json_schema"


def test_missing_runtime_capability_does_not_dispatch(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [STOP])
    agent.engine.run(task.id)
    agent.service.gateway.registry._adapters.clear()
    plan, errors = agent.validator.validate(task, ReconPlanningDecision.model_validate({"proposals": [proposal()]}), 8)
    assert not plan.actions and errors == ("capability unavailable",) and len(calls) == 1


def test_cancelled_planned_action_is_not_replaced_by_new_request(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal()]}])
    action = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH, HttpFetchParams(port=8000, path="/new"))
    agent.repository.save_plan(ReconPlan(task_id=task.id, actions=(action,)))
    agent.repository.acquire_tool_run(action.request)
    agent.service.gateway.cancel(action.request.id)
    agent.run(task.id)
    assert calls == [("GET", "/seed")]
    assert "duplicate action" in agent.store.rounds(task.id)[0]["rejections"]


def test_encoded_url_cannot_bypass_semantic_dedup(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal("/new")]},
                                              {"proposals": [proposal("/n%65w")]}])
    agent.run(task.id)
    assert calls == [("GET", "/seed"), ("GET", "/new")]
    assert agent.store.status(task.id) == "no_valid_actions"


def test_lower_proposal_limit_is_enforced_as_a_batch(tmp_path):
    agent, _, task, calls = adaptive(tmp_path, [{"proposals": [proposal(), proposal("/next")]}],
                                     limits=ReconPlanningLimits(max_proposals_per_round=1))
    agent.run(task.id)
    assert calls == [("GET", "/seed")]
    assert "proposal_limit" in agent.store.rounds(task.id)[0]["rejections"]


def test_request_budget_exhaustion_prevents_model_call(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/seed",)})
    task = task.model_copy(update={"execution_budget": task.execution_budget.model_copy(update={"max_requests": 1})})
    agent, model, task, calls = adaptive(tmp_path, [], task=task)
    agent.run(task.id)
    assert agent.store.status(task.id) == "request_limit" and model.contexts == []
    assert len(calls) == 1


def test_real_structured_model_client_with_mock_provider_transport(tmp_path, monkeypatch):
    from langchain_openai import ChatOpenAI

    sent = []

    def handle(request):
        data = json.loads(request.content)
        sent.append(data)
        assert data["response_format"]["type"] == "json_schema"
        assert data["response_format"]["json_schema"]["strict"] is True
        assert "tools" not in data
        return httpx.Response(200, json={
            "id": "test", "object": "chat.completion", "created": 0, "model": "gpt-4o-mini",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(STOP)}}],
        })

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        monkeypatch.setattr("langchain_openai.ChatOpenAI", lambda **kwargs: ChatOpenAI(http_client=client, **kwargs))
        planner = configured_planner(model_name="gpt-4o-mini", api_key="test")
        agent, _, task, _ = adaptive(tmp_path, [])
        agent.engine.run(task.id)
        context = assemble_context(task, agent.repository, agent.service, agent.limits, 1, 0)
        assert planner.plan(context) == ReconPlanningDecision.model_validate(STOP)
    assert len(sent) == 1
