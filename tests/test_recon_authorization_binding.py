from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.contracts.execution import Risk
from src.recon.models import Capability, CapabilityRequest, HttpFetchParams, PolicyOutcome
from src.recon.policy import PolicyService
from tests.test_recon_day2 import fetch_request, make_task
from tests.test_recon_runtime_contract import runtime


def test_action_fingerprint_binds_exact_action_and_trusted_scope(tmp_path):
    task = make_task()
    repository, adapter, gateway = runtime(tmp_path, task)
    first = gateway.policy.bind(fetch_request())
    assert first.run_id == task.run_id and first.scope_version == task.scope_version
    assert first.target == first.target_ip
    assert first.id != first.action_fingerprint
    assert len(first.action_fingerprint) == 64
    decision = gateway.policy.decide(first)
    assert decision.outcome == PolicyOutcome.ALLOW and decision.risk == Risk.R0
    assert decision.action_fingerprint == first.action_fingerprint
    assert decision.scope_version == task.scope_version
    assert decision.policy_fingerprint == PolicyService.scope_fingerprint(task)
    changed_params = first.model_copy(update={"parameters": HttpFetchParams(port=8000, path="/other")})
    assert PolicyService.expected_fingerprint(changed_params, task) != first.action_fingerprint
    changed_target = first.model_copy(update={"target_ip": "127.0.0.2"})
    assert PolicyService.expected_fingerprint(changed_target, task) != first.action_fingerprint
    changed_scope = task.model_copy(update={"scope_version": "2"})
    assert PolicyService.expected_fingerprint(first, changed_scope) != first.action_fingerprint
    assert gateway.execute(first).status == "success"
    assert repository.get_tool_run(first.id).request_payload
    assert repository.get_policy_decision(first.id).action_fingerprint == first.action_fingerprint
    assert adapter.calls == 1


@pytest.mark.parametrize("change,reason", [
    ({"run_id": "other"}, "run identity"),
    ({"scope_version": "other"}, "scope version"),
    ({"action_fingerprint": "0" * 64}, "action fingerprint"),
])
def test_spoofed_action_binding_is_durably_denied_before_dispatch(tmp_path, change, reason):
    repository, adapter, gateway = runtime(tmp_path, make_task())
    request = gateway.policy.bind(fetch_request()).model_copy(update=change)
    result = gateway.execute(request)
    assert result.status == "denied" and reason in result.message
    assert repository.get_policy_decision(request.id).outcome == PolicyOutcome.DENY
    assert adapter.calls == repository.budget_usage(request.task_id) == 0


def test_risk_vocabulary_rejects_free_strings():
    from src.recon.models import PolicyDecision

    with pytest.raises(ValidationError):
        PolicyDecision(request_id="test", outcome=PolicyOutcome.DENY, reason="test", risk="bounded_recon")
    assert tuple(Risk) == (Risk.R0, Risk.R1, Risk.R2, Risk.R3, Risk.R4)


def test_request_id_replay_is_distinct_from_action_identity(tmp_path):
    task = make_task()
    repository, adapter, gateway = runtime(tmp_path, task)
    one = gateway.policy.bind(fetch_request("one"))
    two = gateway.policy.bind(fetch_request("two"))
    assert one.action_fingerprint == two.action_fingerprint and one.id != two.id
    assert gateway.execute(one).status == gateway.execute(two).status == "success"
    assert adapter.calls == 2
    with pytest.raises(ValueError, match="different content"):
        gateway.execute(one.model_copy(update={"parameters": HttpFetchParams(port=8000, path="/different")}))


def test_scope_expiry_changes_action_binding():
    task = make_task()
    request = CapabilityRequest(id="x", task_id=task.id, capability=Capability.HTTP_FETCH,
                                target_ip="127.0.0.1", parameters=HttpFetchParams(port=8000))
    changed = task.model_copy(update={"expires_at": datetime.now(UTC) + timedelta(minutes=15)})
    assert PolicyService.expected_fingerprint(request, task) != PolicyService.expected_fingerprint(request, changed)
