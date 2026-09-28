"""Real old-layout SQLite fixtures, with independently computed recon-2.2 hashes."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from src.contracts.execution import action_fingerprint
from src.recon.execution import ToolRun, ToolRunState
from src.recon.models import PolicyDecision, ToolResult
from src.recon.policy import PolicyService
from src.recon.storage import ReconRepository
from src.storage import migrations
from tests.test_recon_day2 import fetch_request, make_task
from tests.test_recon_runtime_contract import runtime


def legacy_database(path, version=5, state=ToolRunState.SUCCEEDED):
    task, request = make_task(), fetch_request()
    raw_task = task.model_dump(mode="json", exclude={"policy_version"})
    canonical = json.dumps(raw_task, sort_keys=True, separators=(",", ":"))
    scope_hash = hashlib.sha256(("recon-2.2:" + canonical).encode()).hexdigest()
    fingerprint = action_fingerprint(
        run_id=task.run_id, task_id=task.id, target=request.target_ip, tool=request.capability.value,
        parameters=request.parameters.model_dump(mode="json"), scope_version=task.scope_version,
        policy_version="recon-2.2", scope_fingerprint=scope_hash,
    )
    bound = request.model_copy(update={"run_id": task.run_id, "scope_version": task.scope_version,
                                       "action_fingerprint": fingerprint})
    now = datetime.now(UTC)
    run = ToolRun(request_id=request.id, task_id=task.id, state=state, owner_token="historical",
                  queued_at=now - timedelta(minutes=3), lease_expires_at=now - timedelta(seconds=1),
                  request_payload=bound.model_dump_json(),
                  request_fingerprint=hashlib.sha256(bound.model_dump_json().encode()).hexdigest())
    result = ToolResult(request_id=request.id, task_id=task.id, target_ip=request.target_ip,
                        capability=request.capability, status="success", message="historical execution")
    decision = PolicyDecision(request_id=request.id, allowed=True, reason="in scope", policy_version="recon-2.2",
                              action_fingerprint=fingerprint, scope_version=task.scope_version, policy_fingerprint=scope_hash)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
        for number, name, apply in migrations.MIGRATIONS:
            if number <= version:
                apply(connection)
                connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (number, name, now.isoformat()))
        connection.execute("INSERT INTO recon_tasks VALUES (?, ?)", (task.id, json.dumps(raw_task)))
        connection.execute("INSERT INTO tool_runs VALUES (?, ?, ?)", (request.id, task.id, run.model_dump_json()))
        connection.execute("INSERT INTO policy_decisions VALUES (?, ?)", (request.id, decision.model_dump_json()))
        connection.execute("INSERT INTO policy_audit VALUES (?, ?, ?)", (request.id, 1, decision.model_dump_json()))
        if state == ToolRunState.SUCCEEDED:
            connection.execute("INSERT INTO tool_results VALUES (?, ?, ?, ?)", (request.id, task.id, result.status, result.model_dump_json()))
    return task, request, bound, result, scope_hash


def test_new_task_uses_recon_3_policy(tmp_path):
    task = make_task()
    repository, adapter, gateway = runtime(tmp_path, task)
    assert task.policy_version == PolicyService.VERSION == "recon-3.0"
    gateway.execute(fetch_request())
    assert adapter.calls == 1
    assert repository.get_policy_decision(fetch_request().id).policy_version == "recon-3.0"


def test_policy_version_changes_action_fingerprint():
    task, request = make_task(), fetch_request()
    old = task.model_copy(update={"policy_version": "recon-2.2"})
    assert PolicyService.scope_fingerprint(task) != PolicyService.scope_fingerprint(old)
    assert PolicyService.expected_fingerprint(request, task) != PolicyService.expected_fingerprint(request, old)


def test_v5_task_migrates_with_recon_2_2_snapshot(tmp_path):
    path = tmp_path / "legacy.db"
    task, _, bound, _, scope_hash = legacy_database(path)
    with sqlite3.connect(path) as connection:
        before = {name: connection.execute(f"SELECT * FROM {name}").fetchall()
                  for name in ("tool_runs", "policy_decisions", "policy_audit", "tool_results", "evidence_artifacts")}
    repository = ReconRepository(path)
    migrated = repository.get_task(task.id)
    assert migrated.policy_version == "recon-2.2"
    assert PolicyService.scope_fingerprint(migrated) == scope_hash
    assert PolicyService.expected_fingerprint(bound, migrated) == bound.action_fingerprint
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 6
        for name, rows in before.items():
            assert connection.execute(f"SELECT * FROM {name}").fetchall() == rows


@pytest.mark.parametrize("version", [3, 5])
def test_completed_recon_2_2_request_replays_after_upgrade(tmp_path, version):
    path = tmp_path / "legacy.db"
    task, request, bound, original, _ = legacy_database(path, version)
    _, adapter, gateway = runtime(tmp_path / "runner", make_task())
    repository = ReconRepository(path)
    gateway.results = repository
    gateway.policy = PolicyService(repository)
    assert repository.get_task(task.id).policy_version == "recon-2.2"
    assert gateway.execute(request) == gateway.execute(bound) == original
    assert adapter.calls == 0
    assert repository.get_tool_run(request.id).request_payload == bound.model_dump_json()


def test_stale_policy_task_cannot_dispatch_new_action(tmp_path):
    repository, adapter, gateway = runtime(tmp_path, make_task().model_copy(update={"policy_version": "recon-2.2"}))
    result = gateway.execute(fetch_request())
    assert result.status == "denied" and result.message == "task policy version is stale"
    assert adapter.calls == 0 and repository.budget_usage(result.task_id) == 0


def test_v3_database_upgrade_preserves_historical_fingerprint(tmp_path):
    path = tmp_path / "v3.db"
    task, request, bound, _, scope_hash = legacy_database(path, 3)
    repository = ReconRepository(path)
    saved = repository.get_tool_run(request.id)
    assert saved.request_fingerprint == hashlib.sha256(bound.model_dump_json().encode()).hexdigest()
    assert json.loads(saved.request_payload)["action_fingerprint"] == bound.action_fingerprint
    assert PolicyService.scope_fingerprint(repository.get_task(task.id)) == scope_hash


def test_legacy_expired_unknown_run_fails_without_replay(tmp_path):
    path = tmp_path / "legacy.db"
    _, request, _, _, _ = legacy_database(path, state=ToolRunState.RUNNING)
    _, adapter, gateway = runtime(tmp_path / "runner", make_task())
    gateway.results = ReconRepository(path)
    gateway.policy = PolicyService(gateway.results)
    failed = gateway.execute(request)
    assert failed.status == "error" and "lease expired" in failed.message
    assert gateway.results.get_tool_run(request.id).state == ToolRunState.FAILED
    assert gateway.execute(request) == failed and adapter.calls == 0
