import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from src.contracts.attack_surface import AttackSurfaceInventory, EndpointStatus
from src.contracts.evidence import EvidenceManifest
from src.recon.agent import ReconAgent
from src.recon.models import Capability, CapabilityRequest, HttpFetchParams
from src.recon.planner import ReconPlanner
from src.recon.storage import ReconRepository
from src.recon.web_models import EndpointParameter, WebEndpointEntry, stable_id
from tests.test_recon_day2 import make_task, stack


def discovered(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/search?q=a", "/search?q=b", "/profile")})
    repository, evidence, gateway, service = stack(tmp_path, task, lambda request: httpx.Response(
        200, headers={"content-type": "text/plain"}, stream=httpx.ByteStream(b"baseline")),
    )
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    return repository, evidence, gateway, service, result


def test_shared_inventory_preserves_routes_observations_baselines_and_trace(tmp_path):
    repository, _, _, _, result = discovered(tmp_path)
    inventory = AttackSurfaceInventory.model_validate_json(result.attack_surface_inventory.model_dump_json())
    assert len(inventory.entries) == 2
    search = next(entry for entry in inventory.entries if entry.canonical_path == "/search")
    assert len(search.observations) == 2
    assert {item.concrete_url for item in search.observations} == {
        "http://127.0.0.1:8000/search?q=a", "http://127.0.0.1:8000/search?q=b",
    }
    assert search.parameters[0].name == "q"
    assert search.status == EndpointStatus.FUZZ_READY
    assert repository.get_baseline(search.baseline_ref).observation_id == search.baseline_observation_ref
    assert all(item.status == EndpointStatus.FUZZ_READY for item in inventory.entries)
    assert result.coverage.route_count == 2 and result.coverage.observation_count == 3
    assert result.coverage.baseline_count == result.coverage.fuzz_ready_count == 2
    for entry in inventory.entries:
        for proof in entry.provenance:
            artifact = repository.get_evidence(proof.evidence_ref)
            manifest = EvidenceManifest.model_validate(artifact.model_dump(exclude={"relative_path"}))
            assert manifest.tool_run_id == manifest.request_id == proof.request_ref
            assert manifest.task_id == result.task_id and manifest.run_id == result.run_id
            assert manifest.kind == "http_exchange" and manifest.content_type == "application/json"
            assert manifest.redaction_status == "UNREVIEWED"
            assert repository.get_tool_run(manifest.tool_run_id) is not None
    invalid = search.model_dump()
    invalid["has_verified_baseline"] = False
    with pytest.raises(ValidationError, match="readiness"):
        type(search).model_validate(invalid)


def test_evidence_corruption_revokes_readiness_and_export(tmp_path):
    repository, evidence, _, service, result = discovered(tmp_path)
    profile = next(entry for entry in result.endpoints if entry.canonical_path == "/profile")
    baseline = repository.get_baseline(profile.baseline_id)
    artifact = repository.get_evidence(baseline.evidence_id)
    (evidence.directory / artifact.relative_path).write_bytes(b"tampered")
    refreshed = service.snapshot(result.task_id)
    profile = next(entry for entry in refreshed.endpoints if entry.canonical_path == "/profile")
    assert profile.lifecycle == EndpointStatus.DISCOVERED and profile.baseline_verified is False
    assert not next(item for item in refreshed.observations if item.endpoint_id == profile.id).evidence_verified
    assert all(entry.canonical_path != "/profile" for entry in refreshed.attack_surface_inventory.entries)
    assert refreshed.coverage.baseline_count == refreshed.coverage.fuzz_ready_count == 1


def test_optional_parameters_do_not_block_but_required_input_revokes_readiness(tmp_path):
    repository, _, _, service, result = discovered(tmp_path)
    profile = next(entry for entry in result.endpoints if entry.canonical_path == "/profile")
    repository.save_endpoint(WebEndpointEntry(task_id=result.task_id, url=profile.url, parameters=(
        EndpointParameter(name="page", location="query", required=False),
    )))
    ready = service.snapshot(result.task_id)
    assert next(entry for entry in ready.attack_surface_inventory.entries if entry.id == profile.id).status == EndpointStatus.FUZZ_READY
    repository.save_endpoint(WebEndpointEntry(task_id=result.task_id, url=profile.url, parameters=(
        EndpointParameter(name="token", location="header", required=True),
    )))
    refreshed = service.snapshot(result.task_id)
    blocked = next(entry for entry in refreshed.attack_surface_inventory.entries if entry.id == profile.id)
    assert blocked.status == EndpointStatus.BASELINED and blocked.has_unresolved_required_input


def test_product_contract_imports_without_recon_implementation():
    completed = subprocess.run([sys.executable, "-B", "-c",
                               "import sys; from src.contracts.attack_surface import AttackSurfaceInventory; "
                               "from src.contracts.evidence import EvidenceManifest; "
                               "assert not any(name.startswith('src.recon') for name in sys.modules)"],
                              capture_output=True, text=True, timeout=10, check=False)
    assert completed.returncode == 0, completed.stderr


def test_versioned_shared_contract_schema_is_frozen():
    fixture = Path(__file__).parent / "fixtures" / "attack-surface-v1.schema.json"
    assert json.loads(fixture.read_text(encoding="utf-8")) == AttackSurfaceInventory.model_json_schema()


def test_unversioned_database_upgrades_routes_evidence_claims_without_losing_history(tmp_path):
    repository, evidence, gateway, service, result = discovered(tmp_path)
    # Reconstruct the exact old full-URL endpoint/baseline layout from durable observations.
    # This fixture has no schema_migrations table, just like a deployed Day-1/Day-2 DB.
    database = repository.database_path
    original_evidence = {artifact_id: evidence.read(artifact_id) for artifact_id in result.evidence_ids}
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM web_endpoints")
        connection.execute("DELETE FROM baseline_requests")
        for observation in result.observations:
            endpoint = next(item for item in result.endpoints if item.id == observation.endpoint_id)
            raw = endpoint.model_dump(mode="json")
            baseline = repository.get_baseline(endpoint.baseline_id).model_dump(mode="json")
            old_baseline_id = stable_id(observation.id, observation.request_id)
            raw.update(url=observation.url, baseline_id=old_baseline_id)
            for name in ("in_scope", "baseline_verified", "baseline_url", "is_testable"):
                raw.pop(name)
            raw["provenance"] = [p.model_dump(mode="json", exclude={"request_id", "observation_id"}) for p in observation.provenance]
            baseline.update(endpoint_id=observation.id, request_id=observation.request_id, url=observation.url,
                            evidence_id=observation.evidence_id, response=observation.response.model_dump(mode="json"))
            baseline.pop("observation_id")
            connection.execute("INSERT INTO web_endpoints VALUES (?, ?, ?)", (observation.id, result.task_id, json.dumps(raw)))
            connection.execute("INSERT INTO baseline_requests VALUES (?, ?, ?)", (old_baseline_id, result.task_id, json.dumps(baseline)))
        for artifact_id, raw in list(connection.execute("SELECT id, payload FROM evidence_artifacts")):
            artifact = json.loads(raw)
            for name in ("run_id", "tool_run_id", "kind", "content_type", "metadata", "redaction_status"):
                artifact.pop(name)
            connection.execute("UPDATE evidence_artifacts SET payload = ? WHERE id = ?", (json.dumps(artifact), artifact_id))
        connection.execute("INSERT INTO execution_claims VALUES (?, ?, ?)", ("orphan", result.task_id, result.tool_results[0].started_at.isoformat()))
        for table in ("schema_migrations", "endpoint_observations", "tool_runs", "policy_audit", "execution_reservations"):
            connection.execute(f"DROP TABLE {table}")
    upgraded = ReconRepository(database)
    assert len(upgraded.list_endpoints(result.task_id)) == 2
    assert len(upgraded.list_observations(result.task_id)) == 3
    assert upgraded.list_tool_results(result.task_id) == result.tool_results
    assert len(upgraded.list_plans(result.task_id)) == len(repository.list_plans(result.task_id))
    assert upgraded.get_recon_result(result.task_id) is None  # Derived snapshots are rebuilt.
    for artifact_id in result.evidence_ids:
        assert evidence.read(artifact_id) == original_evidence[artifact_id]
        artifact = upgraded.get_evidence(artifact_id)
        assert artifact.run_id == result.run_id and artifact.redaction_status == "UNREVIEWED"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall() == [(1,), (2,), (3,)]
        assert connection.execute("SELECT COUNT(*) FROM baseline_requests").fetchone()[0] == 3
    gateway.results = upgraded
    orphan = CapabilityRequest(id="orphan", task_id=result.task_id, target_ip="127.0.0.1",
                               capability=Capability.HTTP_FETCH, parameters=HttpFetchParams(port=8000))
    recovered = gateway.execute(orphan)
    assert recovered.status == "error" and "legacy incomplete" in recovered.message
    assert upgraded.get_tool_result("orphan") == recovered
    refreshed = service.snapshot(result.task_id)
    assert all(entry.status == EndpointStatus.FUZZ_READY for entry in refreshed.attack_surface_inventory.entries)
    assert len(refreshed.attack_surface_inventory.entries) == 2
    reopened = ReconRepository(database)
    assert reopened.get_recon_result(result.task_id) == refreshed


def test_migration_rejects_newer_schema_without_mutation(tmp_path):
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
        connection.execute("INSERT INTO schema_migrations VALUES (999, 'future', 'later')")
    with pytest.raises(RuntimeError, match="newer"):
        ReconRepository(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("schema_migrations",)]


def test_failed_migration_rolls_back_schema_and_version(tmp_path, monkeypatch):
    from src.storage import migrations

    def interrupted(connection):
        connection.execute("CREATE TABLE partial_migration (id TEXT)")
        raise RuntimeError("migration interrupted")

    path = tmp_path / "failed.db"
    monkeypatch.setattr(migrations, "MIGRATIONS", (*migrations.MIGRATIONS, (4, "interrupted", interrupted)))
    with pytest.raises(RuntimeError, match="interrupted"):
        ReconRepository(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == []
