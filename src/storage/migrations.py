"""Ordered, transactional SQLite migrations; the only schema creation authority."""

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from urllib.parse import urlsplit


def _legacy_schema(connection):
    definitions = {
        "recon_tasks": "id TEXT PRIMARY KEY, payload TEXT NOT NULL",
        "tool_results": "request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL",
        "execution_claims": "request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, claimed_at TEXT NOT NULL",
        "policy_decisions": "request_id TEXT PRIMARY KEY, payload TEXT NOT NULL",
        "evidence_artifacts": "id TEXT PRIMARY KEY, task_id TEXT NOT NULL, request_id TEXT NOT NULL, payload TEXT NOT NULL",
        "recon_results": "task_id TEXT PRIMARY KEY, payload TEXT NOT NULL",
        "recon_plans": "id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL",
        "web_endpoints": "id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL",
        "discovery_sources": "id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL",
        "baseline_requests": "id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL",
        "recon_coverage": "task_id TEXT PRIMARY KEY, payload TEXT NOT NULL",
    }
    for name, columns in definitions.items():
        connection.execute(f"CREATE TABLE IF NOT EXISTS {name} ({columns})")


def _route_observations(connection):
    from src.recon.endpoints import merge_endpoints
    from src.recon.urls import route_url
    from src.recon.web_models import EndpointObservation, EndpointProvenance, WebEndpointEntry, stable_id

    connection.execute("CREATE TABLE endpoint_observations (id TEXT PRIMARY KEY, task_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, payload TEXT NOT NULL)")
    connection.execute("CREATE INDEX observations_by_route ON endpoint_observations(endpoint_id)")
    sources = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT id, payload FROM discovery_sources")}
    results = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT request_id, payload FROM tool_results")}
    merged = {}
    baseline_ids = {}
    baselines = list(connection.execute("SELECT id, payload FROM baseline_requests"))
    for old_id, raw in baselines:
        item = json.loads(raw)
        item["endpoint_id"] = stable_id(item["task_id"], item["method"], route_url(item["url"]))
        item["observation_id"] = stable_id(item["task_id"], item["method"], item["url"])
        new_id = stable_id(item["endpoint_id"], item["request_id"])
        baseline_ids[old_id] = (new_id, item["url"])
        connection.execute("DELETE FROM baseline_requests WHERE id = ?", (old_id,))
        connection.execute("INSERT OR IGNORE INTO baseline_requests VALUES (?, ?, ?)", (new_id, item["task_id"], json.dumps(item)))
    for old_id, raw in list(connection.execute("SELECT id, payload FROM web_endpoints")):
        item = json.loads(raw)
        concrete = item["url"]
        obs_id = stable_id(item["task_id"], item["method"], concrete)
        route_id = stable_id(item["task_id"], item["method"], route_url(concrete))
        provenance = []
        for entry in item.get("provenance", []):
            source = sources.get(entry["source_id"], {})
            provenance.append(EndpointProvenance(**{**entry, "observation_id": obs_id, "request_id": source.get("request_id")}))
        source = sources.get(old_id, {})
        result = results.get(source.get("request_id"), {})
        observation = EndpointObservation(
            task_id=item["task_id"], endpoint_id=route_id, url=concrete, method=item["method"],
            provenance=tuple(provenance), request_id=result.get("request_id"), evidence_id=result.get("evidence_id"),
            response=result.get("http_response"), observed_at=result.get("finished_at"),
        )
        connection.execute("INSERT OR IGNORE INTO endpoint_observations VALUES (?, ?, ?, ?)",
                           (obs_id, item["task_id"], route_id, observation.model_dump_json()))
        item.update(url=route_url(concrete), provenance=provenance, baseline_verified=False, in_scope=False)
        if item.get("baseline_id") in baseline_ids:
            item["baseline_id"], item["baseline_url"] = baseline_ids[item["baseline_id"]]
        if item["lifecycle"] == "FUZZ_READY":
            item["lifecycle"] = "BASELINED"
        endpoint = WebEndpointEntry.model_validate(item)
        merged[route_id] = merge_endpoints(merged[route_id], endpoint) if route_id in merged else endpoint
    connection.execute("DELETE FROM web_endpoints")
    for endpoint in merged.values():
        connection.execute("INSERT INTO web_endpoints VALUES (?, ?, ?)", (endpoint.id, endpoint.task_id, endpoint.model_dump_json()))
    # These are derived snapshots. Durable results, evidence and plans remain intact.
    connection.execute("DELETE FROM recon_results")
    connection.execute("DELETE FROM recon_coverage")


def _execution_contracts(connection):
    from src.recon.execution import ToolRun, ToolRunState
    from src.recon.models import CapabilityRequest

    connection.execute("CREATE TABLE tool_runs (request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL)")
    connection.execute("CREATE TABLE execution_reservations (request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, capability TEXT NOT NULL, started_at TEXT NOT NULL)")
    connection.execute("CREATE INDEX reservations_by_task ON execution_reservations(task_id, started_at)")
    connection.execute("CREATE TABLE policy_audit (request_id TEXT NOT NULL, attempt INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(request_id, attempt))")
    now = datetime.now(UTC)
    results = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT request_id, payload FROM tool_results")}
    claims = {row[0]: (row[1], row[2]) for row in connection.execute("SELECT request_id, task_id, claimed_at FROM execution_claims")}
    requests = {}
    for row in connection.execute("SELECT payload FROM recon_plans"):
        for action in json.loads(row[0])["actions"]:
            request = CapabilityRequest.model_validate(action["request"])
            requests[request.id] = request.model_dump_json()
    for request_id in sorted(results.keys() | claims.keys()):
        result = results.get(request_id)
        task_id, claimed = claims.get(request_id, (result["task_id"], result["started_at"]) if result else ("", now.isoformat()))
        state = {"success": ToolRunState.SUCCEEDED, "denied": ToolRunState.DENIED}.get(result.get("status"), ToolRunState.FAILED) if result else ToolRunState.FAILED
        payload = requests.get(request_id)
        run = ToolRun(request_id=request_id, task_id=task_id, state=state, owner_token="migrated",
                      request_fingerprint=hashlib.sha256(payload.encode()).hexdigest() if payload else "",
                      request_payload=payload, lease_expires_at=None, queued_at=claimed,
                      finished_at=now, message="migrated result" if result else "legacy incomplete claim; execution outcome unknown")
        connection.execute("INSERT INTO tool_runs VALUES (?, ?, ?)", (request_id, task_id, run.model_dump_json()))
        if result and result["status"] != "denied":
            connection.execute("INSERT INTO execution_reservations VALUES (?, ?, ?, ?)",
                               (request_id, task_id, result["capability"], result["started_at"]))
    tasks = {row[0]: json.loads(row[1]) for row in connection.execute("SELECT id, payload FROM recon_tasks")}
    for artifact_id, raw in list(connection.execute("SELECT id, payload FROM evidence_artifacts")):
        item = json.loads(raw)
        item.update(run_id=tasks.get(item["task_id"], {}).get("run_id", "legacy-unknown"),
                    tool_run_id=item["request_id"], kind="tool_output", content_type="application/octet-stream",
                    redaction_status="UNREVIEWED", metadata={"migration": "legacy evidence; original bytes preserved"})
        connection.execute("UPDATE evidence_artifacts SET payload = ? WHERE id = ?", (json.dumps(item), artifact_id))
    for request_id, raw in list(connection.execute("SELECT request_id, payload FROM policy_decisions")):
        decision = json.loads(raw)
        decision.setdefault("policy_version", "legacy-day1-day2")
        decision.setdefault("policy_fingerprint", hashlib.sha256(raw.encode()).hexdigest())
        decision.setdefault("outcome", "ALLOW" if decision["allowed"] else "DENY")
        connection.execute("UPDATE policy_decisions SET payload = ? WHERE request_id = ?", (json.dumps(decision), request_id))
    connection.execute("INSERT INTO policy_audit SELECT request_id, 1, payload FROM policy_decisions")


def _authorization_binding(connection):
    """Bind historical request payloads for replay without reauthorizing old work."""
    from src.recon.execution import ToolRun
    from src.recon.models import CapabilityRequest, ReconTask
    from src.recon.policy import PolicyService

    tasks = {}
    for task_id, payload in connection.execute("SELECT id, payload FROM recon_tasks"):
        raw_task = json.loads(payload)
        # v4 predates policy snapshots; never bind historical work to today's default.
        raw_task["policy_version"] = "recon-2.2"
        tasks[task_id] = ReconTask.model_validate(raw_task)
    for request_id, raw in list(connection.execute("SELECT request_id, payload FROM tool_runs")):
        item = ToolRun.model_validate_json(raw)
        task = tasks.get(item.task_id)
        if task and item.request_payload:
            request = CapabilityRequest.model_validate_json(item.request_payload)
            request = request.model_copy(update={
                "run_id": task.run_id, "scope_version": task.scope_version,
                "action_fingerprint": PolicyService.expected_fingerprint(request, task),
            })
            payload = request.model_dump_json()
            item = item.model_copy(update={
                "request_payload": payload, "request_fingerprint": hashlib.sha256(payload.encode()).hexdigest(),
            })
            connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (item.model_dump_json(), request_id))
    for request_id, raw in list(connection.execute("SELECT request_id, payload FROM policy_decisions")):
        item = json.loads(raw)
        item["risk"] = "R0" if item.get("risk") == "bounded_recon" else item.get("risk", "R0")
        item.setdefault("action_fingerprint", "")  # Historical policy did not bind an action fingerprint.
        item.setdefault("scope_version", "legacy")
        connection.execute("UPDATE policy_decisions SET payload = ? WHERE request_id = ?", (json.dumps(item), request_id))
        connection.execute("UPDATE policy_audit SET payload = ? WHERE request_id = ?", (json.dumps(item), request_id))


def _declared_templates(connection):
    from src.recon.urls import valid_template_path
    from src.recon.web_models import stable_id

    for route_id, raw in list(connection.execute("SELECT id, payload FROM web_endpoints")):
        route = json.loads(raw)
        path = urlsplit(route["url"]).path
        if valid_template_path(path) and any(
            item.get("kind") == "openapi" and item.get("relation") == "operation"
            for item in route.get("provenance", [])
        ):
            route["route_template"] = path
        if "{" in path or "}" in path:
            placeholder_id = stable_id(route["task_id"], route["method"], route["url"])
            for item in route.get("provenance", []):
                if item.get("observation_id") == placeholder_id:
                    item["observation_id"] = None
        connection.execute("UPDATE web_endpoints SET payload = ? WHERE id = ?", (json.dumps(route), route_id))
    for observation_id, raw in list(connection.execute("SELECT id, payload FROM endpoint_observations")):
        item = json.loads(raw)
        if ("{" in urlsplit(item["url"]).path or "}" in urlsplit(item["url"]).path) and not item.get("request_id"):
            connection.execute("DELETE FROM endpoint_observations WHERE id = ?", (observation_id,))
    connection.execute("DELETE FROM recon_results")
    connection.execute("DELETE FROM recon_coverage")


def _recon_policy_snapshot(connection):
    for task_id, payload in list(connection.execute("SELECT id, payload FROM recon_tasks")):
        task = json.loads(payload)
        if "policy_version" not in task:
            task["policy_version"] = "recon-2.2"
            connection.execute("UPDATE recon_tasks SET payload = ? WHERE id = ?", (json.dumps(task), task_id))


def _adaptive_planning(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS recon_planning_sessions (
        task_id TEXT PRIMARY KEY, binding TEXT NOT NULL, config TEXT NOT NULL, stop_reason TEXT
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS recon_planning_rounds (
        task_id TEXT NOT NULL, number INTEGER NOT NULL, state TEXT NOT NULL,
        owner TEXT NOT NULL, expires_at TEXT NOT NULL, context TEXT NOT NULL,
        decision TEXT, plan TEXT, rejections TEXT NOT NULL DEFAULT '[]',
        action_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(task_id, number)
    )""")


def _adaptive_stages(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS recon_stages (
        task_id TEXT NOT NULL, name TEXT NOT NULL, plan TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'PLANNED', PRIMARY KEY(task_id, name))""")
    for table, column, declaration in (("recon_planning_rounds", "error_code", "TEXT"),
                                        ("execution_reservations", "request_units", "INTEGER NOT NULL DEFAULT 1")):
        if column not in {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _recon_assets_v2(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS recon_authorizations (
        task_id TEXT PRIMARY KEY, payload TEXT NOT NULL
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS discovered_assets (
        id TEXT PRIMARY KEY, task_id TEXT NOT NULL, verification_status TEXT NOT NULL, payload TEXT NOT NULL
    )""")
    connection.execute("CREATE INDEX IF NOT EXISTS assets_by_task_status ON discovered_assets(task_id, verification_status)")
    connection.execute("""CREATE TABLE IF NOT EXISTS derived_bindings (
        task_id TEXT NOT NULL, host TEXT NOT NULL, scheme TEXT NOT NULL, port INTEGER NOT NULL,
        payload TEXT NOT NULL, PRIMARY KEY(task_id, host, scheme, port)
    )""")
    connection.execute("""CREATE TABLE IF NOT EXISTS dns_observations (
        id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL
    )""")


MIGRATIONS = (
    (1, "adopt_day1_day2_schema", _legacy_schema),
    (2, "route_observations", _route_observations),
    (3, "durable_execution_and_evidence", _execution_contracts),
    (4, "authorization_binding", _authorization_binding),
    (5, "declared_route_templates", _declared_templates),
    (6, "v6_recon_policy_snapshot", _recon_policy_snapshot),
    (7, "bounded_adaptive_planning", _adaptive_planning),
    (8, "adaptive_stages_and_bounded_content_budget", _adaptive_stages),
    (9, "recon_discovered_assets_v2", _recon_assets_v2),
)


def migrate(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
        applied = {row[0] for row in connection.execute("SELECT version FROM schema_migrations")}
        if applied - {version for version, _, _ in MIGRATIONS}:
            raise RuntimeError("database schema is newer than this application")
        for version, name, apply in MIGRATIONS:
            if version not in applied:
                apply(connection)
                connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (version, name, datetime.now(UTC).isoformat()))
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
