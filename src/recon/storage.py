"""Small SQLite repositories and content-addressed Recon evidence metadata."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from src.recon.endpoints import merge_endpoints
from src.recon.execution import ToolRun, ToolRunState
from src.recon.models import (
    Capability,
    CapabilityRequest,
    EvidenceArtifact,
    PolicyDecision,
    PolicyOutcome,
    ReconPlan,
    ReconResult,
    ReconTask,
    ToolResult,
)
from src.recon.urls import match_route_template
from src.recon.web_models import BaselineRequest, DiscoverySource, EndpointObservation, ReconCoverage, WebEndpointEntry
from src.storage.migrations import migrate

MAX_EVIDENCE_BYTES = 262_144


class ReconRepository:
    def __init__(self, database_path: Path | str, *, clock=None) -> None:
        self.clock = clock or (lambda: datetime.now(UTC))
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            migrate(connection)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path)

    def save_task(self, task: ReconTask) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO recon_tasks (id, payload) VALUES (?, ?)", (task.id, task.model_dump_json()))

    def get_task(self, task_id: str) -> ReconTask | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM recon_tasks WHERE id = ?", (task_id,)).fetchone()
        return ReconTask.model_validate_json(row[0]) if row else None

    def claim_request(self, request: CapabilityRequest) -> bool:
        return self.acquire_tool_run(request) is not None

    def acquire_tool_run(self, request: CapabilityRequest) -> ToolRun | None:
        from src.recon.policy import PolicyService

        request = PolicyService(self).bind(request)
        now = self.clock()
        run = ToolRun(request_id=request.id, task_id=request.task_id, state=ToolRunState.QUEUED,
                      owner_token=str(uuid4()), request_fingerprint=hashlib.sha256(request.model_dump_json().encode()).hexdigest(),
                      request_payload=request.model_dump_json(), queued_at=now, lease_expires_at=now + timedelta(seconds=120),
                      parent_request_id=request.parent_request_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if request.parent_request_id:
                row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (request.parent_request_id,)).fetchone()
                if row is None:
                    return None
                parent = ToolRun.model_validate_json(row[0])
                parent_request = CapabilityRequest.model_validate_json(parent.request_payload) if parent.request_payload else None
                if (parent.task_id != request.task_id or parent.state != ToolRunState.RUNNING
                        or parent.lease_expires_at <= now or parent_request is None
                        or parent_request.capability != Capability.BROWSER_EXPLORE
                        or parent_request.target_ip != request.target_ip
                        or parent_request.parameters.port != request.parameters.port
                        or parent_request.parameters.scheme != request.parameters.scheme):
                    return None
            cursor = connection.execute(
                "INSERT OR IGNORE INTO tool_runs VALUES (?, ?, ?)", (request.id, request.task_id, run.model_dump_json()),
            )
            if cursor.rowcount == 1:
                connection.execute("INSERT OR IGNORE INTO execution_claims VALUES (?, ?, ?)", (request.id, request.task_id, now.isoformat()))
        return run if cursor.rowcount == 1 else None

    def get_tool_run(self, request_id: str) -> ToolRun | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (request_id,)).fetchone()
        return ToolRun.model_validate_json(row[0]) if row else None

    def list_tool_runs(self, task_id: str) -> tuple[ToolRun, ...]:
        with self._connect() as connection:
            return tuple(ToolRun.model_validate_json(row[0]) for row in connection.execute(
                "SELECT payload FROM tool_runs WHERE task_id = ? ORDER BY rowid", (task_id,)))

    def list_child_runs(self, parent_request_id: str) -> tuple[ToolRun, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM tool_runs ORDER BY rowid")
            return tuple(run for row in rows if (run := ToolRun.model_validate_json(row[0])).parent_request_id == parent_request_id)

    @staticmethod
    def _failed_result(request: CapabilityRequest, run: ToolRun) -> ToolResult:
        return ToolResult(request_id=request.id, task_id=request.task_id, capability=request.capability,
                          target_ip=request.target_ip, status="error", message=run.message,
                          started_at=run.started_at or run.queued_at, finished_at=run.finished_at)

    def recover_expired_runs(self, task_id: str, request: CapabilityRequest | None = None) -> None:
        now = self.clock()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = list(connection.execute("SELECT payload FROM tool_runs WHERE task_id = ?", (task_id,)))
            for row in rows:
                run = ToolRun.model_validate_json(row[0])
                if run.state in (ToolRunState.QUEUED, ToolRunState.RUNNING) and run.lease_expires_at <= now:
                    run = run.model_copy(update={"state": ToolRunState.FAILED, "finished_at": now,
                                                 "message": "execution lease expired; outcome unknown; automatic replay prohibited"})
                    connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (run.model_dump_json(), run.request_id))
                if run.state == ToolRunState.FAILED:
                    saved_request = CapabilityRequest.model_validate_json(run.request_payload) if run.request_payload else None
                    if saved_request is None and request and request.id == run.request_id:
                        saved_request = request
                    if saved_request:
                        result = self._failed_result(saved_request, run)
                        connection.execute("INSERT OR IGNORE INTO tool_results VALUES (?, ?, ?, ?)",
                                           (result.request_id, result.task_id, result.status, result.model_dump_json()))

    def _budget_denial(self, connection, request: CapabilityRequest) -> str | None:
        row = connection.execute("SELECT payload FROM recon_tasks WHERE id = ?", (request.task_id,)).fetchone()
        if row is None:
            return "unknown task"
        task = ReconTask.model_validate_json(row[0])
        if task.expires_at <= self.clock():
            return "task expired"
        budget = task.execution_budget
        total, fetches, recent = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(capability = ?), 0), COALESCE(SUM(started_at > ?), 0) "
            "FROM execution_reservations WHERE task_id = ?",
            (Capability.HTTP_FETCH.value, (self.clock() - timedelta(seconds=1)).isoformat(), task.id),
        ).fetchone()
        if total >= budget.max_requests:
            return "task request budget exhausted"
        if request.capability == Capability.HTTP_FETCH and fetches >= task.discovery_limits.max_requests:
            return "HTTP_FETCH discovery request budget exhausted"
        if recent >= budget.max_requests_per_second:
            return "task request rate exceeded"
        return None

    def budget_denial(self, request: CapabilityRequest) -> str | None:
        with self._connect() as connection:
            return self._budget_denial(connection, request)

    def budget_usage(self, task_id: str) -> int:
        with self._connect() as connection:
            return connection.execute("SELECT COUNT(*) FROM execution_reservations WHERE task_id = ?", (task_id,)).fetchone()[0]

    @staticmethod
    def _save_decision(connection, decision):
        connection.execute("INSERT INTO policy_decisions VALUES (?, ?) ON CONFLICT(request_id) DO UPDATE SET payload=excluded.payload",
                           (decision.request_id, decision.model_dump_json()))
        connection.execute("INSERT INTO policy_audit VALUES (?, ?, ?) ON CONFLICT(request_id, attempt) DO UPDATE SET payload=excluded.payload",
                           (decision.request_id, decision.attempt, decision.model_dump_json()))

    def start_tool_run(self, run: ToolRun, request: CapabilityRequest, decision: PolicyDecision) -> PolicyDecision:
        """Reserve budget, persist policy, and fence dispatch in a single transaction."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = ToolRun.model_validate_json(connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (run.request_id,)).fetchone()[0])
            if current.owner_token != run.owner_token or current.state != ToolRunState.QUEUED or current.lease_expires_at <= self.clock():
                raise RuntimeError("execution lease lost before dispatch")
            if request.parent_request_id:
                parent_row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (request.parent_request_id,)).fetchone()
                parent = ToolRun.model_validate_json(parent_row[0]) if parent_row else None
                if parent is None or parent.state != ToolRunState.RUNNING or parent.lease_expires_at <= self.clock():
                    decision = decision.model_copy(update={"allowed": False, "outcome": PolicyOutcome.DENY,
                                                           "reason": "browser parent is not running"})
            reason = self._budget_denial(connection, request) if decision.allowed else None
            if reason:
                decision = decision.model_copy(update={"allowed": False, "outcome": PolicyOutcome.DENY, "reason": reason})
            self._save_decision(connection, decision)
            if decision.allowed:
                connection.execute("INSERT INTO execution_reservations VALUES (?, ?, ?, ?)",
                                   (request.id, request.task_id, request.capability.value, self.clock().isoformat()))
                current = current.model_copy(update={"state": ToolRunState.RUNNING, "started_at": self.clock()})
                connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (current.model_dump_json(), current.request_id))
        return decision

    def mark_external_dispatched(self, run: ToolRun) -> bool:
        """Spend the single continuation permit, guarded by parent and child states."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (run.request_id,)).fetchone()
            if row is None:
                return False
            current = ToolRun.model_validate_json(row[0])
            parent_row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (current.parent_request_id,)).fetchone()
            parent = ToolRun.model_validate_json(parent_row[0]) if parent_row else None
            if (current.owner_token != run.owner_token or current.state != ToolRunState.RUNNING
                    or current.external_dispatched_at is not None or current.lease_expires_at <= self.clock()
                    or parent is None or parent.state != ToolRunState.RUNNING or parent.lease_expires_at <= self.clock()):
                return False
            parent_request = CapabilityRequest.model_validate_json(parent.request_payload)
            dispatched = sum(
                child.parent_request_id == parent.request_id and child.external_dispatched_at is not None
                for row in connection.execute("SELECT payload FROM tool_runs WHERE task_id = ?", (parent.task_id,))
                if (child := ToolRun.model_validate_json(row[0]))
            )
            if dispatched >= parent_request.parameters.limits.max_requests:
                return False
            current = current.model_copy(update={"external_dispatched_at": self.clock()})
            connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (current.model_dump_json(), run.request_id))
            return True

    def cancel_tool_run(self, request_id: str) -> ToolResult | None:
        """Atomically cancel a run and its live children; terminal results fence late workers."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            ids = [request_id]
            ids.extend(run.request_id for row in connection.execute("SELECT payload FROM tool_runs")
                       if (run := ToolRun.model_validate_json(row[0])).parent_request_id == request_id)
            root_result = None
            for current_id in ids:
                row = connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (current_id,)).fetchone()
                if row is None:
                    continue
                run = ToolRun.model_validate_json(row[0])
                existing = connection.execute("SELECT payload FROM tool_results WHERE request_id = ?", (current_id,)).fetchone()
                if existing:
                    if current_id == request_id:
                        root_result = ToolResult.model_validate_json(existing[0])
                    continue
                if run.state not in (ToolRunState.QUEUED, ToolRunState.RUNNING):
                    continue
                request = CapabilityRequest.model_validate_json(run.request_payload)
                result = ToolResult(request_id=current_id, task_id=run.task_id,
                                    capability=request.capability, target_ip=request.target_ip,
                                    parent_request_id=request.parent_request_id, status="cancelled",
                                    message="execution cancelled", started_at=run.started_at or run.queued_at,
                                    finished_at=self.clock())
                updated = run.model_copy(update={"state": ToolRunState.CANCELLED,
                                                 "finished_at": self.clock(), "message": result.message})
                connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (updated.model_dump_json(), current_id))
                connection.execute("INSERT INTO tool_results VALUES (?, ?, ?, ?)",
                                   (current_id, run.task_id, result.status, result.model_dump_json()))
                if current_id == request_id:
                    root_result = result
            return root_result

    def finish_tool_run(self, run: ToolRun, result: ToolResult, *, timed_out: bool = False) -> ToolResult:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = ToolRun.model_validate_json(connection.execute("SELECT payload FROM tool_runs WHERE request_id = ?", (run.request_id,)).fetchone()[0])
            existing = connection.execute("SELECT payload FROM tool_results WHERE request_id = ?", (run.request_id,)).fetchone()
            if existing:
                return ToolResult.model_validate_json(existing[0])
            if current.owner_token != run.owner_token or current.state not in (ToolRunState.QUEUED, ToolRunState.RUNNING):
                raise RuntimeError("execution owner lost")
            if current.lease_expires_at <= self.clock():
                current = current.model_copy(update={"message": "execution lease expired; late result rejected", "finished_at": self.clock()})
                result = self._failed_result(CapabilityRequest.model_validate_json(current.request_payload), current)
                timed_out = False
            state = {"success": ToolRunState.SUCCEEDED, "denied": ToolRunState.DENIED,
                     "cancelled": ToolRunState.CANCELLED}.get(result.status, ToolRunState.FAILED)
            current = current.model_copy(update={"state": ToolRunState.TIMED_OUT if timed_out else state,
                                                 "finished_at": self.clock(), "message": result.message})
            connection.execute("UPDATE tool_runs SET payload = ? WHERE request_id = ?", (current.model_dump_json(), run.request_id))
            connection.execute("INSERT INTO tool_results VALUES (?, ?, ?, ?)", (result.request_id, result.task_id, result.status, result.model_dump_json()))
        return result

    def save_policy_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as connection:
            self._save_decision(connection, decision)

    def get_policy_decision(self, request_id: str) -> PolicyDecision | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM policy_decisions WHERE request_id = ?", (request_id,)).fetchone()
        return PolicyDecision.model_validate_json(row[0]) if row else None

    def save_tool_result(self, result: ToolResult) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tool_results (request_id, task_id, status, payload) VALUES (?, ?, ?, ?)",
                (result.request_id, result.task_id, result.status, result.model_dump_json()),
            )

    def get_tool_result(self, request_id: str) -> ToolResult | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM tool_results WHERE request_id = ?", (request_id,)).fetchone()
        return ToolResult.model_validate_json(row[0]) if row else None

    def list_tool_results(self, task_id: str) -> tuple[ToolResult, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM tool_results WHERE task_id = ? ORDER BY rowid", (task_id,))
            return tuple(ToolResult.model_validate_json(row[0]) for row in rows)

    def save_plan(self, plan: ReconPlan) -> None:
        with self._connect() as connection:
            connection.execute("INSERT OR IGNORE INTO recon_plans VALUES (?, ?, ?)",
                               (plan.id, plan.task_id, plan.model_dump_json()))

    def list_plans(self, task_id: str) -> tuple[ReconPlan, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM recon_plans WHERE task_id = ? ORDER BY rowid", (task_id,))
            return tuple(ReconPlan.model_validate_json(row[0]) for row in rows)

    def save_evidence(self, artifact: EvidenceArtifact) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO evidence_artifacts (id, task_id, request_id, payload) VALUES (?, ?, ?, ?)",
                (artifact.id, artifact.task_id, artifact.request_id, artifact.model_dump_json()),
            )

    def get_evidence(self, artifact_id: str) -> EvidenceArtifact | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM evidence_artifacts WHERE id = ?", (artifact_id,)).fetchone()
        return EvidenceArtifact.model_validate_json(row[0]) if row else None

    def save_recon_result(self, result: ReconResult) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO recon_results (task_id, payload) VALUES (?, ?) "
                "ON CONFLICT(task_id) DO UPDATE SET payload=excluded.payload",
                (result.task_id, result.model_dump_json()),
            )

    def get_recon_result(self, task_id: str) -> ReconResult | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM recon_results WHERE task_id = ?", (task_id,)).fetchone()
        return ReconResult.model_validate_json(row[0]) if row else None

    def save_endpoint(self, endpoint: WebEndpointEntry) -> WebEndpointEntry:
        endpoint = WebEndpointEntry.model_validate_json(endpoint.model_dump_json())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM web_endpoints WHERE id = ?", (endpoint.id,)).fetchone()
            if row:
                endpoint = merge_endpoints(WebEndpointEntry.model_validate_json(row[0]), endpoint)
            connection.execute("INSERT INTO web_endpoints VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                               (endpoint.id, endpoint.task_id, endpoint.model_dump_json()))
        return endpoint

    def get_endpoint(self, endpoint_id: str) -> WebEndpointEntry | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM web_endpoints WHERE id = ?", (endpoint_id,)).fetchone()
        return WebEndpointEntry.model_validate_json(row[0]) if row else None

    def list_endpoints(self, task_id: str) -> tuple[WebEndpointEntry, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM web_endpoints WHERE task_id = ? ORDER BY id", (task_id,))
            return tuple(WebEndpointEntry.model_validate_json(row[0]) for row in rows)

    def matching_template(self, task_id: str, method: str, concrete_url: str) -> WebEndpointEntry | None:
        candidates = tuple(endpoint for endpoint in self.list_endpoints(task_id)
                           if endpoint.method == method and endpoint.route_template
                           and match_route_template(endpoint.url, concrete_url) is not None)
        return candidates[0] if len(candidates) == 1 else None

    def reconcile_all_templates(self, task_id: str) -> None:
        for template in self.list_endpoints(task_id):
            if template.route_template:
                self.reconcile_template(template)

    def reconcile_template(self, template: WebEndpointEntry) -> None:
        """Move precise concrete routes to a unique trusted template, preserving proof IDs."""
        for old in self.list_endpoints(template.task_id):
            if old.id == template.id or old.route_template or not self.matching_template(old.task_id, old.method, old.url):
                continue
            if self.matching_template(old.task_id, old.method, old.url).id != template.id:
                continue
            self._rebind_route(old, template)

    def _rebind_route(self, old: WebEndpointEntry, template: WebEndpointEntry) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute("SELECT payload FROM web_endpoints WHERE id = ?", (template.id,)).fetchone()
            previous = connection.execute("SELECT payload FROM web_endpoints WHERE id = ?", (old.id,)).fetchone()
            if current is None or previous is None:
                return
            template = WebEndpointEntry.model_validate_json(current[0])
            old = WebEndpointEntry.model_validate_json(previous[0])
            baseline_id = old.baseline_id
            if baseline_id:
                row = connection.execute("SELECT payload FROM baseline_requests WHERE id = ?", (baseline_id,)).fetchone()
                if row:
                    baseline = BaselineRequest.model_validate_json(row[0])
                    baseline = baseline.model_copy(update={
                        "endpoint_id": template.id, "route_template": template.route_template,
                    })
                    baseline = BaselineRequest.model_validate_json(baseline.model_dump_json())
                    baseline_id = baseline.id
                    connection.execute("INSERT OR IGNORE INTO baseline_requests VALUES (?, ?, ?)",
                                       (baseline.id, baseline.task_id, baseline.model_dump_json()))
            rebound = old.model_copy(update={"url": template.url, "route_template": template.route_template,
                                             "baseline_id": baseline_id})
            linked_provenance = []
            for row in list(connection.execute("SELECT id, payload FROM endpoint_observations WHERE endpoint_id = ?", (old.id,))):
                observation = EndpointObservation.model_validate_json(row[1]).model_copy(update={
                    "endpoint_id": template.id, "route_template": template.route_template,
                })
                proofs = tuple(item.model_copy(update={"observation_id": observation.id})
                               for item in template.provenance if item.request_id and item.evidence_id)
                observation = observation.model_copy(update={"provenance": (*observation.provenance, *proofs)})
                observation = EndpointObservation.model_validate_json(observation.model_dump_json())
                linked_provenance.extend(proofs)
                connection.execute("UPDATE endpoint_observations SET endpoint_id = ?, payload = ? WHERE id = ?",
                                   (template.id, observation.model_dump_json(), row[0]))
            rebound = rebound.model_copy(update={"provenance": (*rebound.provenance, *linked_provenance)})
            merged = merge_endpoints(template, rebound)
            for row in list(connection.execute("SELECT id, payload FROM discovery_sources WHERE task_id = ?", (old.task_id,))):
                source = DiscoverySource.model_validate_json(row[1])
                if source.endpoint_id == old.id:
                    source = source.model_copy(update={"route_template": template.route_template})
                    connection.execute("UPDATE discovery_sources SET payload = ? WHERE id = ?",
                                       (source.model_dump_json(), row[0]))
            connection.execute("UPDATE web_endpoints SET payload = ? WHERE id = ?", (merged.model_dump_json(), template.id))
            connection.execute("DELETE FROM web_endpoints WHERE id = ?", (old.id,))

    def replace_endpoint(self, endpoint: WebEndpointEntry) -> None:
        """Refresh derived readiness after verifying scope/evidence, including revocation."""
        endpoint = WebEndpointEntry.model_validate_json(endpoint.model_dump_json())
        with self._connect() as connection:
            connection.execute("UPDATE web_endpoints SET payload = ? WHERE id = ?", (endpoint.model_dump_json(), endpoint.id))

    def save_observation(self, observation: EndpointObservation) -> EndpointObservation:
        observation = EndpointObservation.model_validate_json(observation.model_dump_json())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT payload FROM endpoint_observations WHERE id = ?", (observation.id,)).fetchone()
            if row:
                old = EndpointObservation.model_validate_json(row[0])
                provenance = {p.model_dump_json(): p for p in (*old.provenance, *observation.provenance)}
                observation = (observation if observation.request_id else old).model_copy(update={
                    "provenance": tuple(provenance[key] for key in sorted(provenance)),
                })
            connection.execute("INSERT INTO endpoint_observations VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                               (observation.id, observation.task_id, observation.endpoint_id, observation.model_dump_json()))
        return observation

    def list_observations(self, task_id: str) -> tuple[EndpointObservation, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM endpoint_observations WHERE task_id = ? ORDER BY id", (task_id,))
            return tuple(EndpointObservation.model_validate_json(row[0]) for row in rows)

    def save_source(self, source: DiscoverySource) -> None:
        source = DiscoverySource.model_validate_json(source.model_dump_json())
        with self._connect() as connection:
            connection.execute("INSERT INTO discovery_sources VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                               (source.id, source.task_id, source.model_dump_json()))

    def list_sources(self, task_id: str) -> tuple[DiscoverySource, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT payload FROM discovery_sources WHERE task_id = ? ORDER BY rowid", (task_id,))
            return tuple(DiscoverySource.model_validate_json(row[0]) for row in rows)

    def save_baseline(self, baseline: BaselineRequest) -> None:
        with self._connect() as connection:
            connection.execute("INSERT OR IGNORE INTO baseline_requests VALUES (?, ?, ?)",
                               (baseline.id, baseline.task_id, baseline.model_dump_json()))

    def get_baseline(self, baseline_id: str) -> BaselineRequest | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM baseline_requests WHERE id = ?", (baseline_id,)).fetchone()
        return BaselineRequest.model_validate_json(row[0]) if row else None

    def save_coverage(self, coverage: ReconCoverage) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO recon_coverage VALUES (?, ?) ON CONFLICT(task_id) DO UPDATE SET payload=excluded.payload",
                               (coverage.task_id, coverage.model_dump_json()))

    def get_coverage(self, task_id: str) -> ReconCoverage | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM recon_coverage WHERE task_id = ?", (task_id,)).fetchone()
        return ReconCoverage.model_validate_json(row[0]) if row else None


class EvidenceStore:
    def __init__(self, directory: Path | str, repository: ReconRepository) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.repository = repository

    def save(self, request: CapabilityRequest, content: bytes) -> EvidenceArtifact:
        if len(content) > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence exceeds Day-1 size limit")
        artifact_id = str(uuid4())
        relative_path = f"{artifact_id}.bin"
        path = self.directory / relative_path
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            artifact = EvidenceArtifact(
                id=artifact_id,
                run_id=self.repository.get_task(request.task_id).run_id,
                task_id=request.task_id,
                request_id=request.id,
                tool_run_id=request.id,
                kind="http_exchange" if request.capability in {Capability.HTTP_FETCH, Capability.BROWSER_REQUEST} else "tool_output",
                content_type="application/json" if request.capability in {Capability.HTTP_FETCH, Capability.BROWSER_REQUEST} else "application/octet-stream",
                metadata={"capability": request.capability.value,
                          **({"parent_request_id": request.parent_request_id} if request.parent_request_id else {})},
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                relative_path=relative_path,
                created_at=datetime.now(UTC),
            )
            self.repository.save_evidence(artifact)
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return artifact

    def read(self, artifact_id: str) -> bytes | None:
        artifact = self.repository.get_evidence(artifact_id)
        if artifact is None:
            return None
        # The path is derived from the identifier, never from caller input or stored path.
        if artifact.relative_path != f"{artifact.id}.bin":
            raise ValueError("invalid evidence path")
        content = (self.directory / artifact.relative_path).read_bytes()
        if len(content) != artifact.size_bytes or hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise ValueError("evidence integrity check failed")
        return content
