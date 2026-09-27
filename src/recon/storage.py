"""Small SQLite repositories and content-addressed Recon evidence metadata."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from src.recon.endpoints import merge_endpoints
from src.recon.models import (
    CapabilityRequest,
    EvidenceArtifact,
    PolicyDecision,
    ReconPlan,
    ReconResult,
    ReconTask,
    ToolResult,
)
from src.recon.web_models import BaselineRequest, DiscoverySource, ReconCoverage, WebEndpointEntry

MAX_EVIDENCE_BYTES = 262_144


class ReconRepository:
    def __init__(self, database_path: Path | str) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS recon_tasks (
                    id TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_results (
                    request_id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
                    status TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS execution_claims (
                    request_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    claimed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS policy_decisions (
                    request_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_artifacts (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL,
                    request_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recon_results (
                    task_id TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recon_plans (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS web_endpoints (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS discovery_sources (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS baseline_requests (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recon_coverage (
                    task_id TEXT PRIMARY KEY, payload TEXT NOT NULL
                );
            """)

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
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO execution_claims (request_id, task_id, claimed_at) VALUES (?, ?, ?)",
                (request.id, request.task_id, datetime.now(UTC).isoformat()),
            )
        return cursor.rowcount == 1

    def save_policy_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO policy_decisions (request_id, payload) VALUES (?, ?)",
                (decision.request_id, decision.model_dump_json()),
            )

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
                task_id=request.task_id,
                request_id=request.id,
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
