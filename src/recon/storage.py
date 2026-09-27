"""Small SQLite repositories and content-addressed Recon evidence metadata."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from src.recon.models import CapabilityRequest, EvidenceArtifact, PolicyDecision, ReconResult, ReconTask, ToolResult

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
                "INSERT INTO recon_results (task_id, payload) VALUES (?, ?)",
                (result.task_id, result.model_dump_json()),
            )

    def get_recon_result(self, task_id: str) -> ReconResult | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM recon_results WHERE task_id = ?", (task_id,)).fetchone()
        return ReconResult.model_validate_json(row[0]) if row else None


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
