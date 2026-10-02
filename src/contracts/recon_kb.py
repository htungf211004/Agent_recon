"""Strict, separate contracts for operator-maintained Recon knowledge snapshots."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.contracts.execution import Risk


class KBModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageClass(StrEnum):
    VECTOR_RAG = "VECTOR_RAG"
    STRUCTURED_LOOKUP = "STRUCTURED_LOOKUP"
    RUNNER_DATA = "RUNNER_DATA"


class IngestionStatus(StrEnum):
    STAGED = "STAGED"
    READY = "READY"
    QUARANTINED = "QUARANTINED"
    PROMOTED = "PROMOTED"
    FAILED = "FAILED"


class Provenance(KBModel):
    source_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    source_url: str = Field(min_length=1)
    source_version: str | None = None
    source_commit: str | None = Field(default=None, pattern=r"^[a-f0-9]{40,64}$")
    source_record: str = Field(min_length=1)
    retrieved_at: datetime
    snapshot_id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")

    @model_validator(mode="after")
    def traceable(self):
        if not (self.source_version or self.source_commit):
            raise ValueError("source version or commit is required")
        if self.retrieved_at.tzinfo is None:
            raise ValueError("retrieved_at must have timezone")
        parts = urlsplit(self.source_url)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError("HTTPS provenance required")
        return self


class ArtifactRejection(KBModel):
    file: str
    reason: str
    first_failing_rule: str


class ValidationAttempt(KBModel):
    status: str
    errors: tuple[str, ...]


class SourceReference(KBModel):
    source_id: str
    source_record: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class SourceManifest(Provenance):
    license: str | None = None
    license_status: Literal["DECLARED", "REVIEW_REQUIRED", "APPROVED"]
    adapter_version: str
    storage_class: StorageClass
    namespace: str
    record_count: int = Field(ge=0)
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_sha256: dict[str, str]
    normalized_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    status: IngestionStatus
    sync_watermark: str | None = None
    base_snapshot_id: str | None = None
    reports: tuple[str, ...] = ()
    coverage_status: Literal["COMPLETE", "PARTIAL", "NOT_APPLICABLE_FOR_LIVE_SYNC"] = "COMPLETE"
    expected_artifacts: tuple[str, ...] = ()
    accepted_artifacts: tuple[str, ...] = ()
    rejected_artifacts: tuple[ArtifactRejection, ...] = ()
    final_validation_errors: tuple[str, ...] = ()
    final_warnings: tuple[str, ...] = ()
    attempt_history: tuple[ValidationAttempt, ...] = ()

    @model_validator(mode="after")
    def final_state(self):
        if self.status in {IngestionStatus.READY, IngestionStatus.PROMOTED} and self.final_validation_errors:
            raise ValueError("READY/PROMOTED cannot contain final validation errors")
        return self

    @field_validator("artifact_sha256")
    @classmethod
    def artifact_hashes(cls, value):
        import re

        if not value or any(not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in value.values()):
            raise ValueError("all raw artifacts require SHA-256")
        return value


class ReconContent(KBModel):
    objective: str = Field(min_length=1)
    applies_when: tuple[str, ...] = Field(min_length=1)
    safe_actions: tuple[str, ...] = Field(min_length=1)
    expected_observations: tuple[str, ...] = Field(min_length=1)
    evidence_required: tuple[str, ...] = Field(min_length=1)
    follow_up: tuple[str, ...] = ()
    completion_rule: str = Field(min_length=1)


class VectorKnowledgeRecord(Provenance):
    storage_class: Literal[StorageClass.VECTOR_RAG] = StorageClass.VECTOR_RAG
    knowledge_id: str
    namespace: Literal["attack_surface_methodology", "technique_reference", "tool_capability_reference"]
    title: str = Field(min_length=1, max_length=160)
    phase: Literal["attack_surface"] = "attack_surface"
    category: str
    asset_types: tuple[str, ...]
    technologies: tuple[str, ...] = ()
    capabilities: tuple[str, ...]
    risk: Literal[Risk.R0, Risk.R1, Risk.R2]
    delivery: Literal["AUTOMATIC", "MANUAL_HITL", "METHODOLOGY_ONLY"] = "AUTOMATIC"
    source_refs: tuple[SourceReference, ...] = ()
    requires: tuple[str, ...]
    produces: tuple[str, ...]
    active_testing: Literal[False] = False
    api_related: bool = False
    content: ReconContent

    @model_validator(mode="after")
    def manual_risk(self):
        if not self.produces:
            raise ValueError("methodology requires inventory output")
        return self


class LookupRecord(Provenance):
    storage_class: Literal[StorageClass.STRUCTURED_LOOKUP] = StorageClass.STRUCTURED_LOOKUP
    record_id: str
    dataset: str
    lookup_keys: dict
    value: dict


class RunnerConstraints(KBModel):
    recursive: Literal[False] = False
    agent_can_override_path: Literal[False] = False
    agent_can_supply_payload: Literal[False] = False
    automatic_execution: Literal[False] = False
    api_related: bool = False
    technology_required: str | None = None
    evidence_required: Literal[True] = True
    max_line_length: Literal[512] = 512


class RunnerDataManifest(Provenance):
    storage_class: Literal[StorageClass.RUNNER_DATA] = StorageClass.RUNNER_DATA
    runner_data_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$")
    capability: Literal["CONTENT_DISCOVERY"] = "CONTENT_DISCOVERY"
    tool: Literal["ffuf"] = "ffuf"
    local_path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    line_count: int = Field(ge=1)
    risk: Literal[Risk.R1] = Risk.R1
    constraints: RunnerConstraints


RECORD_MODELS = {
    StorageClass.VECTOR_RAG: VectorKnowledgeRecord,
    StorageClass.STRUCTURED_LOOKUP: LookupRecord,
    StorageClass.RUNNER_DATA: RunnerDataManifest,
}
