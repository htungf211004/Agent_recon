"""Shared evidence manifest v1. Raw artifacts are not assumed redacted."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from src.contracts.attack_surface import ContractModel


class EvidenceManifest(ContractModel):
    id: str
    run_id: str
    task_id: str
    request_id: str
    tool_run_id: str
    kind: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)
    content_type: str
    created_at: datetime
    redaction_status: Literal["UNREVIEWED", "REDACTED", "NOT_REQUIRED"] = "UNREVIEWED"
    metadata: dict[str, str] = Field(default_factory=dict)
