"""Durable execution lifecycle and trusted runtime limits."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ExecutionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolRunState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class ToolRun(ExecutionModel):
    request_id: str
    task_id: str
    state: ToolRunState
    owner_token: str
    request_fingerprint: str
    request_payload: str | None
    lease_expires_at: datetime | None
    attempt: int = Field(default=1, ge=1)
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    message: str = ""
    parent_request_id: str | None = None
    external_dispatched_at: datetime | None = None


class ExecutionBudget(ExecutionModel):
    max_requests: int = Field(default=128, ge=1, le=1024)
    max_requests_per_second: int = Field(default=100, ge=1, le=1000)
    max_timeout_seconds: float = Field(default=60, gt=0, le=60)
    max_body_bytes: int = Field(default=131072, ge=1, le=131072)


class BudgetContext(ExecutionModel):
    task_id: str
