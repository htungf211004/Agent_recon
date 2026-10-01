"""Durable execution lifecycle and trusted runtime limits."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_serializer


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
    max_external_queries: int = Field(default=12, ge=0, le=64)
    max_external_results: int = Field(default=300, ge=0, le=1000)
    max_offline_bytes: int = Field(default=262144, ge=0, le=1048576)
    max_tool_processes: int = Field(default=32, ge=0, le=256)
    max_subdomains: int = Field(default=128, ge=0, le=2048)
    max_historical_urls: int = Field(default=256, ge=0, le=4096)
    max_crawl_urls: int = Field(default=128, ge=0, le=2048)
    max_parameter_attempts: int = Field(default=32, ge=0, le=256)
    max_vhost_candidates: int = Field(default=64, ge=0, le=512)

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        payload = handler(self)
        for key, default in (("max_external_queries", 12), ("max_external_results", 300),
                             ("max_offline_bytes", 262144), ("max_tool_processes", 32),
                             ("max_subdomains", 128), ("max_historical_urls", 256),
                             ("max_crawl_urls", 128), ("max_parameter_attempts", 32),
                             ("max_vhost_candidates", 64)):
            if payload[key] == default:
                del payload[key]
        return payload


class BudgetContext(ExecutionModel):
    task_id: str
