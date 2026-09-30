"""Durable work state for an authorized derived web origin."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class OriginReconWorkItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str
    host: str
    resolved_ip: str
    scheme: Literal["http", "https"]
    port: int = Field(ge=1, le=65535)
    derived_from_asset: str | None = None
    scope_version: str
    status: Literal["PENDING", "RUNNING", "COMPLETE", "LIMITED", "BLOCKED"] = "PENDING"
    reason: str = ""
