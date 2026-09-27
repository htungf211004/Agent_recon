"""Strict data contracts exchanged by Recon, policy, gateway, and storage."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Capability(StrEnum):
    HTTP_PROBE = "http_probe"
    NMAP_SCAN = "nmap_scan"
    WHATWEB = "whatweb"


class Scope(StrictModel):
    allowed_ips: tuple[str, ...] = Field(min_length=1)
    allowed_ports: tuple[int, ...] = Field(min_length=1)
    capabilities: tuple[Capability, ...] = Field(min_length=1)

    @field_validator("allowed_ips")
    @classmethod
    def valid_ips(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(str(ipaddress.ip_address(value)) for value in values)

    @field_validator("allowed_ports")
    @classmethod
    def valid_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("ports must be between 1 and 65535")
        return values


class ReconTask(StrictModel):
    id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    scope: Scope
    expires_at: datetime


class HttpProbeParams(StrictModel):
    kind: Literal["http_probe"] = "http_probe"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"


class NmapScanParams(StrictModel):
    kind: Literal["nmap_scan"] = "nmap_scan"
    ports: tuple[int, ...] = Field(min_length=1, max_length=32)

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("ports must be between 1 and 65535")
        return values


class WhatWebParams(StrictModel):
    kind: Literal["whatweb"] = "whatweb"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"


Parameters = HttpProbeParams | NmapScanParams | WhatWebParams


class CapabilityRequest(StrictModel):
    id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    capability: Capability
    target_ip: str
    parameters: Parameters = Field(discriminator="kind")

    @field_validator("target_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def matching_parameters(self) -> CapabilityRequest:
        if self.capability.value != self.parameters.kind:
            raise ValueError("parameters do not match capability")
        return self


class ReconAction(StrictModel):
    id: str = Field(min_length=1)
    request: CapabilityRequest


class ReconPlan(StrictModel):
    task_id: str = Field(min_length=1)
    actions: tuple[ReconAction, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def same_task(self) -> ReconPlan:
        if any(action.request.task_id != self.task_id for action in self.actions):
            raise ValueError("all actions must belong to plan task")
        request_ids = [action.request.id for action in self.actions]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("request ids must be unique within a plan")
        return self


class PolicyDecision(StrictModel):
    request_id: str
    allowed: bool
    reason: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceArtifact(StrictModel):
    id: str
    task_id: str
    request_id: str
    sha256: str
    size_bytes: int
    relative_path: str
    created_at: datetime


class AttackSurfaceEntry(StrictModel):
    target_ip: str
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    service: str
    version: str = ""
    evidence_id: str = ""


class TechnologyObservation(StrictModel):
    target_ip: str
    name: str
    version: str = ""
    source: Capability
    evidence_id: str = ""


class ToolResult(StrictModel):
    request_id: str
    task_id: str
    capability: Capability
    target_ip: str
    status: Literal["success", "error", "denied"]
    message: str = ""
    evidence_id: str | None = None
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReconResult(StrictModel):
    task_id: str
    run_id: str
    tool_results: tuple[ToolResult, ...]
    attack_surface: tuple[AttackSurfaceEntry, ...]
    technologies: tuple[TechnologyObservation, ...]
    evidence_ids: tuple[str, ...]
