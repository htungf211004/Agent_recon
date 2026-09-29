"""Strict data contracts exchanged by Recon, policy, gateway, and storage."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from src.contracts.attack_surface import AttackSurfaceInventory
from src.contracts.evidence import EvidenceManifest
from src.contracts.execution import CURRENT_RECON_POLICY_VERSION, Risk
from src.recon.execution import BudgetContext, ExecutionBudget
from src.recon.urls import canonical_host, validate_path, validate_query
from src.recon.web_models import (
    DiscoveryLimits,
    EndpointObservation,
    HttpResponseMetadata,
    ReconCoverage,
    WebEndpointEntry,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Capability(StrEnum):
    HTTP_PROBE = "http_probe"
    NMAP_SCAN = "nmap_scan"
    WHATWEB = "whatweb"
    HTTP_FETCH = "http_fetch"
    BROWSER_EXPLORE = "browser_explore"
    BROWSER_REQUEST = "browser_request"
    CONTENT_DISCOVERY = "content_discovery"


class WebOrigin(StrictModel):
    host: str
    scheme: Literal["http", "https"]
    port: int = Field(ge=1, le=65535)
    pinned_ip: str

    _host = field_validator("host")(canonical_host)

    @field_validator("pinned_ip")
    @classmethod
    def valid_pin(cls, value):
        address = ipaddress.ip_address(value)
        if "%" in value or address.is_unspecified or address.is_multicast:
            raise ValueError("a concrete unicast IP is required")
        return str(address)


class Scope(StrictModel):
    allowed_ips: tuple[str, ...] = Field(min_length=1)
    allowed_ports: tuple[int, ...] = Field(min_length=1)
    capabilities: tuple[Capability, ...] = Field(min_length=1)
    allowed_paths: tuple[str, ...] = ()
    allowed_methods: tuple[Literal["GET", "HEAD"], ...] = ("GET", "HEAD")
    web_origin: WebOrigin | None = None

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        payload = handler(self)
        if self.web_origin is None:
            payload.pop("web_origin", None)
        return payload

    @model_validator(mode="after")
    def pinned_origin(self):
        if self.web_origin and (self.allowed_ips != (self.web_origin.pinned_ip,)
                                or self.allowed_ports != (self.web_origin.port,)):
            raise ValueError("web origin requires exactly its pinned IP and port")
        return self

    @field_validator("allowed_paths")
    @classmethod
    def valid_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(validate_path(value) for value in values)

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
    scope_version: str = Field(default="1", min_length=1)
    policy_version: str = Field(default=CURRENT_RECON_POLICY_VERSION, min_length=1)
    scope: Scope
    expires_at: datetime
    discovery_limits: DiscoveryLimits = Field(default_factory=DiscoveryLimits)
    discovery_seeds: tuple[str, ...] = Field(default=(), max_length=32)
    execution_budget: ExecutionBudget = Field(default_factory=ExecutionBudget)

    @field_validator("discovery_seeds")
    @classmethod
    def valid_seeds(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            parts = urlsplit(value)
            if (parts.scheme or parts.netloc or parts.fragment or len(value) > 4096
                    or any(ord(char) <= 32 or char in "{}" for char in value)):
                raise ValueError("discovery seeds must be concrete local paths with optional query")
            validate_path(parts.path)
            validate_query(parts.query)
        return values


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


class HttpFetchParams(StrictModel):
    kind: Literal["http_fetch"] = "http_fetch"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    method: Literal["GET", "HEAD"] = "GET"
    path: str = "/"
    query: str = ""
    timeout_seconds: float = Field(default=5.0, gt=0, le=10)
    max_body_bytes: int = Field(default=131072, ge=1, le=131072)

    @field_validator("path")
    @classmethod
    def local_path(cls, value: str) -> str:
        validate_path(value)
        if any(c in value for c in "{}"):
            raise ValueError("unresolved path template")
        return value

    _query = field_validator("query")(validate_query)


class BrowserLimits(StrictModel):
    max_requests: int = Field(default=16, ge=1, le=64)
    max_runtime_seconds: float = Field(default=10.0, gt=0, le=30)
    max_response_bytes: int = Field(default=65536, ge=1, le=131072)
    max_pages: int = Field(default=1, ge=1, le=16)
    max_depth: int = Field(default=0, ge=0, le=5)
    max_total_bytes: int = Field(default=1048576, ge=1, le=8388608)

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        # Keep persisted Ver1 fingerprints replayable at the legacy defaults.
        payload = handler(self)
        for key, default in (("max_pages", 1), ("max_depth", 0), ("max_total_bytes", 1048576)):
            if payload.get(key) == default:
                del payload[key]
        return payload


class BrowserExploreParams(StrictModel):
    kind: Literal["browser_explore"] = "browser_explore"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: str = "/"
    query: str = ""
    limits: BrowserLimits = Field(default_factory=BrowserLimits)

    @field_validator("path")
    @classmethod
    def local_path(cls, value: str) -> str:
        validate_path(value)
        if any(c in value for c in "{}"):
            raise ValueError("unresolved path template")
        return value

    _query = field_validator("query")(validate_query)


class BrowserRequestParams(StrictModel):
    kind: Literal["browser_request"] = "browser_request"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    method: Literal["GET", "HEAD"] = "GET"
    path: str = "/"
    query: str = ""
    resource_type: Literal["document", "stylesheet", "image", "font", "script", "xhr", "fetch", "manifest", "other"] = "document"
    timeout_seconds: float = Field(default=10.0, gt=0, le=30)
    max_body_bytes: int = Field(default=65536, ge=1, le=131072)
    page_sequence: int = Field(default=0, ge=0, le=15)

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        payload = handler(self)
        if payload.get("page_sequence") == 0:
            del payload["page_sequence"]
        return payload

    @field_validator("path")
    @classmethod
    def local_path(cls, value: str) -> str:
        validate_path(value)
        if any(c in value for c in "{}"):
            raise ValueError("unresolved path template")
        return value

    _query = field_validator("query")(validate_query)


class ContentDiscoveryParams(StrictModel):
    kind: Literal["content_discovery"] = "content_discovery"
    port: int = Field(ge=1, le=65535, strict=True)
    scheme: Literal["http", "https"] = "http"
    path_prefix: str = Field(default="/", max_length=2048)
    wordlist_id: str = Field(min_length=1, max_length=64)

    @field_validator("path_prefix")
    @classmethod
    def prefix(cls, value):
        validate_path(value)
        if any(c in value for c in "{}%") or "FUZZ" in value:
            raise ValueError("concrete content prefix required")
        return value.rstrip("/") + "/"

    @field_validator("wordlist_id")
    @classmethod
    def trusted_wordlist(cls, value):
        from src.recon.wordlists import load_wordlist
        load_wordlist(value)
        return value


Parameters = (HttpProbeParams | NmapScanParams | WhatWebParams | HttpFetchParams | BrowserExploreParams
              | BrowserRequestParams | ContentDiscoveryParams)


class CapabilityRequest(StrictModel):
    id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    # Older callers may omit binding metadata. Gateway fills it from the stored task
    # before claiming; any supplied value is checked by PolicyService.
    run_id: str | None = None
    scope_version: str | None = None
    action_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    capability: Capability
    target_ip: str
    target_host: str | None = None
    parameters: Parameters = Field(discriminator="kind")
    budget_context: BudgetContext | None = None
    parent_request_id: str | None = Field(default=None, min_length=1)

    @field_validator("target_host")
    @classmethod
    def valid_host(cls, value):
        return canonical_host(value) if value is not None else None

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        payload = handler(self)
        if self.target_host is None:
            payload.pop("target_host", None)
        return payload

    @field_validator("target_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def matching_parameters(self) -> CapabilityRequest:
        if self.capability.value != self.parameters.kind:
            raise ValueError("parameters do not match capability")
        if (self.capability == Capability.BROWSER_REQUEST) != (self.parent_request_id is not None):
            raise ValueError("browser child request requires a parent; other capabilities cannot have one")
        if self.parent_request_id == self.id:
            raise ValueError("browser request cannot be its own parent")
        return self

    @property
    def target(self) -> str:
        return self.target_ip


class ReconAction(StrictModel):
    id: str = Field(min_length=1)
    request: CapabilityRequest


class ReconPlan(StrictModel):
    task_id: str = Field(min_length=1)
    actions: tuple[ReconAction, ...] = ()

    @property
    def id(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()

    @model_validator(mode="after")
    def same_task(self) -> ReconPlan:
        if any(action.request.task_id != self.task_id for action in self.actions):
            raise ValueError("all actions must belong to plan task")
        request_ids = [action.request.id for action in self.actions]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("request ids must be unique within a plan")
        return self


class PolicyOutcome(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyDecision(StrictModel):
    request_id: str
    action_fingerprint: str = ""
    scope_version: str = "legacy"
    allowed: bool | None = None
    outcome: PolicyOutcome | None = None
    reason: str
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    policy_version: str = CURRENT_RECON_POLICY_VERSION
    policy_fingerprint: str = ""
    risk: Risk = Risk.R0
    attempt: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def normalize_outcome(self):
        outcome = self.outcome or (PolicyOutcome.ALLOW if self.allowed else PolicyOutcome.DENY)
        allowed = outcome == PolicyOutcome.ALLOW
        if self.allowed is not None and self.allowed != allowed:
            raise ValueError("policy outcome and allowed flag disagree")
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "allowed", allowed)
        return self


class EvidenceArtifact(EvidenceManifest):
    relative_path: str


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
    status: Literal["success", "error", "denied", "cancelled"]
    parent_request_id: str | None = None
    message: str = ""
    evidence_id: str | None = None
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()
    http_response: HttpResponseMetadata | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ReconResult(StrictModel):
    task_id: str
    run_id: str
    tool_results: tuple[ToolResult, ...]
    attack_surface: tuple[AttackSurfaceEntry, ...]
    technologies: tuple[TechnologyObservation, ...]
    evidence_ids: tuple[str, ...]
    endpoints: tuple[WebEndpointEntry, ...] = ()
    coverage: ReconCoverage | None = None
    observations: tuple[EndpointObservation, ...] = ()
    attack_surface_inventory: AttackSurfaceInventory | None = None
    worker_status: Literal["RUNNING", "COMPLETED", "FAILED", "CANCELLED"] | None = None
    handoff_ready: bool = False
