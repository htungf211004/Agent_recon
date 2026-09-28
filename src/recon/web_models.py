"""Persisted endpoint-discovery contracts; candidates never contain executable commands."""

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.contracts.attack_surface import EndpointStatus as EndpointLifecycle
from src.contracts.attack_surface import Parameter as EndpointParameter
from src.recon.urls import canonical_url, route_url


def stable_id(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts, separators=(",", ":")).encode()).hexdigest()


class WebModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DiscoveryKind(StrEnum):
    HTML = "html"
    ROBOTS = "robots"
    SITEMAP = "sitemap"
    SITEMAP_INDEX = "sitemap_index"
    OPENAPI = "openapi"
    JAVASCRIPT = "javascript"
    SEED = "seed"


class SourceStatus(StrEnum):
    PENDING = "PENDING"
    PARSED = "PARSED"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    LIMITED = "LIMITED"


class EndpointProvenance(WebModel):
    source_id: str = Field(min_length=1)
    kind: DiscoveryKind
    relation: str = Field(min_length=1, max_length=64)
    evidence_id: str | None = None
    request_id: str | None = None
    observation_id: str | None = None


HttpMethod = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]


class WebEndpointEntry(WebModel):
    task_id: str = Field(min_length=1)
    url: str
    method: HttpMethod = "GET"
    parameters: tuple[EndpointParameter, ...] = ()
    provenance: tuple[EndpointProvenance, ...] = ()
    lifecycle: EndpointLifecycle = EndpointLifecycle.DISCOVERED
    evidence_ids: tuple[str, ...] = ()
    baseline_id: str | None = None
    # Forms and unresolved API operations are inventory, not automatic submissions.
    requires_manual_input: bool = False
    in_scope: bool = False
    baseline_verified: bool = False
    baseline_url: str | None = None
    is_testable: bool = True

    _url = field_validator("url")(route_url)

    @property
    def id(self) -> str:
        return stable_id(self.task_id, self.method, route_url(self.url))

    @property
    def canonical_path(self) -> str:
        return urlsplit(self.url).path

    @model_validator(mode="after")
    def consistent_lifecycle(self):
        keys = [(p.location, p.name) for p in self.parameters]
        if len(keys) != len(set(keys)):
            raise ValueError("endpoint parameters must be unique by location and name")
        if self.lifecycle != EndpointLifecycle.DISCOVERED and not self.evidence_ids:
            raise ValueError("observed endpoints require evidence")
        if self.lifecycle in {EndpointLifecycle.BASELINED, EndpointLifecycle.FUZZ_READY} and not self.baseline_id:
            raise ValueError("baselined endpoints require a baseline")
        if self.lifecycle in {EndpointLifecycle.BASELINED, EndpointLifecycle.FUZZ_READY} and self.method not in {"GET", "HEAD"}:
            raise ValueError("only read-only methods can be baselined")
        if self.lifecycle == EndpointLifecycle.FUZZ_READY and (self.method not in {"GET", "HEAD"} or self.requires_manual_input):
            raise ValueError("endpoint is not eligible for FUZZ_READY")
        if self.lifecycle == EndpointLifecycle.FUZZ_READY and not (self.in_scope and self.baseline_verified and self.is_testable):
            raise ValueError("FUZZ_READY requires scope, verified baseline and testability")
        return self


class DiscoverySource(WebModel):
    task_id: str = Field(min_length=1)
    url: str
    method: Literal["GET", "HEAD"] = "GET"
    kind: DiscoveryKind = DiscoveryKind.SEED
    depth: int = Field(default=0, ge=0, le=6)
    status: SourceStatus = SourceStatus.PENDING
    request_id: str | None = None
    evidence_id: str | None = None
    candidate_count: int = Field(default=0, ge=0)
    message: str = ""

    _url = field_validator("url")(canonical_url)

    @property
    def id(self) -> str:
        return stable_id(self.task_id, self.method, self.url)

    @property
    def endpoint_id(self) -> str:
        return stable_id(self.task_id, self.method, route_url(self.url))

    @model_validator(mode="after")
    def completed_source_has_evidence(self):
        if self.status in {SourceStatus.PARSED, SourceStatus.UNAVAILABLE} and not (self.request_id and self.evidence_id):
            raise ValueError("completed sources require a request and evidence")
        return self


class HttpResponseMetadata(WebModel):
    status_code: int = Field(ge=100, le=599)
    content_type: str = Field(default="", max_length=512)
    body_size: int = Field(ge=0, le=131072)
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    truncated: bool = False


class BaselineRequest(WebModel):
    task_id: str = Field(min_length=1)
    endpoint_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    observation_id: str = Field(min_length=1)
    url: str
    method: Literal["GET", "HEAD"]
    evidence_id: str = Field(min_length=1)
    response: HttpResponseMetadata
    observed_at: datetime

    _url = field_validator("url")(canonical_url)

    @property
    def id(self) -> str:
        return stable_id(self.endpoint_id, self.request_id)

    @model_validator(mode="after")
    def complete_success(self):
        if not 200 <= self.response.status_code < 300 or self.response.truncated:
            raise ValueError("baseline requires a complete 2xx response")
        if self.observed_at.tzinfo is None:
            raise ValueError("baseline timestamp requires a timezone")
        if self.endpoint_id != stable_id(self.task_id, self.method, route_url(self.url)):
            raise ValueError("baseline endpoint identity mismatch")
        if self.observation_id != stable_id(self.task_id, self.method, self.url):
            raise ValueError("baseline observation identity mismatch")
        return self


class EndpointObservation(WebModel):
    task_id: str
    endpoint_id: str
    url: str
    method: HttpMethod = "GET"
    provenance: tuple[EndpointProvenance, ...] = ()
    request_id: str | None = None
    evidence_id: str | None = None
    response: HttpResponseMetadata | None = None
    observed_at: datetime | None = None
    evidence_verified: bool = False

    _url = field_validator("url")(canonical_url)

    @property
    def id(self) -> str:
        return stable_id(self.task_id, self.method, self.url)

    @model_validator(mode="after")
    def identity_and_evidence(self):
        if self.endpoint_id != stable_id(self.task_id, self.method, route_url(self.url)):
            raise ValueError("observation does not belong to route")
        if self.evidence_verified and not (self.request_id and self.evidence_id and self.response):
            raise ValueError("verified observation requires response and evidence")
        return self


class DiscoveryLimits(WebModel):
    max_rounds: int = Field(default=8, ge=1, le=20)
    max_requests: int = Field(default=64, ge=1, le=128)
    max_sources: int = Field(default=128, ge=1, le=256)
    max_endpoints: int = Field(default=256, ge=1, le=1024)
    max_depth: int = Field(default=3, ge=0, le=5)


class ReconCoverage(WebModel):
    task_id: str
    rounds: int = Field(default=0, ge=0)
    requests: int = Field(default=0, ge=0)
    runtime_attempts: int = Field(default=0, ge=0)
    sources: int = Field(default=0, ge=0)
    source_statuses: dict[SourceStatus, int] = Field(default_factory=dict)
    endpoints: int = Field(default=0, ge=0)
    route_count: int = Field(default=0, ge=0)
    observation_count: int = Field(default=0, ge=0)
    source_count: int = Field(default=0, ge=0)
    baseline_count: int = Field(default=0, ge=0)
    fuzz_ready_count: int = Field(default=0, ge=0)
    lifecycle_counts: dict[EndpointLifecycle, int] = Field(default_factory=dict)
    converged: bool = False
    complete: bool = False
    stop_reason: Literal["exhausted", "round_limit", "request_limit", "source_limit", "endpoint_limit", "depth_limit", "parser_limit"] = "exhausted"

    @model_validator(mode="after")
    def consistent_counts(self):
        if sum(self.source_statuses.values()) != self.sources or sum(self.lifecycle_counts.values()) != self.endpoints:
            raise ValueError("coverage counts do not match inventory")
        if any(value < 0 for value in (*self.source_statuses.values(), *self.lifecycle_counts.values())):
            raise ValueError("coverage counts must be non-negative")
        if self.complete and not self.converged:
            raise ValueError("complete coverage requires convergence")
        return self
