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
    DNS_RESOLVE = "dns_resolve"
    HTTP_PROBE = "http_probe"
    NMAP_SCAN = "nmap_scan"
    WHATWEB = "whatweb"
    HTTP_FETCH = "http_fetch"
    BROWSER_EXPLORE = "browser_explore"
    BROWSER_REQUEST = "browser_request"
    CONTENT_DISCOVERY = "content_discovery"
    PASSIVE_SUBDOMAIN_ENUM = "passive_subdomain_enum"
    PASSIVE_INFRA_ENUM = "passive_infra_enum"
    HISTORICAL_URL_DISCOVERY = "historical_url_discovery"
    WHOIS_RDAP_LOOKUP = "whois_rdap_lookup"
    WEB_CRAWL = "web_crawl"
    VHOST_DISCOVERY = "vhost_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    TECHNOLOGY_SCAN = "technology_scan"
    GRAPHQL_DISCOVERY = "graphql_discovery"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    WSDL_DISCOVERY = "wsdl_discovery"
    EXPOSURE_DISCOVERY = "exposure_discovery"
    SOURCEMAP_ANALYZE = "sourcemap_analyze"
    EXTERNAL_ASSET_SEARCH = "external_asset_search"
    PUBLIC_CODE_SEARCH = "public_code_search"
    SEARCH_ENGINE_OSINT = "search_engine_osint"


class CapabilityAvailability(StrictModel):
    capability: Capability
    status: Literal["AVAILABLE", "MISSING_BINARY", "MISSING_CREDENTIAL",
                    "POLICY_DISABLED", "UNSUPPORTED_TARGET_KIND", "RUNTIME_ERROR"]
    provider: str | None = None
    tool_version: str | None = None
    reason: str = ""


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
    multi_origin: bool = False

    @model_serializer(mode="wrap")
    def compatible_payload(self, handler):
        payload = handler(self)
        if self.web_origin is None:
            payload.pop("web_origin", None)
        if not self.multi_origin:
            payload.pop("multi_origin", None)
        return payload

    @model_validator(mode="after")
    def pinned_origin(self):
        if self.web_origin and (self.allowed_ips != (self.web_origin.pinned_ip,)
                                or (self.web_origin.port not in self.allowed_ports if self.multi_origin
                                    else self.allowed_ports != (self.web_origin.port,))):
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
    wordlist_id: str = Field(min_length=1, max_length=128)

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
        if load_wordlist(value).category in {"vhost", "parameter"}:
            raise ValueError("wordlist belongs to a different capability")
        return value


class ExposureDiscoveryParams(ContentDiscoveryParams):
    kind: Literal["exposure_discovery"] = "exposure_discovery"
    wordlist_id: Literal["backup-small-v1", "backup-small-v2", "scm-small-v1"]


class BoundedWebToolParams(StrictModel):
    port: int = Field(ge=1, le=65535, strict=True)
    scheme: Literal["http", "https"] = "http"
    path: str = Field(default="/", max_length=2048)
    max_requests: int = Field(default=16, ge=1, le=64, strict=True)
    timeout_seconds: int = Field(default=20, ge=1, le=30, strict=True)
    max_body_bytes: int = Field(default=65536, ge=1, le=65536, strict=True)

    @field_validator("path")
    @classmethod
    def concrete_path(cls, value):
        validate_path(value)
        if any(char in value for char in "{}"):
            raise ValueError("concrete tool path required")
        return value


class WebCrawlParams(BoundedWebToolParams):
    kind: Literal["web_crawl"] = "web_crawl"
    max_depth: int = Field(default=1, ge=1, le=2, strict=True)
    max_results: int = Field(default=32, ge=1, le=128, strict=True)


class VhostDiscoveryParams(BoundedWebToolParams):
    kind: Literal["vhost_discovery"] = "vhost_discovery"
    root_domain: str
    path: Literal["/"] = "/"
    wordlist_id: Literal["vhosts-small-v1"] = "vhosts-small-v1"

    _root = field_validator("root_domain")(canonical_host)


class ParameterDiscoveryParams(BoundedWebToolParams):
    kind: Literal["parameter_discovery"] = "parameter_discovery"
    baseline_evidence_ref: str = Field(min_length=1)
    wordlist_id: Literal["parameters-small-v1"] = "parameters-small-v1"


class TechnologyScanParams(BoundedWebToolParams):
    kind: Literal["technology_scan"] = "technology_scan"
    path: Literal["/"] = "/"
    profile: Literal["technology-v1"] = "technology-v1"
    max_requests: int = Field(default=4, ge=1, le=4, strict=True)


class GraphqlDiscoveryParams(StrictModel):
    kind: Literal["graphql_discovery"] = "graphql_discovery"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: Literal["/graphql", "/gql", "/graphiql", "/v1/graphql"]
    timeout_seconds: float = Field(default=5, gt=0, le=10)
    max_body_bytes: int = Field(default=8192, ge=1, le=16384)


class GraphqlIntrospectionParams(StrictModel):
    kind: Literal["graphql_introspection"] = "graphql_introspection"
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    path: Literal["/graphql", "/gql", "/v1/graphql"]
    discovery_evidence_ref: str = Field(min_length=1)
    timeout_seconds: float = Field(default=5, gt=0, le=10)
    max_body_bytes: int = Field(default=32768, ge=1, le=65536)


class DnsResolveParams(StrictModel):
    kind: Literal["dns_resolve"] = "dns_resolve"
    host: str
    max_answers: int = Field(default=8, ge=1, le=8)
    timeout_seconds: float = Field(default=8, gt=0, le=8)

    _host = field_validator("host")(canonical_host)


Parameters = (HttpProbeParams | NmapScanParams | WhatWebParams | HttpFetchParams | BrowserExploreParams
              | BrowserRequestParams | ContentDiscoveryParams | ExposureDiscoveryParams
              | GraphqlDiscoveryParams | GraphqlIntrospectionParams | DnsResolveParams
              | WebCrawlParams | VhostDiscoveryParams | ParameterDiscoveryParams | TechnologyScanParams)


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


class ProviderParams(StrictModel):
    """Fixed query profiles; callers cannot supply provider URLs or query strings."""

    profile: Literal["root_domain", "public_code", "PUBLIC_DOCUMENTS", "ADMIN_LOGIN",
                     "DIRECTORY_INDEX", "CONFIG_FILES", "BACKUP_FILES"]
    max_results: int = Field(default=25, ge=1, le=100)
    timeout_seconds: float = Field(default=10, gt=0, le=20)


class ProviderCapabilityRequest(StrictModel):
    request_kind: Literal["provider"] = "provider"
    id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    run_id: str | None = None
    scope_version: str | None = None
    action_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    root_domain: str
    capability: Literal[Capability.EXTERNAL_ASSET_SEARCH, Capability.PUBLIC_CODE_SEARCH,
                        Capability.SEARCH_ENGINE_OSINT, Capability.WHOIS_RDAP_LOOKUP]
    provider: Literal["shodan", "censys", "fofa", "github", "gitlab", "brave", "rdap"]
    parameters: ProviderParams
    budget_context: BudgetContext | None = None
    parent_request_id: None = None

    _root = field_validator("root_domain")(canonical_host)

    @model_validator(mode="after")
    def matching_provider(self):
        allowed = {
            Capability.EXTERNAL_ASSET_SEARCH: {"shodan", "censys", "fofa"},
            Capability.PUBLIC_CODE_SEARCH: {"github", "gitlab"},
            Capability.SEARCH_ENGINE_OSINT: {"brave"},
            Capability.WHOIS_RDAP_LOOKUP: {"rdap"},
        }
        if self.provider not in allowed[self.capability]:
            raise ValueError("provider does not implement capability")
        profiles = {Capability.EXTERNAL_ASSET_SEARCH: {"root_domain"},
                    Capability.PUBLIC_CODE_SEARCH: {"public_code"},
                    Capability.SEARCH_ENGINE_OSINT: {"PUBLIC_DOCUMENTS", "ADMIN_LOGIN",
                                                      "DIRECTORY_INDEX", "CONFIG_FILES", "BACKUP_FILES"},
                    Capability.WHOIS_RDAP_LOOKUP: {"root_domain"}}[self.capability]
        if self.parameters.profile not in profiles:
            raise ValueError("profile does not match capability")
        return self


class LocalOsintParams(StrictModel):
    """A bounded local passive CLI invocation; no caller-supplied flags or URLs."""

    profile: Literal["root_domain"] = "root_domain"
    max_results: int = Field(default=128, ge=1, le=512)
    timeout_seconds: float = Field(default=20, gt=0, le=60)


class LocalOsintCapabilityRequest(StrictModel):
    request_kind: Literal["local_osint"] = "local_osint"
    id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    run_id: str | None = None
    scope_version: str | None = None
    action_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    root_domain: str
    capability: Literal[Capability.PASSIVE_SUBDOMAIN_ENUM, Capability.PASSIVE_INFRA_ENUM,
                        Capability.HISTORICAL_URL_DISCOVERY]
    tool: Literal["subfinder", "amass", "gau"]
    parameters: LocalOsintParams = Field(default_factory=LocalOsintParams)
    budget_context: BudgetContext | None = None
    parent_request_id: None = None

    _root = field_validator("root_domain")(canonical_host)

    @model_validator(mode="after")
    def matching_tool(self):
        tools = {
            Capability.PASSIVE_SUBDOMAIN_ENUM: {"subfinder", "amass"},
            Capability.PASSIVE_INFRA_ENUM: {"amass"},
            Capability.HISTORICAL_URL_DISCOVERY: {"gau"},
        }
        if self.tool not in tools[self.capability]:
            raise ValueError("local tool does not implement capability")
        return self


class EvidenceParams(StrictModel):
    profile: Literal["sourcemap_metadata", "wsdl_metadata"]
    max_input_bytes: int = Field(default=131072, ge=1, le=262144)
    max_items: int = Field(default=64, ge=1, le=256)


class EvidenceCapabilityRequest(StrictModel):
    request_kind: Literal["evidence"] = "evidence"
    id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    run_id: str | None = None
    scope_version: str | None = None
    action_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    capability: Literal[Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY]
    evidence_ref: str = Field(min_length=1)
    parameters: EvidenceParams
    budget_context: BudgetContext | None = None
    parent_request_id: None = None

    @model_validator(mode="after")
    def matching_profile(self):
        profiles = {Capability.SOURCEMAP_ANALYZE: "sourcemap_metadata",
                    Capability.WSDL_DISCOVERY: "wsdl_metadata"}
        if self.parameters.profile != profiles[self.capability]:
            raise ValueError("profile does not match capability")
        return self


ReconExecutionRequest = (CapabilityRequest | ProviderCapabilityRequest | LocalOsintCapabilityRequest
                         | EvidenceCapabilityRequest)


def parse_execution_request(payload: str) -> ReconExecutionRequest:
    import json

    data = json.loads(payload)
    kind = data.get("request_kind", "target")
    models = {"target": CapabilityRequest, "provider": ProviderCapabilityRequest,
              "local_osint": LocalOsintCapabilityRequest,
              "evidence": EvidenceCapabilityRequest}
    if kind not in models:
        raise ValueError("unknown request kind")
    return models[kind].model_validate(data)


def parse_target_request(payload: str) -> CapabilityRequest | None:
    request = parse_execution_request(payload)
    return request if isinstance(request, CapabilityRequest) else None


def request_target_ip(request: ReconExecutionRequest) -> str | None:
    return request.target_ip if isinstance(request, CapabilityRequest) else None


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


class ReconObservation(StrictModel):
    kind: Literal["HOST", "IP", "URL", "PORT", "PROTOCOL", "EXPOSURE", "CODE_REFERENCE",
                  "SEARCH_REFERENCE", "TECHNOLOGY", "METADATA"]
    value: str = Field(min_length=1, max_length=2048)
    source: Capability
    provider: str | None = None
    evidence_id: str = ""


class ToolResult(StrictModel):
    request_id: str
    task_id: str
    capability: Capability
    target_ip: str | None = None
    status: Literal["success", "error", "denied", "cancelled"]
    parent_request_id: str | None = None
    message: str = ""
    evidence_id: str | None = None
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()
    http_response: HttpResponseMetadata | None = None
    observations: tuple[ReconObservation, ...] = ()
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
    coverage_outcome: Literal["COMPLETE", "PARTIAL", "LIMITED"] | None = None
