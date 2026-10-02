"""Untrusted planning suggestions, independent of execution/Recon implementation."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.recon.models import (
    BrowserExploreParams,
    ContentDiscoveryParams,
    DnsResolveParams,
    EvidenceParams,
    ExposureDiscoveryParams,
    GraphqlDiscoveryParams,
    GraphqlIntrospectionParams,
    HttpFetchParams,
    HttpProbeParams,
    LocalOsintParams,
    NmapScanParams,
    ParameterDiscoveryParams,
    ProviderParams,
    TechnologyScanParams,
    VhostDiscoveryParams,
    WebCrawlParams,
    WhatWebParams,
)
from src.recon.rag.models import KnowledgeReference, ReconKnowledgeQuery


class PlanningModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProposalBase(PlanningModel):
    rationale: str = Field(min_length=1, max_length=512)
    priority: int = Field(ge=1, le=5, strict=True)
    knowledge_refs: tuple[str, ...] = Field(default=(), max_length=4)


class TargetProposal(ProposalBase):
    asset_id: str | None = Field(default=None, max_length=64)
    target_ip: str | None = Field(default=None, max_length=45)
    port: int = Field(ge=1, le=65535, strict=True)
    scheme: Literal["http", "https"] = "http"


class SafeHttpProbeProposal(TargetProposal):
    kind: Literal["safe_http_probe"] = "safe_http_probe"
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(default="/", max_length=2048)


class BrowserExploreProposal(TargetProposal):
    kind: Literal["browser_explore"] = "browser_explore"
    path: str = Field(default="/", max_length=2048)


class ContentDiscoveryProposal(TargetProposal):
    kind: Literal["content_discovery"] = "content_discovery"
    path_prefix: str = Field(max_length=2048)
    wordlist_id: str = Field(min_length=1, max_length=128)


class TargetCapabilityProposal(ProposalBase):
    kind: Literal["target_capability"] = "target_capability"
    asset_id: str | None = Field(default=None, max_length=64)
    target_ip: str | None = Field(default=None, max_length=45)
    parameters: Annotated[
        HttpProbeParams | NmapScanParams | WhatWebParams | HttpFetchParams | BrowserExploreParams
        | ContentDiscoveryParams | ExposureDiscoveryParams | GraphqlDiscoveryParams
        | GraphqlIntrospectionParams | DnsResolveParams | WebCrawlParams | VhostDiscoveryParams
        | ParameterDiscoveryParams | TechnologyScanParams, Field(discriminator="kind")]

    @model_validator(mode="after")
    def no_query_values(self):
        if getattr(self.parameters, "query", ""):
            raise ValueError("planner cannot supply query values")
        return self


class ProviderCapabilityProposal(ProposalBase):
    kind: Literal["provider_capability"] = "provider_capability"
    capability: Literal["external_asset_search", "public_code_search", "search_engine_osint", "whois_rdap_lookup"]
    provider: Literal["shodan", "censys", "fofa", "github", "gitlab", "brave", "rdap"]
    parameters: ProviderParams


class LocalOsintCapabilityProposal(ProposalBase):
    kind: Literal["local_osint_capability"] = "local_osint_capability"
    capability: Literal["passive_subdomain_enum", "passive_infra_enum", "historical_url_discovery"]
    tool: Literal["subfinder", "amass", "gau"]
    parameters: LocalOsintParams = Field(default_factory=LocalOsintParams)


class EvidenceCapabilityProposal(ProposalBase):
    kind: Literal["evidence_capability"] = "evidence_capability"
    capability: Literal["sourcemap_analyze", "wsdl_discovery"]
    evidence_ref: str = Field(min_length=1, max_length=128)
    parameters: EvidenceParams


class StopReason(StrEnum):
    COVERAGE_SUFFICIENT = "COVERAGE_SUFFICIENT"
    NO_SAFE_SUPPORTED_ACTION = "NO_SAFE_SUPPORTED_ACTION"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class StopProposal(ProposalBase):
    kind: Literal["stop"] = "stop"
    reason_code: StopReason


ReconProposal = Annotated[SafeHttpProbeProposal | BrowserExploreProposal | ContentDiscoveryProposal
                          | TargetCapabilityProposal | ProviderCapabilityProposal | LocalOsintCapabilityProposal
                          | EvidenceCapabilityProposal | StopProposal,
                          Field(discriminator="kind")]


class ReconPlanningDecision(PlanningModel):
    proposals: tuple[ReconProposal, ...] = Field(max_length=5)

    @model_validator(mode="after")
    def stop_is_exclusive(self):
        if len(self.proposals) > 1 and any(p.kind == "stop" for p in self.proposals):
            raise ValueError("STOP must be the only proposal")
        return self


class ReconPlanningLimits(PlanningModel):
    max_llm_rounds: int = Field(default=32, ge=1, le=128, strict=True)
    max_proposals_per_round: int = Field(default=1, ge=1, le=5, strict=True)
    max_total_llm_actions: int = Field(default=96, ge=1, le=512, strict=True)
    max_context_bytes: int = Field(default=32768, ge=2048, le=65536, strict=True)
    model_timeout_seconds: float = Field(default=20, gt=0, le=30)


class PlanningScope(PlanningModel):
    targets: tuple[str, ...]
    ports: tuple[int, ...]
    allowed_paths: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    capabilities: tuple[str, ...]
    scope_version: str
    policy_version: str


class PlanningRedirect(PlanningModel):
    present: bool = False
    target_scheme: str | None = None
    target_port: int | None = None
    same_target_ip: bool = False
    scope_status: Literal["NONE", "IN_SCOPE", "OUT_OF_SCOPE", "INVALID"] = "NONE"


class PlanningRoute(PlanningModel):
    method: str
    path: str
    origin: str
    status: str
    parameters: tuple[str, ...]
    last_status_code: int | None = None
    baseline_verified: bool = False
    baseline_blocker: str | None = None
    redirect: PlanningRedirect = Field(default_factory=PlanningRedirect)
    requires_manual_input: bool = False
    required_inputs: bool = False


class PlanningAction(PlanningModel):
    request_id: str
    capability: str
    target_ip: str | None
    port: int | None
    method: str | None
    path: str | None
    status: str
    selector: str | None = None


class PlanningCoverage(PlanningModel):
    routes: int
    observations: int
    fuzz_ready: int
    limitations: tuple[str, ...]
    static_status: str
    browser_status: str


class PlanningBudget(PlanningModel):
    requests: int
    actions: int


class PlanningProgress(PlanningModel):
    current_round: int
    max_rounds: int
    future_rounds_remaining: int


class PlanningService(PlanningModel):
    target_ip: str
    port: int
    protocol: str
    service: str
    version: str
    evidence_ref: str


class PlanningTechnology(PlanningModel):
    technology: str
    version: str
    source: str
    evidence_ref: str


class PlanningAsset(PlanningModel):
    asset_id: str
    asset_type: str
    value: str
    scope_status: str
    verification_status: str


class ChecklistSummary(PlanningModel):
    id: str
    status: Literal["PENDING", "COMPLETE", "BLOCKED", "UNSUPPORTED", "NOT_APPLICABLE", "MANUAL_REVIEW"]
    reason: str
    finding: Literal["FOUND", "NOT_FOUND", "NOT_TESTED"] = "NOT_TESTED"
    recommended_capabilities: tuple[str, ...] = ()
    suggested_paths: tuple[str, ...] = ()


class PlanningTool(PlanningModel):
    capability: str
    execution_kind: Literal["target", "provider", "local_osint", "evidence"]
    risk: Literal["R0", "R1", "R2"]
    availability: str
    provider: str | None = None


class PlanningEvidence(PlanningModel):
    evidence_ref: str
    request_id: str
    capability: str
    status_code: int | None = None
    path: str | None = None


class PlanningBinding(PlanningModel):
    host: str
    target_ip: str
    scheme: str
    port: int
    evidence_ref: str


class PlanningSignal(PlanningModel):
    signal_id: str
    kind: str
    asset_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    suggested_capabilities: tuple[str, ...] = ()


class PlanningRunnerData(PlanningModel):
    id: str
    category: str
    source_id: str
    entry_count: int
    intended_phase: str


class ReconPlanningContext(PlanningModel):
    task_id: str
    run_id: str
    inventory_version: Literal["1.0"] = "1.0"
    planning_round: int
    planning: PlanningProgress
    scope: PlanningScope
    capabilities: tuple[str, ...]
    root_target: str | None = None
    discovery_seeds: tuple[str, ...] = ()
    tools: tuple[PlanningTool, ...] = ()
    evidence: tuple[PlanningEvidence, ...] = ()
    bindings: tuple[PlanningBinding, ...] = ()
    previous_rejections: tuple[str, ...] = ()
    coverage_score: float = Field(default=0, ge=0, le=100)
    mandatory_resolved: bool = False
    residual_signals: tuple[PlanningSignal, ...] = ()
    coverage: PlanningCoverage
    services: tuple[PlanningService, ...]
    technologies: tuple[PlanningTechnology, ...]
    assets: tuple[PlanningAsset, ...] = ()
    checklist_version: Literal["recon-checklist-v1", "recon-checklist-v2", "recon-checklist-v3"] = "recon-checklist-v1"
    checklist: tuple[ChecklistSummary, ...]
    available_actions: tuple[str, ...]
    trusted_wordlists: tuple[str, ...] = ()
    approved_runner_datasets: tuple[PlanningRunnerData, ...] = ()
    routes: tuple[PlanningRoute, ...]
    previous_actions: tuple[PlanningAction, ...]
    remaining_budget: PlanningBudget
    knowledge_query: ReconKnowledgeQuery | None = None
    knowledge_refs: tuple[KnowledgeReference, ...] = ()
    knowledge_excerpts: tuple[str, ...] = ()
    retriever_id: str = "noop-v1"
    context_truncated: bool = False
