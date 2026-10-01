"""Untrusted planning suggestions, independent of execution/Recon implementation."""

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    wordlist_id: str = Field(min_length=1, max_length=64)


class StopReason(StrEnum):
    COVERAGE_SUFFICIENT = "COVERAGE_SUFFICIENT"
    NO_SAFE_SUPPORTED_ACTION = "NO_SAFE_SUPPORTED_ACTION"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class StopProposal(ProposalBase):
    kind: Literal["stop"] = "stop"
    reason_code: StopReason


ReconProposal = Annotated[SafeHttpProbeProposal | BrowserExploreProposal | ContentDiscoveryProposal | StopProposal,
                          Field(discriminator="kind")]


class ReconPlanningDecision(PlanningModel):
    proposals: tuple[ReconProposal, ...] = Field(max_length=5)

    @model_validator(mode="after")
    def stop_is_exclusive(self):
        if len(self.proposals) > 1 and any(p.kind == "stop" for p in self.proposals):
            raise ValueError("STOP must be the only proposal")
        return self


class ReconPlanningLimits(PlanningModel):
    max_llm_rounds: int = Field(default=2, ge=1, le=3, strict=True)
    max_proposals_per_round: int = Field(default=5, ge=1, le=5, strict=True)
    max_total_llm_actions: int = Field(default=8, ge=1, le=8, strict=True)
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
    target_ip: str
    port: int | None
    method: str | None
    path: str | None
    status: str


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


class ReconPlanningContext(PlanningModel):
    task_id: str
    run_id: str
    inventory_version: Literal["1.0"] = "1.0"
    planning_round: int
    planning: PlanningProgress
    scope: PlanningScope
    capabilities: tuple[str, ...]
    coverage: PlanningCoverage
    services: tuple[PlanningService, ...]
    technologies: tuple[PlanningTechnology, ...]
    assets: tuple[PlanningAsset, ...] = ()
    checklist_version: Literal["recon-checklist-v1", "recon-checklist-v2", "recon-checklist-v3"] = "recon-checklist-v1"
    checklist: tuple[ChecklistSummary, ...]
    available_actions: tuple[str, ...]
    trusted_wordlists: tuple[str, ...] = ()
    routes: tuple[PlanningRoute, ...]
    previous_actions: tuple[PlanningAction, ...]
    remaining_budget: PlanningBudget
    knowledge_query: ReconKnowledgeQuery | None = None
    knowledge_refs: tuple[KnowledgeReference, ...] = ()
    knowledge_excerpts: tuple[str, ...] = ()
    retriever_id: str = "noop-v1"
    context_truncated: bool = False
