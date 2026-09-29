"""Untrusted planning suggestions, independent of execution/Recon implementation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PlanningModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReconProposal(PlanningModel):
    kind: Literal["safe_http_probe", "browser_explore", "content_discovery", "stop"]
    target_ip: str | None = Field(default=None, max_length=45)
    port: int | None = Field(default=None, ge=1, le=65535, strict=True)
    scheme: Literal["http", "https"] = "http"
    method: Literal["GET", "HEAD"] = "GET"
    path: str = Field(default="/", max_length=2048)
    rationale: str = Field(min_length=1, max_length=512)
    priority: int = Field(ge=1, le=5, strict=True)


class ReconPlanningDecision(PlanningModel):
    proposals: tuple[ReconProposal, ...] = Field(max_length=5)


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


class PlanningRoute(PlanningModel):
    method: str
    path: str
    origin: str
    status: str
    parameters: tuple[str, ...]


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


class PlanningBudget(PlanningModel):
    requests: int
    planning_rounds: int
    actions: int


class ReconPlanningContext(PlanningModel):
    task_id: str
    run_id: str
    inventory_version: Literal["1.0"] = "1.0"
    planning_round: int
    scope: PlanningScope
    capabilities: tuple[str, ...]
    coverage: PlanningCoverage
    services: tuple[str, ...]
    technologies: tuple[str, ...]
    routes: tuple[PlanningRoute, ...]
    previous_actions: tuple[PlanningAction, ...]
    remaining_budget: PlanningBudget
    context_truncated: bool = False
