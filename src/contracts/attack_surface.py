"""Recon -> Supervisor/Fuzz contract v1. No dependency on Recon implementation."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EndpointStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    OBSERVED = "OBSERVED"
    BASELINED = "BASELINED"
    FUZZ_READY = "FUZZ_READY"


class Parameter(ContractModel):
    name: str = Field(min_length=1, max_length=256)
    location: Literal["query", "path", "header", "cookie", "body", "formData"]
    required: bool = False
    data_type: str = Field(default="unknown", max_length=64)


class Provenance(ContractModel):
    source_ref: str = Field(min_length=1)
    observation_ref: str = Field(min_length=1)
    request_ref: str = Field(min_length=1)
    evidence_ref: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    relation: str = Field(min_length=1)


class Observation(ContractModel):
    id: str = Field(min_length=1)
    concrete_url: str = Field(min_length=1)
    request_ref: str | None = None
    response_status: int | None = Field(default=None, ge=100, le=599)
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    provenance: tuple[Provenance, ...] = Field(min_length=1)


class AttackSurfaceEntry(ContractModel):
    id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    scheme: Literal["http", "https"]
    authority: str
    resolved_ip: str
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
    canonical_path: str
    route_template: str | None = None
    parameters: tuple[Parameter, ...] = ()
    observations: tuple[Observation, ...]
    baseline_ref: str | None = None
    baseline_observation_ref: str | None = None
    evidence_refs: tuple[str, ...]
    provenance: tuple[Provenance, ...]
    auth_context_ref: str | None = None
    status: EndpointStatus
    in_scope: bool
    has_verified_baseline: bool
    has_valid_evidence: bool
    has_unresolved_required_input: bool
    is_testable: bool

    @model_validator(mode="after")
    def traceable_and_ready(self):
        if not self.canonical_path.startswith("/") or any(c in self.canonical_path for c in "?#"):
            raise ValueError("route identity must not contain query or fragment")
        if self.route_template is not None and self.route_template != self.canonical_path:
            raise ValueError("route template must equal the canonical route path")
        observation_ids = {item.id for item in self.observations}
        if len(observation_ids) != len(self.observations):
            raise ValueError("duplicate observation identity")
        if not self.provenance or not self.evidence_refs:
            raise ValueError("exported attack surface requires evidence-backed provenance")
        for item in self.provenance:
            if item.observation_ref not in observation_ids or item.evidence_ref not in self.evidence_refs:
                raise ValueError("broken attack surface provenance reference")
        for observation in self.observations:
            if any(proof.observation_ref != observation.id or proof.evidence_ref not in observation.evidence_refs
                   or proof not in self.provenance for proof in observation.provenance):
                raise ValueError("broken observation provenance reference")
            if any(ref not in self.evidence_refs for ref in observation.evidence_refs):
                raise ValueError("observation evidence missing from entry")
        if self.baseline_observation_ref and self.baseline_observation_ref not in observation_ids:
            raise ValueError("baseline observation missing")
        if self.status == EndpointStatus.FUZZ_READY and not (
            self.in_scope and self.has_verified_baseline and self.has_valid_evidence
            and not self.has_unresolved_required_input and self.is_testable
            and self.baseline_ref and self.baseline_observation_ref
        ):
            raise ValueError("FUZZ_READY readiness conditions are not satisfied")
        return self


class AttackSurfaceInventory(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    task_id: str
    entries: tuple[AttackSurfaceEntry, ...] = ()

    @model_validator(mode="after")
    def consistent_inventory(self):
        if any(entry.run_id != self.run_id for entry in self.entries):
            raise ValueError("inventory run mismatch")
        if len({entry.id for entry in self.entries}) != len(self.entries):
            raise ValueError("duplicate route identity")
        return self
