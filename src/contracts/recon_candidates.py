"""Recon observations for later validation, never vulnerability verdicts."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AttackSurfaceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    asset_id: str | None = None
    endpoint_id: str | None = None
    title: str = Field(min_length=1)
    observation: str = Field(min_length=1)
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    verification_status: Literal["OBSERVED", "VERIFIED"]
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    knowledge_refs: tuple[str, ...] = ()
    source_capabilities: tuple[str, ...] = Field(min_length=1)
    checklist_refs: tuple[str, ...] = ()
    recommended_next_stage: Literal["VALIDATION", "FUZZING", "REVIEW"] = "VALIDATION"

    @model_validator(mode="after")
    def no_vulnerability_claim(self):
        if bool(self.asset_id) == bool(self.endpoint_id):
            raise ValueError("candidate requires exactly one asset or endpoint identity")
        if "confirmed vulnerability" in (self.title + " " + self.observation).lower():
            raise ValueError("Recon cannot assert a confirmed vulnerability")
        return self
