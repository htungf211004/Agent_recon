"""Bounded structured queries and traceable retrieved knowledge."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.contracts.execution import Risk


class RagModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Namespace = Literal["attack_surface_methodology", "technology_cve", "technique_reference", "tool_capability_reference"]


class ReconKnowledgeQuery(RagModel):
    phase: Literal["attack_surface"] = "attack_surface"
    categories: tuple[str, ...] = Field(default=(), max_length=16)
    available_capabilities: tuple[str, ...] = Field(default=(), max_length=32)
    risk_ceiling: Literal[Risk.R0, Risk.R1] = Risk.R0
    checklist_gaps: tuple[str, ...] = Field(default=(), max_length=16)
    asset_types: tuple[str, ...] = Field(default=(), max_length=16)
    verified_technologies: tuple[str, ...] = Field(default=(), max_length=16)
    verified_services: tuple[str, ...] = Field(default=(), max_length=16)
    route_categories: tuple[str, ...] = Field(default=(), max_length=16)
    limitations: tuple[str, ...] = Field(default=(), max_length=16)

    @field_validator("checklist_gaps", "asset_types", "verified_technologies", "verified_services",
                     "route_categories", "limitations")
    @classmethod
    def bounded_facts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(len(value) > 100 or any(ord(char) < 32 for char in value) for value in values):
            raise ValueError("knowledge query fact exceeds bounds")
        return values


class KnowledgeChunk(RagModel):
    knowledge_id: str = Field(min_length=1, max_length=128)
    namespace: Namespace
    source_id: str = Field(min_length=1, max_length=128)
    title: str = Field(max_length=160)
    excerpt: str = Field(max_length=512)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    version: str = Field(max_length=64)
    source_snapshot_id: str | None = None
    source_commit: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict, max_length=8)

    @field_validator("metadata")
    @classmethod
    def bounded_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if any(len(key) > 40 or len(item) > 120 for key, item in value.items()):
            raise ValueError("knowledge metadata exceeds bounds")
        return value


class KnowledgeReference(RagModel):
    knowledge_id: str
    source_id: str
    content_hash: str
    namespace: Namespace
    source_version: str | None = None
    source_commit: str | None = None
    source_snapshot_id: str | None = None
