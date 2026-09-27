"""The only entry point that dispatches a Recon capability to an adapter."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityRequest,
    EvidenceArtifact,
    TechnologyObservation,
    ToolResult,
)
from src.recon.policy import PolicyService


@dataclass(frozen=True)
class AdapterOutput:
    status: str
    raw_output: bytes = b""
    message: str = ""
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()


class Adapter(Protocol):
    def execute(self, request: CapabilityRequest) -> AdapterOutput: ...


class EvidenceWriter(Protocol):
    def save(self, request: CapabilityRequest, content: bytes) -> EvidenceArtifact: ...


class ResultWriter(Protocol):
    def save_tool_result(self, result: ToolResult) -> None: ...


class CapabilityRegistry:
    def __init__(self) -> None:
        self._adapters: dict[Capability, Adapter] = {}

    def register(self, capability: Capability, adapter: Adapter) -> None:
        if capability in self._adapters:
            raise ValueError(f"adapter already registered: {capability.value}")
        self._adapters[capability] = adapter

    def get(self, capability: Capability) -> Adapter | None:
        return self._adapters.get(capability)


class ToolExecutionGateway:
    def __init__(
        self,
        policy: PolicyService,
        registry: CapabilityRegistry,
        evidence: EvidenceWriter,
        results: ResultWriter,
    ) -> None:
        self.policy = policy
        self.registry = registry
        self.evidence = evidence
        self.results = results

    def execute(self, request: CapabilityRequest) -> ToolResult:
        started_at = datetime.now(UTC)
        decision = self.policy.decide(request)
        adapter = self.registry.get(request.capability)
        if not decision.allowed or adapter is None:
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request.target_ip,
                status="denied",
                message=decision.reason if not decision.allowed else "capability adapter unavailable",
                started_at=started_at,
            )
            self.results.save_tool_result(result)
            return result

        try:
            output = adapter.execute(request)
            if output.status not in ("success", "error"):
                raise ValueError("adapter returned invalid status")
            artifact = self.evidence.save(request, output.raw_output) if output.raw_output else None
            evidence_id = artifact.id if artifact else None
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request.target_ip,
                status=output.status,
                message=output.message,
                evidence_id=evidence_id,
                attack_surface=tuple(entry.model_copy(update={"evidence_id": evidence_id or ""}) for entry in output.attack_surface),
                technologies=tuple(tech.model_copy(update={"evidence_id": evidence_id or ""}) for tech in output.technologies),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        except Exception as exc:
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request.target_ip,
                status="error",
                message=f"{type(exc).__name__}: {exc}",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        self.results.save_tool_result(result)
        return result
