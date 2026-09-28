"""The only entry point that dispatches a Recon capability to an adapter."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from src.recon.execution import ToolRun
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityRequest,
    EvidenceArtifact,
    PolicyDecision,
    PolicyOutcome,
    TechnologyObservation,
    ToolResult,
)
from src.recon.policy import PolicyService
from src.recon.web_models import HttpResponseMetadata


@dataclass(frozen=True)
class AdapterOutput:
    status: str
    timed_out: bool = False
    raw_output: bytes = b""
    message: str = ""
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()
    http_response: HttpResponseMetadata | None = None


class Adapter(Protocol):
    def execute(self, request: CapabilityRequest) -> AdapterOutput: ...


class EvidenceWriter(Protocol):
    def save(self, request: CapabilityRequest, content: bytes) -> EvidenceArtifact: ...

    def read(self, artifact_id: str) -> bytes | None: ...


class ResultWriter(Protocol):
    def get_tool_result(self, request_id: str) -> ToolResult | None: ...

    def acquire_tool_run(self, request: CapabilityRequest) -> ToolRun | None: ...

    def get_tool_run(self, request_id: str) -> ToolRun | None: ...

    def recover_expired_runs(self, task_id: str, request: CapabilityRequest | None = None) -> None: ...

    def start_tool_run(self, run: ToolRun, request: CapabilityRequest, decision: PolicyDecision) -> PolicyDecision: ...

    def finish_tool_run(self, run: ToolRun, result: ToolResult, *, timed_out: bool = False) -> ToolResult: ...

    def save_policy_decision(self, decision: PolicyDecision) -> None: ...

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

    def available_capabilities(self) -> tuple[Capability, ...]:
        return tuple(sorted(self._adapters, key=lambda capability: capability.value))


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
        previous = self.results.get_tool_run(request.id)
        if previous and (previous.task_id != request.task_id or (previous.request_fingerprint and
                previous.request_fingerprint != hashlib.sha256(request.model_dump_json().encode()).hexdigest())):
            raise ValueError("request id reused with different content")
        self.results.recover_expired_runs(request.task_id, request)
        existing = self.results.get_tool_result(request.id)
        if existing is not None:
            return existing
        run = self.results.acquire_tool_run(request)
        if run is None:
            # Another worker may have claimed the ID after the initial lookup.
            previous = self.results.get_tool_run(request.id)
            if previous and (previous.task_id != request.task_id or (previous.request_fingerprint and
                    previous.request_fingerprint != hashlib.sha256(request.model_dump_json().encode()).hexdigest())):
                raise ValueError("request id reused with different content")
            existing = self.results.get_tool_result(request.id)
            if existing is not None:
                return existing
            return ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request.target_ip,
                status="error",
                message="request already claimed or incomplete",
            )

        started_at = datetime.now(UTC)
        decision = self.policy.decide(request)
        adapter = self.registry.get(request.capability)
        if decision.allowed and adapter is None:
            decision = decision.model_copy(update={"allowed": False, "outcome": PolicyOutcome.DENY,
                                                   "reason": "capability adapter unavailable"})
        decision = self.results.start_tool_run(run, request, decision)
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
            return self.results.finish_tool_run(run, result)

        timed_out = False
        try:
            output = adapter.execute(request)
            timed_out = output.timed_out
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
                http_response=output.http_response,
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        except Exception as exc:
            timed_out = isinstance(exc, TimeoutError)
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
        return self.results.finish_tool_run(run, result, timed_out=timed_out)
