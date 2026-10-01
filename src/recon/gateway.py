"""The only entry point that dispatches a Recon capability to an adapter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlsplit

from src.recon.execution import ToolRun, ToolRunState
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityAvailability,
    CapabilityRequest,
    EvidenceArtifact,
    PolicyDecision,
    PolicyOutcome,
    ProviderCapabilityRequest,
    ReconExecutionRequest,
    ReconObservation,
    TechnologyObservation,
    ToolResult,
    request_target_ip,
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
    observations: tuple[ReconObservation, ...] = ()


@dataclass(frozen=True)
class ExternalDispatchPermit:
    request: CapabilityRequest
    run: ToolRun
    started_at: datetime


class Adapter(Protocol):
    def execute(self, request: ReconExecutionRequest) -> AdapterOutput: ...


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

    def mark_external_dispatched(self, run: ToolRun) -> bool: ...

    def cancel_tool_run(self, request_id: str) -> ToolResult | None: ...


class CapabilityRegistry:
    def __init__(self) -> None:
        self._adapters: dict[Capability, Adapter] = {}
        self._unavailable: dict[Capability, str] = {}

    def register(self, capability: Capability, adapter: Adapter) -> None:
        if capability in self._adapters:
            raise ValueError(f"adapter already registered: {capability.value}")
        self._adapters[capability] = adapter
        self._unavailable.pop(capability, None)

    def mark_unavailable(self, capability: Capability, status: str) -> None:
        if status not in {"MISSING_BINARY", "MISSING_CREDENTIAL", "POLICY_DISABLED",
                          "UNSUPPORTED_TARGET_KIND", "RUNTIME_ERROR"}:
            raise ValueError("invalid capability availability")
        if capability in self._adapters:
            raise ValueError("registered capability cannot be unavailable")
        self._unavailable[capability] = status

    def availability(self, capability: Capability, provider: str | None = None) -> str:
        if capability == Capability.BROWSER_REQUEST:
            return "AVAILABLE" if Capability.BROWSER_EXPLORE in self._adapters else "MISSING_BINARY"
        adapter = self._adapters.get(capability)
        if adapter is not None:
            return adapter.availability(provider) if hasattr(adapter, "availability") else "AVAILABLE"
        return self._unavailable.get(capability, "MISSING_BINARY")

    def get(self, capability: Capability) -> Adapter | None:
        return self._adapters.get(capability)

    def available_capabilities(self) -> tuple[Capability, ...]:
        return tuple(sorted((capability for capability in self._adapters
                             if self.availability(capability) == "AVAILABLE"), key=lambda capability: capability.value))

    def availability_manifest(self) -> tuple[dict, ...]:
        rows = []
        for capability in Capability:
            adapter = self._adapters.get(capability)
            providers = getattr(adapter, "adapters", None)
            if providers:
                rows.extend(CapabilityAvailability(capability=capability, provider=provider,
                             status=self.availability(capability, provider)).model_dump(mode="json")
                            for provider in sorted(providers))
            else:
                rows.append(CapabilityAvailability(capability=capability,
                            status=self.availability(capability)).model_dump(mode="json"))
        return tuple(rows)


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

    def execute(self, request: ReconExecutionRequest) -> ToolResult:
        if request.capability == Capability.BROWSER_REQUEST:
            raise ValueError("browser requests require external dispatch")
        request = self.policy.bind(request)
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
                target_ip=request_target_ip(request),
                status="error",
                message="request already claimed or incomplete",
            )

        started_at = datetime.now(UTC)
        decision = self.policy.decide(request)
        adapter = self.registry.get(request.capability)
        availability = self.registry.availability(request.capability, getattr(request, "provider", None))
        if decision.allowed and adapter is None:
            decision = decision.model_copy(update={"allowed": False, "outcome": PolicyOutcome.DENY,
                                                   "reason": f"capability adapter unavailable: {availability}"})
        elif decision.allowed and availability != "AVAILABLE":
            decision = decision.model_copy(update={"allowed": False, "outcome": PolicyOutcome.DENY,
                                                   "reason": f"capability unavailable: {availability}"})
        decision = self.results.start_tool_run(run, request, decision)
        if not decision.allowed or adapter is None:
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request_target_ip(request),
                status="denied",
                parent_request_id=request.parent_request_id,
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
            if isinstance(request, ProviderCapabilityRequest) and output.status == "error":
                output = AdapterOutput(status="error", timed_out=timed_out,
                                       message="provider request failed")
            if isinstance(request, ProviderCapabilityRequest) and output.status == "success":
                for observation in output.observations:
                    value = observation.value
                    if (observation.provider != request.provider
                            or any(marker in value.lower() for marker in ("api_key=", "secret=", "token="))):
                        raise ValueError("provider output is not normalized")
                    if observation.kind in {"URL", "CODE_REFERENCE", "SEARCH_REFERENCE"} and value.startswith("http"):
                        parts = urlsplit(value)
                        if parts.scheme != "https" or parts.query or parts.fragment or parts.username or parts.password:
                            raise ValueError("provider output is not normalized")
                try:
                    normalized = json.loads(output.raw_output)
                    expected = {"provider": request.provider, "root_domain": request.root_domain,
                                "profile": request.parameters.profile,
                                "observations": [row.model_dump(mode="json") for row in output.observations]}
                    if normalized != expected:
                        raise ValueError("provider output is not normalized")
                except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
                    raise ValueError("provider output is not normalized") from exc
            terminal = self.results.get_tool_result(request.id)
            if terminal is not None:
                return terminal
            artifact = self.evidence.save(request, output.raw_output) if output.raw_output else None
            evidence_id = artifact.id if artifact else None
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request_target_ip(request),
                status=output.status,
                parent_request_id=request.parent_request_id,
                message=output.message,
                evidence_id=evidence_id,
                attack_surface=tuple(entry.model_copy(update={"evidence_id": evidence_id or ""}) for entry in output.attack_surface),
                technologies=tuple(tech.model_copy(update={"evidence_id": evidence_id or ""}) for tech in output.technologies),
                http_response=output.http_response,
                observations=tuple(obs.model_copy(update={"evidence_id": evidence_id or ""})
                                   for obs in output.observations),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        except Exception as exc:
            timed_out = isinstance(exc, TimeoutError)
            result = ToolResult(
                request_id=request.id,
                task_id=request.task_id,
                capability=request.capability,
                target_ip=request_target_ip(request),
                status="error",
                parent_request_id=request.parent_request_id,
                message=("provider execution failed" if isinstance(request, ProviderCapabilityRequest)
                         else f"{type(exc).__name__}: {exc}"),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        return self.results.finish_tool_run(run, result, timed_out=timed_out)

    def begin_external_dispatch(self, request: CapabilityRequest) -> ExternalDispatchPermit | ToolResult:
        """Claim and authorize an intercepted browser request before any network I/O."""
        if request.capability != Capability.BROWSER_REQUEST or not request.parent_request_id:
            raise ValueError("external dispatch is only for browser child requests")
        request = self.policy.bind(request)
        fingerprint = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
        previous = self.results.get_tool_run(request.id)
        if previous and (previous.task_id != request.task_id or previous.request_fingerprint != fingerprint):
            raise ValueError("request id reused with different content")
        self.results.recover_expired_runs(request.task_id, request)
        existing = self.results.get_tool_result(request.id)
        if existing is not None:
            return existing
        run = self.results.acquire_tool_run(request)
        if run is None:
            return self.results.get_tool_result(request.id) or ToolResult(
                request_id=request.id, task_id=request.task_id, capability=request.capability,
                target_ip=request.target_ip, parent_request_id=request.parent_request_id,
                status="error", message="request already claimed or parent not running",
            )
        started_at = datetime.now(UTC)
        decision = self.results.start_tool_run(run, request, self.policy.decide(request))
        if not decision.allowed:
            return self.results.finish_tool_run(run, ToolResult(
                request_id=request.id, task_id=request.task_id, capability=request.capability,
                target_ip=request.target_ip, parent_request_id=request.parent_request_id,
                status="denied", message=decision.reason, started_at=started_at,
            ))
        return ExternalDispatchPermit(request=request, run=run, started_at=started_at)

    def authorize_external_continuation(self, permit: ExternalDispatchPermit) -> bool:
        """Consume a durable, one-use network continuation token."""
        return self.results.mark_external_dispatched(permit.run)

    def finish_external_dispatch(self, permit: ExternalDispatchPermit, output: AdapterOutput) -> ToolResult:
        """Persist child evidence and terminal result; cancellation wins any race."""
        request, run = permit.request, permit.run
        existing = self.results.get_tool_result(request.id)
        if existing is not None:
            return existing
        current = self.results.get_tool_run(request.id)
        if (current is None or current.owner_token != run.owner_token
                or current.state != ToolRunState.RUNNING or current.external_dispatched_at is None):
            raise RuntimeError("external dispatch was not continued or execution was cancelled")
        if output.status not in ("success", "error"):
            raise ValueError("invalid external dispatch status")
        artifact = self.evidence.save(request, output.raw_output) if output.raw_output else None
        result = ToolResult(
            request_id=request.id, task_id=request.task_id, capability=request.capability,
            target_ip=request.target_ip, parent_request_id=request.parent_request_id,
            status=output.status, message=output.message,
            evidence_id=artifact.id if artifact else None, http_response=output.http_response,
            started_at=permit.started_at, finished_at=datetime.now(UTC),
        )
        return self.results.finish_tool_run(run, result, timed_out=output.timed_out)

    def cancel(self, request_id: str) -> ToolResult | None:
        return self.results.cancel_tool_run(request_id)
