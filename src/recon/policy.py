"""Deny-by-default authorization for Day-1 Recon capabilities."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol

from src.recon.models import Capability, CapabilityRequest, HttpFetchParams, PolicyDecision, ReconTask
from src.recon.urls import path_allowed


class TaskReader(Protocol):
    def get_task(self, task_id: str) -> ReconTask | None: ...

    def budget_denial(self, request: CapabilityRequest) -> str | None: ...


class PolicyService:
    def __init__(self, tasks: TaskReader):
        self.tasks = tasks

    def decide(self, request: CapabilityRequest) -> PolicyDecision:
        task = self.tasks.get_task(request.task_id)
        reason = self._denial_reason(request, task)
        if reason is None:
            reason = self.tasks.budget_denial(request)
        fingerprint = hashlib.sha256(("recon-2.1:" + (task.model_dump_json() if task else "unknown")).encode()).hexdigest()
        return PolicyDecision(request_id=request.id, allowed=reason is None, reason=reason or "in scope", policy_fingerprint=fingerprint)

    @staticmethod
    def _denial_reason(request: CapabilityRequest, task: ReconTask | None) -> str | None:
        if task is None:
            return "unknown task"
        if request.budget_context is not None and request.budget_context.task_id != task.id:
            return "budget context does not match task"
        if task.expires_at.tzinfo is None or task.expires_at <= datetime.now(UTC):
            return "task expired or has no timezone"
        if request.capability not in task.scope.capabilities:
            return "capability not allowed"
        if request.target_ip not in task.scope.allowed_ips:
            return "target not allowed"
        params = request.parameters
        timeout = params.timeout_seconds if isinstance(params, HttpFetchParams) else {
            Capability.HTTP_PROBE: 5, Capability.NMAP_SCAN: 60, Capability.WHATWEB: 20,
        }[request.capability]
        if timeout > task.execution_budget.max_timeout_seconds:
            return "timeout exceeds task budget"
        requested_ports = params.ports if hasattr(params, "ports") else (params.port,)
        if any(port not in task.scope.allowed_ports for port in requested_ports):
            return "port not allowed"
        if isinstance(params, HttpFetchParams):
            if params.max_body_bytes > task.execution_budget.max_body_bytes:
                return "body size exceeds task budget"
            if params.method not in task.scope.allowed_methods:
                return "method not allowed"
            if not path_allowed(params.path, task.scope.allowed_paths):
                return "path not allowed"
        return None
