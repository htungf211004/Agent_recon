"""Deny-by-default authorization for Day-1 Recon capabilities."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Protocol

from src.contracts.execution import CURRENT_RECON_POLICY_VERSION, Risk, action_fingerprint
from src.recon.models import (
    BrowserExploreParams,
    BrowserRequestParams,
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    PolicyDecision,
    ReconTask,
)
from src.recon.urls import path_allowed


class TaskReader(Protocol):
    def get_task(self, task_id: str) -> ReconTask | None: ...

    def budget_denial(self, request: CapabilityRequest) -> str | None: ...


class PolicyService:
    VERSION = CURRENT_RECON_POLICY_VERSION

    def __init__(self, tasks: TaskReader):
        self.tasks = tasks

    @classmethod
    def scope_fingerprint(cls, task: ReconTask) -> str:
        snapshot = task.model_dump(mode="json")
        version = snapshot.pop("policy_version")
        payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256((version + ":" + payload).encode()).hexdigest()

    @classmethod
    def expected_fingerprint(cls, request: CapabilityRequest, task: ReconTask) -> str:
        parameters = request.parameters.model_dump(mode="json")
        if request.parent_request_id is not None:
            parameters["parent_request_id"] = request.parent_request_id
        return action_fingerprint(
            run_id=task.run_id, task_id=task.id, target=request.target_ip,
            tool=request.capability.value, parameters=parameters,
            scope_version=task.scope_version, policy_version=task.policy_version,
            scope_fingerprint=cls.scope_fingerprint(task),
        )

    def bind(self, request: CapabilityRequest) -> CapabilityRequest:
        """Fill absent legacy metadata; never replace a caller's conflicting value."""
        task = self.tasks.get_task(request.task_id)
        if task is None:
            return request
        return request.model_copy(update={
            "run_id": request.run_id or task.run_id,
            "scope_version": request.scope_version or task.scope_version,
            "action_fingerprint": request.action_fingerprint or self.expected_fingerprint(request, task),
        })

    def decide(self, request: CapabilityRequest) -> PolicyDecision:
        request = self.bind(request)
        task = self.tasks.get_task(request.task_id)
        reason = self._denial_reason(request, task)
        if reason is None:
            reason = self.tasks.budget_denial(request)
        fingerprint = self.scope_fingerprint(task) if task else ""
        return PolicyDecision(
            request_id=request.id, action_fingerprint=request.action_fingerprint or "",
            scope_version=request.scope_version or "unknown", allowed=reason is None,
            reason=reason or "in scope", policy_version=self.VERSION,
            policy_fingerprint=fingerprint,
            risk=Risk.R1 if request.capability == Capability.NMAP_SCAN else Risk.R0,
        )

    @staticmethod
    def _denial_reason(request: CapabilityRequest, task: ReconTask | None) -> str | None:
        if task is None:
            return "unknown task"
        if task.policy_version != PolicyService.VERSION:
            return "task policy version is stale"
        if request.run_id != task.run_id:
            return "run identity does not match task"
        if request.scope_version != task.scope_version:
            return "scope version does not match task"
        if request.action_fingerprint != PolicyService.expected_fingerprint(request, task):
            return "action fingerprint does not match trusted scope and parameters"
        if request.budget_context is not None and request.budget_context.task_id != task.id:
            return "budget context does not match task"
        if task.expires_at.tzinfo is None or task.expires_at <= datetime.now(UTC):
            return "task expired or has no timezone"
        if request.capability not in task.scope.capabilities:
            return "capability not allowed"
        if request.target_ip not in task.scope.allowed_ips:
            return "target not allowed"
        params = request.parameters
        if isinstance(params, BrowserExploreParams):
            timeout = params.limits.max_runtime_seconds
        elif isinstance(params, (HttpFetchParams, BrowserRequestParams)):
            timeout = params.timeout_seconds
        else:
            timeout = {Capability.HTTP_PROBE: 5, Capability.NMAP_SCAN: 60, Capability.WHATWEB: 20}[request.capability]
        if timeout > task.execution_budget.max_timeout_seconds:
            return "timeout exceeds task budget"
        requested_ports = params.ports if hasattr(params, "ports") else (params.port,)
        if any(port not in task.scope.allowed_ports for port in requested_ports):
            return "port not allowed"
        if isinstance(params, (HttpFetchParams, BrowserRequestParams, BrowserExploreParams)):
            body_limit = params.limits.max_response_bytes if isinstance(params, BrowserExploreParams) else params.max_body_bytes
            if body_limit > task.execution_budget.max_body_bytes:
                return "body size exceeds task budget"
            if isinstance(params, (HttpFetchParams, BrowserRequestParams)) and params.method not in task.scope.allowed_methods:
                return "method not allowed"
            if not path_allowed(params.path, task.scope.allowed_paths):
                return "path not allowed"
        if isinstance(params, BrowserExploreParams) and "GET" not in task.scope.allowed_methods:
            return "method not allowed"
        if isinstance(params, BrowserRequestParams) and not request.parent_request_id:
            return "browser request has no parent"
        return None
