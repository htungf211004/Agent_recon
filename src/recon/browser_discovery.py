"""Deterministic browser phase using ordinary plans, gateway execution and inventory."""

import json
from urllib.parse import urlsplit

from src.recon.browser_dom import project_browser_response
from src.recon.execution import ToolRunState
from src.recon.models import BrowserExploreParams, BrowserLimits, Capability, CapabilityRequest, ReconAction, ReconPlan
from src.recon.planner import scheme_for_port
from src.recon.urls import path_allowed
from src.recon.web_models import stable_id


class BrowserDiscovery:
    def __init__(self, repository, service, limits: BrowserLimits | None = None):
        self.repository, self.service = repository, service
        self.limits = limits or BrowserLimits(max_pages=8, max_depth=2, max_requests=32)

    def run(self, task):
        if (Capability.BROWSER_EXPLORE not in task.scope.capabilities
                or self.service.gateway.registry.get(Capability.BROWSER_EXPLORE) is None):
            return self.service.snapshot(task.id)
        self.repository.recover_expired_runs(task.id)
        plans = tuple(plan for plan in self.repository.list_plans(task.id)
                      if any(action.id.startswith("browser-discovery-") for action in plan.actions))
        if not plans:
            candidates = sorted(task.discovery_seeds) or sorted(task.scope.allowed_paths) or ["/"]
            roots = [root for root in candidates if path_allowed(urlsplit(root).path, task.scope.allowed_paths)]
            if not roots:
                return self.service.snapshot(task.id)
            root = urlsplit(roots[0])
            limits = self.limits.model_copy(update={
                "max_runtime_seconds": min(self.limits.max_runtime_seconds, task.execution_budget.max_timeout_seconds),
                "max_response_bytes": min(self.limits.max_response_bytes, task.execution_budget.max_body_bytes),
            })
            actions = []
            for ip in sorted(set(task.scope.allowed_ips)):
                for port in sorted(set(task.scope.allowed_ports)):
                    params = BrowserExploreParams(port=port, scheme=scheme_for_port(port), path=root.path,
                                                  query=root.query, limits=limits)
                    identity = "browser-discovery-" + stable_id(task.id, task.run_id, ip, params.model_dump_json())
                    request = CapabilityRequest(id=identity, task_id=task.id, capability=Capability.BROWSER_EXPLORE,
                                                target_ip=ip, parameters=params)
                    actions.append(ReconAction(id=identity, request=request))
            plans = (ReconPlan(task_id=task.id, actions=tuple(actions)),)
            # Persist all origins before execution, so restart does not change phase identity.
            self.repository.save_plan(plans[0])
        for plan in plans:
            self.service.run(plan)
            # Repair projection after a crash between child completion and inventory writes.
            for action in plan.actions:
                parent = self.repository.get_tool_run(action.request.id)
                if parent is None or parent.state == ToolRunState.CANCELLED:
                    continue
                for child in self.repository.list_child_runs(action.request.id):
                    result = self.repository.get_tool_result(child.request_id)
                    if child.state != ToolRunState.SUCCEEDED or not result or not result.evidence_id:
                        continue
                    raw = self.service.gateway.evidence.read(result.evidence_id)
                    if raw is not None:
                        request = CapabilityRequest.model_validate_json(child.request_payload)
                        project_browser_response(self.repository, request, result, json.loads(raw))
        return self.service.snapshot(task.id)
