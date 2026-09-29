"""Translate suggestions to existing typed actions; the Gateway remains authority."""

from src.contracts.recon_planning import ReconPlanningDecision, ReconPlanningLimits
from src.recon.endpoints import baseline_eligible
from src.recon.models import (
    BrowserExploreParams,
    BrowserLimits,
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    ReconPlan,
)
from src.recon.planner import ReconPlanner
from src.recon.urls import match_route_template, request_url


def action_key(request):
    """Ignore IDs, rationale and transport limits when detecting repeated actions."""
    params = request.parameters
    if hasattr(params, "port"):
        return (request.capability, request_url(request.target_ip, params.scheme, params.port,
                getattr(params, "path", "/"), getattr(params, "query", "")), getattr(params, "method", "GET"))
    return (request.capability, request.target_ip, params.model_dump_json())


class ReconProposalValidator:
    def __init__(self, repository, service, limits: ReconPlanningLimits):
        self.repository, self.service, self.limits = repository, service, limits

    def validate(self, task, decision: ReconPlanningDecision, remaining_actions: int):
        if len(decision.proposals) > self.limits.max_proposals_per_round:
            return ReconPlan(task_id=task.id), ("proposal_limit",)
        if any(p.kind == "stop" for p in decision.proposals):
            return ReconPlan(task_id=task.id), ("model_stop",)
        seen = {action_key(CapabilityRequest.model_validate_json(run.request_payload))
                for run in self.repository.list_tool_runs(task.id) if run.request_payload}
        seen.update(action_key(action.request) for plan in self.repository.list_plans(task.id) for action in plan.actions)
        actions, rejected = [], []
        for proposal in sorted(decision.proposals, key=lambda p: (p.priority, p.kind, p.model_dump_json())):
            try:
                if proposal.kind == "content_discovery":
                    raise ValueError("unsupported capability: content_discovery")
                if len(actions) >= remaining_actions:
                    raise ValueError("action_limit")
                if proposal.target_ip is None or proposal.port is None:
                    raise ValueError("missing target")
                common = dict(port=proposal.port, scheme=proposal.scheme, path=proposal.path)
                if proposal.kind == "safe_http_probe":
                    capability = Capability.HTTP_FETCH  # HTTP_PROBE cannot enforce arbitrary path/method.
                    params = HttpFetchParams(**common, method=proposal.method,
                                             timeout_seconds=min(5, task.execution_budget.max_timeout_seconds),
                                             max_body_bytes=task.execution_budget.max_body_bytes)
                else:
                    if proposal.method != "GET":
                        raise ValueError("browser navigation requires GET")
                    if Capability.BROWSER_REQUEST not in task.scope.capabilities:
                        raise ValueError("browser child capability not allowed")
                    capability = Capability.BROWSER_EXPLORE
                    params = BrowserExploreParams(**common, limits=BrowserLimits(
                        max_pages=2, max_depth=1, max_requests=8,
                        max_runtime_seconds=min(10, task.execution_budget.max_timeout_seconds),
                        max_response_bytes=min(65536, task.execution_budget.max_body_bytes), max_total_bytes=131072,
                    ))
                if self.service.gateway.registry.get(capability) is None:
                    raise ValueError("capability unavailable")
                action = ReconPlanner._action(task, proposal.target_ip, capability, params)
                request = action.request
                url = request_url(request.target_ip, params.scheme, params.port, params.path)
                matches = [endpoint for endpoint in self.repository.list_endpoints(task.id)
                           if endpoint.method == proposal.method and
                           (endpoint.url == url or (endpoint.route_template and match_route_template(endpoint.url, url)))]
                if any(not baseline_eligible(endpoint, url) for endpoint in matches):
                    raise ValueError("manual or unresolved input")
                key = action_key(request)
                if key in seen:
                    raise ValueError("duplicate action")
                decision_check = self.service.gateway.policy.decide(request)
                if not decision_check.allowed:
                    raise ValueError(decision_check.reason)
                # This check only filters suggestions. Gateway rechecks and atomically reserves on execution.
                seen.add(key)
                actions.append(action)
            except (ValueError, TypeError) as error:
                # Store bounded rejection codes, not a Pydantic error echoing untrusted input.
                reason = str(error) if type(error) is ValueError else "invalid proposal target or parameters"
                rejected.append(reason[:160])
        return ReconPlan(task_id=task.id, actions=tuple(actions)), tuple(rejected)
