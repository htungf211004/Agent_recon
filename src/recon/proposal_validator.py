"""Translate suggestions to existing typed actions; the Gateway remains authority."""

from urllib.parse import urlsplit

from src.contracts.recon_assets import AssetScopeStatus
from src.contracts.recon_planning import ReconPlanningDecision, ReconPlanningLimits
from src.recon.endpoints import baseline_eligible
from src.recon.models import (
    BrowserExploreParams,
    BrowserLimits,
    Capability,
    ContentDiscoveryParams,
    HttpFetchParams,
    ReconPlan,
)
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.urls import match_route_template, request_url
from src.recon.wordlists import request_units


def action_key(request):
    """Ignore IDs, rationale and transport limits when detecting repeated actions."""
    params = request.parameters
    if isinstance(params, ContentDiscoveryParams):
        return (request.capability, request.target_ip, request.target_host, params.model_dump_json())
    if hasattr(params, "port"):
        return (request.capability, request_url(request.target_ip, params.scheme, params.port,
                getattr(params, "path", "/"), getattr(params, "query", ""), target_host=request.target_host), getattr(params, "method", "GET"))
    return (request.capability, request.target_ip, params.model_dump_json())


class ReconProposalValidator:
    def __init__(self, repository, service, limits: ReconPlanningLimits):
        self.repository, self.service, self.limits = repository, service, limits

    def validate(self, task, decision: ReconPlanningDecision, remaining_actions: int, knowledge_ids=()):
        trusted = self.repository.get_task(task.id)
        if trusted is None or trusted != task:
            return ReconPlan(task_id=task.id), ("trusted task changed",)
        if len(decision.proposals) > self.limits.max_proposals_per_round:
            return ReconPlan(task_id=task.id), ("proposal_limit",)
        if any(p.kind == "stop" for p in decision.proposals):
            if len(decision.proposals) != 1:
                return ReconPlan(task_id=task.id), ("malformed_stop",)
            if (decision.proposals[0].reason_code == "BUDGET_EXHAUSTED" and remaining_actions > 0
                    and self.repository.budget_usage(task.id) < task.execution_budget.max_requests):
                return ReconPlan(task_id=task.id), ("inconsistent_stop_budget",)
            return ReconPlan(task_id=task.id), ("model_stop",)
        from src.recon.models import parse_target_request

        seen = {action_key(request) for run in self.repository.list_tool_runs(task.id)
                if run.request_payload and (request := parse_target_request(run.request_payload)) is not None}
        seen.update(action_key(action.request) for plan in self.repository.list_plans(task.id) for action in plan.actions)
        actions, rejected = [], []
        remaining_requests = task.execution_budget.max_requests - self.repository.budget_usage(task.id)
        for proposal in sorted(decision.proposals, key=lambda p: (p.priority, p.kind, p.model_dump_json())):
            try:
                if len(actions) >= remaining_actions:
                    raise ValueError("action_limit")
                if self.repository.get_authorization(task.id) and not proposal.asset_id:
                    raise ValueError("asset_id required for V2 actions")
                if not set(proposal.knowledge_refs) <= set(knowledge_ids):
                    raise ValueError("unknown knowledge reference")
                target_ip = proposal.target_ip
                if proposal.asset_id:
                    asset = self.repository.get_asset(proposal.asset_id)
                    if asset is None or asset.task_id != task.id or asset.scope_status != AssetScopeStatus.IN_SCOPE:
                        raise ValueError("unknown or out-of-scope asset")
                    host = urlsplit(asset.canonical_value).hostname if "://" in asset.canonical_value else asset.canonical_value
                    trusted_ip = (task.scope.web_origin.pinned_ip if task.scope.web_origin
                                  and host == task.scope.web_origin.host else host if host in task.scope.allowed_ips else None)
                    binding = (self.repository.get_binding(task.id, host, proposal.scheme, proposal.port)
                               if trusted_ip is None else None)
                    trusted_ip = trusted_ip or (binding.address if binding else None)
                    if trusted_ip is None:
                        raise ValueError("asset has no trusted transport binding")
                    if target_ip is not None and target_ip != trusted_ip:
                        raise ValueError("proposal target differs from trusted asset")
                    target_ip = trusted_ip
                if target_ip is None or proposal.port is None:
                    raise ValueError("missing target")
                if proposal.scheme != (task.scope.web_origin.scheme if task.scope.web_origin else scheme_for_port(proposal.port)):
                    raise ValueError("scheme/port mapping not allowed")
                common = dict(port=proposal.port, scheme=proposal.scheme, path=getattr(proposal, "path", "/"))
                if proposal.kind == "safe_http_probe":
                    capability = Capability.HTTP_FETCH  # HTTP_PROBE cannot enforce arbitrary path/method.
                    params = HttpFetchParams(**common, method=proposal.method,
                                             timeout_seconds=min(5, task.execution_budget.max_timeout_seconds),
                                             max_body_bytes=task.execution_budget.max_body_bytes)
                elif proposal.kind == "content_discovery":
                    capability = Capability.CONTENT_DISCOVERY
                    params = ContentDiscoveryParams(port=proposal.port, scheme=proposal.scheme,
                        path_prefix=proposal.path_prefix, wordlist_id=proposal.wordlist_id)
                else:
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
                action = ReconPlanner._action(task, target_ip, capability, params,
                    target_host=host if proposal.asset_id and binding else None)
                request = action.request
                adapter = self.service.gateway.registry.get(capability)
                if hasattr(adapter, "supports") and not adapter.supports(request):
                    raise ValueError("capability unavailable for bound transport")
                if request_units(request) > remaining_requests:
                    raise ValueError("request_limit")
                if capability == Capability.CONTENT_DISCOVERY:
                    from src.recon.content_discovery import candidate_urls
                    urls = candidate_urls(request)
                else:
                    urls = (request_url(request.target_ip, params.scheme, params.port, params.path, target_host=request.target_host),)
                for url in urls:
                    matches = [endpoint for endpoint in self.repository.list_endpoints(task.id)
                               if endpoint.method == getattr(proposal, "method", "GET") and
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
                remaining_requests -= request_units(request)
            except (ValueError, TypeError) as error:
                # Store bounded rejection codes, not a Pydantic error echoing untrusted input.
                reason = str(error) if type(error) is ValueError else "invalid proposal target or parameters"
                rejected.append(reason[:160])
        return ReconPlan(task_id=task.id, actions=tuple(actions)), tuple(rejected)
