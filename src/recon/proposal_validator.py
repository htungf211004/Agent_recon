"""Map model-selected capabilities to trusted typed requests and prerequisite checks."""

import json
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from pydantic import ValidationError

from src.contracts.recon_planning import ReconPlanningDecision, ReconPlanningLimits
from src.recon.endpoints import baseline_eligible
from src.recon.models import (
    BrowserExploreParams,
    BrowserLimits,
    Capability,
    CapabilityRequest,
    ContentDiscoveryParams,
    DnsResolveParams,
    EvidenceCapabilityRequest,
    HttpFetchParams,
    LocalOsintCapabilityRequest,
    ProviderCapabilityRequest,
    ReconAction,
    ReconPlan,
    parse_execution_request,
)
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.urls import match_route_template, request_url
from src.recon.wordlists import request_units


def action_key(request):
    params = request.parameters
    if not isinstance(request, CapabilityRequest):
        return (request.capability, getattr(request, "root_domain", None),
            getattr(request, "provider", None), getattr(request, "tool", None),
            getattr(request, "evidence_ref", None), params.profile)
    if isinstance(params, DnsResolveParams):
        return (request.capability, params.host)
    if isinstance(params, ContentDiscoveryParams):
        return (request.capability, request.target_ip, request.target_host,
            params.scheme, params.port, params.path_prefix, params.wordlist_id)
    if hasattr(params, "port"):
        return (request.capability, request_url(request.target_ip, params.scheme, params.port,
            getattr(params, "path", "/"), getattr(params, "query", ""), target_host=request.target_host),
            getattr(params, "method", "GET"), getattr(params, "wordlist_id", None))
    return (request.capability, request.target_ip, params.model_dump_json())


class ReconProposalValidator:
    def __init__(self, repository, service, limits: ReconPlanningLimits):
        self.repository, self.service, self.limits = repository, service, limits

    def _target_action(self, task, proposal):
        if proposal.kind == "target_capability":
            params = proposal.parameters
            capability = Capability(params.kind)
        else:
            common = dict(port=proposal.port, scheme=proposal.scheme, path=getattr(proposal, "path", "/"))
            if proposal.kind == "safe_http_probe":
                capability = Capability.HTTP_FETCH
                params = HttpFetchParams(**common, method=proposal.method,
                    timeout_seconds=min(5, task.execution_budget.max_timeout_seconds),
                    max_body_bytes=task.execution_budget.max_body_bytes)
            elif proposal.kind == "content_discovery":
                capability = Capability.CONTENT_DISCOVERY
                params = ContentDiscoveryParams(port=proposal.port, scheme=proposal.scheme,
                    path_prefix=proposal.path_prefix, wordlist_id=proposal.wordlist_id)
            else:
                capability = Capability.BROWSER_EXPLORE
                params = BrowserExploreParams(**common, limits=BrowserLimits(max_pages=2, max_depth=1,
                    max_requests=8, max_runtime_seconds=min(10, task.execution_budget.max_timeout_seconds),
                    max_response_bytes=min(65536, task.execution_budget.max_body_bytes), max_total_bytes=131072))
        if capability == Capability.BROWSER_EXPLORE and Capability.BROWSER_REQUEST not in task.scope.capabilities:
            raise ValueError("browser child capability not allowed")
        target_ip, target_host = proposal.target_ip, None
        boundary = self.repository.get_authorization(task.id)
        if boundary and not proposal.asset_id:
            raise ValueError("asset_id required for V2 actions")
        if proposal.asset_id:
            asset = self.repository.get_asset(proposal.asset_id)
            if asset is None or asset.task_id != task.id or asset.scope_status != "IN_SCOPE":
                raise ValueError("unknown or out-of-scope asset")
            host = urlsplit(asset.canonical_value).hostname if "://" in asset.canonical_value else asset.canonical_value
            if isinstance(params, DnsResolveParams):
                if asset.asset_type != "HOST" or host != params.host:
                    raise ValueError("DNS host differs from trusted asset")
                trusted_ip, target_host = task.scope.allowed_ips[0], host
            elif host in task.scope.allowed_ips and not task.scope.web_origin:
                trusted_ip = host
            elif task.scope.web_origin and host == task.scope.web_origin.host:
                trusted_ip, target_host = task.scope.web_origin.pinned_ip, host
            else:
                binding = (self.repository.get_binding(task.id, host, params.scheme, params.port)
                           if hasattr(params, "port") else None)
                if binding is None:
                    raise ValueError("asset has no trusted transport binding")
                self.service.gateway.evidence.read(binding.dns_evidence_ref)
                trusted_ip, target_host = binding.address, host
            if target_ip is not None and target_ip != trusted_ip:
                raise ValueError("proposal target differs from trusted asset")
            target_ip = trusted_ip
        if target_ip is None:
            raise ValueError("missing target")
        if hasattr(params, "scheme"):
            origin = task.scope.web_origin
            expected = origin.scheme if origin and not task.scope.multi_origin else scheme_for_port(params.port)
            if target_host and self.repository.get_binding(task.id, target_host, params.scheme, params.port):
                expected = params.scheme
            if params.scheme != expected:
                raise ValueError("scheme/port mapping not allowed")
        return ReconPlanner._action(task, target_ip, capability, params, target_host=target_host)

    def _action(self, task, proposal):
        if proposal.kind not in {"provider_capability", "local_osint_capability", "evidence_capability"}:
            return self._target_action(task, proposal)
        values = {"id": "pending", "task_id": task.id, "capability": proposal.capability,
                  "parameters": proposal.parameters}
        if proposal.kind == "evidence_capability":
            request = EvidenceCapabilityRequest(**values, evidence_ref=proposal.evidence_ref)
            self.service.gateway.evidence.read(proposal.evidence_ref)
        else:
            boundary = self.repository.get_authorization(task.id)
            if boundary is None or boundary.root.kind != "DOMAIN":
                raise ValueError("domain root authorization required")
            if proposal.kind == "provider_capability":
                request = ProviderCapabilityRequest(**values, root_domain=boundary.root.value,
                                                    provider=proposal.provider)
            else:
                request = LocalOsintCapabilityRequest(**values, root_domain=boundary.root.value,
                                                       tool=proposal.tool)
        identity = json.dumps([task.id, request.model_dump(mode="json")], sort_keys=True)
        request_id = str(uuid5(NAMESPACE_URL, identity))
        request = self.service.gateway.policy.bind(request.model_copy(update={"id": request_id}))
        return ReconAction(id=request_id, request=request)

    def validate(self, task, decision: ReconPlanningDecision, remaining_actions: int, knowledge_ids=(),
                 *, may_stop=None, stop_context=None):
        if self.repository.get_task(task.id) != task:
            return ReconPlan(task_id=task.id), ("trusted task changed",)
        if len(decision.proposals) > self.limits.max_proposals_per_round:
            return ReconPlan(task_id=task.id), ("proposal_limit",)
        if any(p.kind == "stop" for p in decision.proposals):
            stop = decision.proposals[0]
            if len(decision.proposals) != 1:
                return ReconPlan(task_id=task.id), ("malformed_stop",)
            if stop_context is not None:
                from src.recon.stop_evaluator import assess_stop

                rejection = assess_stop(stop.reason_code, task, stop_context, remaining_actions,
                    task.execution_budget.max_requests - self.repository.budget_usage(task.id))
                if rejection:
                    return ReconPlan(task_id=task.id), (rejection,)
            if stop.reason_code == "COVERAGE_SUFFICIENT" and may_stop is False:
                return ReconPlan(task_id=task.id), ("inconsistent_stop_coverage",)
            if (stop.reason_code == "BUDGET_EXHAUSTED" and remaining_actions > 0
                    and self.repository.budget_usage(task.id) < task.execution_budget.max_requests):
                return ReconPlan(task_id=task.id), ("inconsistent_stop_budget",)
            return ReconPlan(task_id=task.id), ("model_stop",)
        seen = {action_key(parse_execution_request(run.request_payload))
                for run in self.repository.list_tool_runs(task.id) if run.request_payload}
        seen.update(action_key(action.request) for plan in self.repository.list_plans(task.id)
                    for action in plan.actions)
        actions, rejected = [], []
        remaining_requests = task.execution_budget.max_requests - self.repository.budget_usage(task.id)
        for proposal in sorted(decision.proposals, key=lambda p: p.priority):
            try:
                if len(actions) >= remaining_actions:
                    raise ValueError("action_limit")
                if not set(proposal.knowledge_refs) <= set(knowledge_ids):
                    raise ValueError("unknown knowledge reference")
                action = self._action(task, proposal)
                action = action.model_copy(update={"knowledge_refs": proposal.knowledge_refs})
                request, capability, params = action.request, action.request.capability, action.request.parameters
                adapter = self.service.gateway.registry.get(capability)
                selector = getattr(request, "provider", getattr(request, "tool", None))
                if adapter is None or self.service.gateway.registry.availability(capability, selector) != "AVAILABLE":
                    raise ValueError("capability unavailable")
                if hasattr(adapter, "supports") and not adapter.supports(request):
                    raise ValueError("capability unavailable for bound transport")
                if request_units(request) > remaining_requests:
                    raise ValueError("request_limit")
                if isinstance(request, CapabilityRequest) and hasattr(params, "port"):
                    if isinstance(params, ContentDiscoveryParams):
                        from src.recon.content_discovery import candidate_urls
                        urls = candidate_urls(request)
                    else:
                        urls = (request_url(request.target_ip, params.scheme, params.port,
                            getattr(params, "path", "/"), target_host=request.target_host),)
                    for url in urls:
                        matches = [endpoint for endpoint in self.repository.list_endpoints(task.id)
                            if endpoint.method == getattr(params, "method", "GET") and (endpoint.url == url or
                                endpoint.route_template and match_route_template(endpoint.url, url))]
                        if any(not baseline_eligible(endpoint, url) for endpoint in matches):
                            raise ValueError("manual or unresolved input")
                key = action_key(request)
                if key in seen:
                    raise ValueError("duplicate action")
                decision_check = self.service.gateway.policy.decide(request)
                if not decision_check.allowed:
                    raise ValueError(decision_check.reason)
                seen.add(key)
                actions.append(action)
                remaining_requests -= request_units(request)
            except ValidationError:
                rejected.append("invalid proposal target or parameters")
            except (ValueError, TypeError, OSError) as error:
                reason = str(error) if type(error) is ValueError else "invalid proposal target or parameters"
                rejected.append(reason[:160])
        return ReconPlan(task_id=task.id, actions=tuple(actions)), tuple(rejected)
