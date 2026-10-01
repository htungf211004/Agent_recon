"""Deny-by-default authorization for Day-1 Recon capabilities."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Protocol

from src.contracts.execution import CURRENT_RECON_POLICY_VERSION, action_fingerprint
from src.recon.models import (
    BoundedWebToolParams,
    BrowserExploreParams,
    BrowserRequestParams,
    Capability,
    ContentDiscoveryParams,
    DnsResolveParams,
    EvidenceCapabilityRequest,
    GraphqlDiscoveryParams,
    GraphqlIntrospectionParams,
    HttpFetchParams,
    LocalOsintCapabilityRequest,
    ParameterDiscoveryParams,
    PolicyDecision,
    ProviderCapabilityRequest,
    ReconExecutionRequest,
    ReconTask,
    VhostDiscoveryParams,
)
from src.recon.scope.deriver import ScopeDeriver
from src.recon.urls import path_allowed


class TaskReader(Protocol):
    def get_task(self, task_id: str) -> ReconTask | None: ...

    def budget_denial(self, request: ReconExecutionRequest) -> str | None: ...


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
    def expected_fingerprint(cls, request: ReconExecutionRequest, task: ReconTask) -> str:
        if isinstance(request, ProviderCapabilityRequest):
            return action_fingerprint(
                run_id=task.run_id, task_id=task.id, target=request.root_domain,
                tool=request.capability.value,
                parameters={"request_kind": "provider", "provider": request.provider,
                            **request.parameters.model_dump(mode="json")},
                scope_version=task.scope_version, policy_version=task.policy_version,
                scope_fingerprint=cls.scope_fingerprint(task),
            )
        if isinstance(request, LocalOsintCapabilityRequest):
            return action_fingerprint(
                run_id=task.run_id, task_id=task.id, target=request.root_domain,
                tool=request.capability.value,
                parameters={"request_kind": "local_osint", "tool": request.tool,
                            **request.parameters.model_dump(mode="json")},
                scope_version=task.scope_version, policy_version=task.policy_version,
                scope_fingerprint=cls.scope_fingerprint(task),
            )
        if isinstance(request, EvidenceCapabilityRequest):
            return action_fingerprint(
                run_id=task.run_id, task_id=task.id, target=request.evidence_ref,
                tool=request.capability.value,
                parameters={"request_kind": "evidence", **request.parameters.model_dump(mode="json")},
                scope_version=task.scope_version, policy_version=task.policy_version,
                scope_fingerprint=cls.scope_fingerprint(task),
            )
        parameters = request.parameters.model_dump(mode="json")
        if request.target_host is not None:
            parameters["target_host"] = request.target_host
        if request.parent_request_id is not None:
            parameters["parent_request_id"] = request.parent_request_id
        return action_fingerprint(
            run_id=task.run_id, task_id=task.id, target=request.target_ip,
            tool=request.capability.value, parameters=parameters,
            scope_version=task.scope_version, policy_version=task.policy_version,
            scope_fingerprint=cls.scope_fingerprint(task),
        )

    def bind(self, request: ReconExecutionRequest) -> ReconExecutionRequest:
        """Fill absent legacy metadata; never replace a caller's conflicting value."""
        task = self.tasks.get_task(request.task_id)
        if task is None:
            return request
        return request.model_copy(update={
            "run_id": request.run_id or task.run_id,
            "scope_version": request.scope_version or task.scope_version,
            "action_fingerprint": request.action_fingerprint or self.expected_fingerprint(request, task),
        })

    def decide(self, request: ReconExecutionRequest) -> PolicyDecision:
        request = self.bind(request)
        task = self.tasks.get_task(request.task_id)
        reason = self._denial_reason(request, task)
        if reason is None:
            reason = self.tasks.budget_denial(request)
        fingerprint = self.scope_fingerprint(task) if task else ""
        from src.recon.capability_catalog import RISK

        return PolicyDecision(
            request_id=request.id, action_fingerprint=request.action_fingerprint or "",
            scope_version=request.scope_version or "unknown", allowed=reason is None,
            reason=reason or "in scope", policy_version=self.VERSION,
            policy_fingerprint=fingerprint,
            risk=RISK[request.capability],
        )

    def _denial_reason(self, request: ReconExecutionRequest, task: ReconTask | None) -> str | None:
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
        if isinstance(request, ProviderCapabilityRequest):
            boundary = self.tasks.get_authorization(task.id)
            if boundary is None or boundary.root.kind != "DOMAIN" or boundary.root.value != request.root_domain:
                return "provider query root does not match domain authorization"
            if request.provider == "rdap" and request.root_domain.rsplit(".", 1)[-1] not in {"com", "net"}:
                return "RDAP TLD unsupported by configured endpoint"
            if request.parameters.timeout_seconds > task.execution_budget.max_timeout_seconds:
                return "timeout exceeds task budget"
            return None
        if isinstance(request, LocalOsintCapabilityRequest):
            boundary = self.tasks.get_authorization(task.id)
            if boundary is None or boundary.root.kind != "DOMAIN" or boundary.root.value != request.root_domain:
                return "local OSINT root does not match domain authorization"
            if request.parameters.timeout_seconds > task.execution_budget.max_timeout_seconds:
                return "timeout exceeds task budget"
            result_limit = (task.execution_budget.max_historical_urls if
                            request.capability == Capability.HISTORICAL_URL_DISCOVERY else
                            task.execution_budget.max_subdomains)
            if request.parameters.max_results > result_limit:
                return "local OSINT result limit exceeds task budget"
            return None
        if isinstance(request, EvidenceCapabilityRequest):
            artifact = self.tasks.get_evidence(request.evidence_ref)
            result = self.tasks.get_tool_result(artifact.request_id) if artifact else None
            run = self.tasks.get_tool_run(artifact.request_id) if artifact else None
            source = None
            if run and run.request_payload:
                from src.recon.models import parse_target_request

                source = parse_target_request(run.request_payload)
            if (artifact is None or artifact.task_id != task.id or result is None
                    or result.status != "success" or result.evidence_id != artifact.id
                    or source is None or source.capability != Capability.HTTP_FETCH):
                return "evidence is not a successful artifact of this task"
            path = source.parameters.path.lower()
            if request.capability == Capability.SOURCEMAP_ANALYZE and not path.endswith(".map"):
                return "source map analysis requires fetched .map evidence"
            if request.capability == Capability.WSDL_DISCOVERY and not (
                    path.endswith(".wsdl") or source.parameters.query.lower() == "wsdl"):
                return "WSDL analysis requires fetched WSDL evidence"
            return None
        params = request.parameters
        if isinstance(params, DnsResolveParams):
            boundary = self.tasks.get_authorization(task.id)
            if (request.target_ip not in task.scope.allowed_ips or request.target_host != params.host
                    or boundary is None or params.host == boundary.root.value):
                return "DNS candidate is not within root authorization"
            try:
                ipaddress.ip_address(params.host)
            except ValueError:
                pass
            else:
                return "DNS candidate must be a hostname"
            classification = ScopeDeriver(boundary, self.tasks.list_dns_observations(task.id)).classify_host(params.host)
            if classification != ("IN_SCOPE" if boundary.root.kind == "DOMAIN" else "MANUAL_REVIEW"):
                return "DNS candidate is not within root authorization"
            assets = self.tasks.list_assets(task.id)
            if not any(asset.asset_type == "HOST" and asset.canonical_value == params.host
                       and asset.scope_status == classification and asset.discovery_evidence_refs
                       and any(self.tasks.get_evidence(ref) is not None for ref in asset.discovery_evidence_refs)
                       for asset in assets):
                return "DNS candidate lacks verified discovery provenance"
            if params.max_answers > boundary.max_dns_addresses_per_host:
                return "DNS answer limit exceeds task policy"
            return None
        origin = task.scope.web_origin
        derived = (self.tasks.get_binding(task.id, request.target_host, params.scheme, params.port)
                   if request.target_host and hasattr(params, "scheme") and hasattr(params, "port")
                   and hasattr(self.tasks, "get_binding") else None)
        derived_allowed = (derived is not None and derived.address == request.target_ip
                           and request.capability in {Capability.HTTP_FETCH, Capability.HTTP_PROBE, Capability.WHATWEB,
                                                      Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST,
                                                      Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                                                      Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION,
                                                      Capability.WEB_CRAWL, Capability.VHOST_DISCOVERY,
                                                      Capability.PARAMETER_DISCOVERY, Capability.TECHNOLOGY_SCAN})
        if request.target_ip not in task.scope.allowed_ips and not derived_allowed:
            return "target not allowed"
        if origin and not derived_allowed:
            if request.capability not in {Capability.HTTP_FETCH, Capability.HTTP_PROBE, Capability.WHATWEB,
                                          Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST,
                                          Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                                          Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION,
                                          Capability.WEB_CRAWL, Capability.VHOST_DISCOVERY,
                                          Capability.PARAMETER_DISCOVERY, Capability.TECHNOLOGY_SCAN}:
                return "capability has no pinned-origin transport"
            root_transport = (request.target_ip == origin.pinned_ip and request.target_host == origin.host
                              and (params.scheme, params.port) == (origin.scheme, origin.port))
            if task.scope.multi_origin:
                from src.recon.planner import scheme_for_port
                root_transport = (request.target_ip == origin.pinned_ip and request.target_host == origin.host
                                  and params.port in task.scope.allowed_ports
                                  and params.scheme == scheme_for_port(params.port))
            if not root_transport:
                return "web origin binding does not match trusted scope"
        elif request.target_host is not None and not derived_allowed:
            return "hostname has no trusted origin binding"
        if isinstance(params, BoundedWebToolParams):
            timeout = params.timeout_seconds
            if task.execution_budget.max_requests_per_second < 2:
                return "web tool rate exceeds task budget"
            if params.max_body_bytes > task.execution_budget.max_body_bytes:
                return "body size exceeds task budget"
            if not path_allowed(params.path, task.scope.allowed_paths):
                return "path not allowed"
            method = "HEAD" if isinstance(params, VhostDiscoveryParams) else "GET"
            if method not in task.scope.allowed_methods:
                return "method not allowed"
            if isinstance(params, VhostDiscoveryParams):
                boundary = self.tasks.get_authorization(task.id)
                if (boundary is None or boundary.root.kind != "DOMAIN" or not boundary.root.include_subdomains
                        or params.root_domain != boundary.root.value):
                    return "vhost discovery requires a domain root with subdomains authorized"
            if isinstance(params, ParameterDiscoveryParams):
                artifact = self.tasks.get_evidence(params.baseline_evidence_ref)
                result = self.tasks.get_tool_result(artifact.request_id) if artifact else None
                run = self.tasks.get_tool_run(artifact.request_id) if artifact else None
                from src.recon.models import parse_target_request

                source = parse_target_request(run.request_payload) if run and run.request_payload else None
                if (artifact is None or artifact.task_id != task.id or result is None or result.status != "success"
                        or result.evidence_id != artifact.id or result.http_response is None
                        or not 200 <= result.http_response.status_code < 300 or result.http_response.truncated
                        or source is None or source.capability != Capability.HTTP_FETCH
                        or source.parameters.method != "GET" or source.parameters.query
                        or (source.target_ip, source.target_host, source.parameters.scheme,
                            source.parameters.port, source.parameters.path) !=
                           (request.target_ip, request.target_host, params.scheme, params.port, params.path)):
                    return "parameter discovery requires a verified GET baseline at the same endpoint"
            else:
                from src.recon.models import parse_target_request

                origin_verified = False
                for run in self.tasks.list_tool_runs(task.id):
                    source = parse_target_request(run.request_payload) if run.request_payload else None
                    if source is None or source.capability != Capability.HTTP_PROBE:
                        continue
                    result = self.tasks.get_tool_result(source.id)
                    if (result and result.status == "success" and result.evidence_id and result.attack_surface
                            and self.tasks.get_evidence(result.evidence_id)
                            and (source.target_ip, source.target_host, source.parameters.scheme, source.parameters.port) ==
                                (request.target_ip, request.target_host, params.scheme, params.port)):
                        origin_verified = True
                        break
                if not origin_verified:
                    return "web tool requires a verified HTTP origin"
        elif isinstance(params, BrowserExploreParams):
            timeout = params.limits.max_runtime_seconds
        elif isinstance(params, (HttpFetchParams, BrowserRequestParams, GraphqlDiscoveryParams,
                                 GraphqlIntrospectionParams)):
            timeout = params.timeout_seconds
        else:
            timeout = {Capability.HTTP_PROBE: 5, Capability.NMAP_SCAN: 60, Capability.WHATWEB: 20,
                       Capability.CONTENT_DISCOVERY: 20, Capability.EXPOSURE_DISCOVERY: 20}[request.capability]
        if timeout > task.execution_budget.max_timeout_seconds:
            return "timeout exceeds task budget"
        requested_ports = params.ports if hasattr(params, "ports") else (params.port,)
        if any(port not in task.scope.allowed_ports for port in requested_ports):
            return "port not allowed"
        if isinstance(params, ContentDiscoveryParams):
            from src.recon.wordlists import load_wordlist
            if "HEAD" not in task.scope.allowed_methods:
                return "method not allowed"
            if any(not path_allowed(params.path_prefix + word, task.scope.allowed_paths)
                   for word in load_wordlist(params.wordlist_id).entries):
                return "path not allowed"
            if task.execution_budget.max_requests_per_second < 2:
                return "content discovery rate exceeds task budget"
        if request.capability in {Capability.HTTP_PROBE, Capability.WHATWEB}:
            method = "HEAD" if request.capability == Capability.HTTP_PROBE else "GET"
            if method not in task.scope.allowed_methods:
                return "method not allowed"
            if not path_allowed("/", task.scope.allowed_paths):
                return "path not allowed"
        if isinstance(params, (HttpFetchParams, BrowserRequestParams, BrowserExploreParams,
                               GraphqlDiscoveryParams, GraphqlIntrospectionParams)):
            body_limit = params.limits.max_response_bytes if isinstance(params, BrowserExploreParams) else params.max_body_bytes
            if body_limit > task.execution_budget.max_body_bytes:
                return "body size exceeds task budget"
            if isinstance(params, (HttpFetchParams, BrowserRequestParams)) and params.method not in task.scope.allowed_methods:
                return "method not allowed"
            if not path_allowed(params.path, task.scope.allowed_paths):
                return "path not allowed"
        if isinstance(params, GraphqlDiscoveryParams) and "GET" not in task.scope.allowed_methods:
            return "method not allowed"
        if isinstance(params, GraphqlIntrospectionParams):
            artifact = self.tasks.get_evidence(params.discovery_evidence_ref)
            prior = self.tasks.get_tool_result(artifact.request_id) if artifact else None
            from src.recon.urls import request_url

            expected_url = request_url(request.target_ip, params.scheme, params.port, params.path,
                                       target_host=request.target_host)
            if (artifact is None or artifact.task_id != task.id or prior is None
                    or prior.status != "success" or prior.capability != Capability.GRAPHQL_DISCOVERY
                    or prior.evidence_id != artifact.id or not any(
                        obs.kind == "PROTOCOL" and obs.value == expected_url for obs in prior.observations)):
                return "GraphQL endpoint lacks verified discovery evidence"
        if isinstance(params, BrowserExploreParams) and "GET" not in task.scope.allowed_methods:
            return "method not allowed"
        if isinstance(params, BrowserRequestParams) and not request.parent_request_id:
            return "browser request has no parent"
        return None
