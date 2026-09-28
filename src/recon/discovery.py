"""Bounded deterministic discovery rounds. Every fetch is dispatched by ReconService."""

import base64
import hashlib
import json
from collections import Counter
from urllib.parse import parse_qsl, urlsplit
from xml.etree.ElementTree import ParseError

from yaml import YAMLError

from src.recon.discovery_parsers import Candidate, parse_document
from src.recon.endpoints import baseline_eligible, fuzz_ready
from src.recon.models import Capability, ReconTask, ToolResult
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.service import ReconService
from src.recon.storage import ReconRepository
from src.recon.urls import normalize_candidate, request_url, valid_template_path
from src.recon.web_models import (
    BaselineRequest,
    DiscoveryKind,
    DiscoverySource,
    EndpointLifecycle,
    EndpointObservation,
    EndpointParameter,
    EndpointProvenance,
    ReconCoverage,
    SourceStatus,
    WebEndpointEntry,
    stable_id,
)


class EndpointDiscovery:
    def __init__(self, repository: ReconRepository, planner: ReconPlanner, service: ReconService):
        self.repository = repository
        self.planner = planner
        self.service = service
        self.limit_reason = "exhausted"

    def run(self, task: ReconTask):
        self.repository.recover_expired_runs(task.id)
        previous = self.repository.get_coverage(task.id)
        self.limit_reason = previous.stop_reason if previous else "exhausted"
        self._seed(task)
        while True:
            sources = self.repository.list_sources(task.id)
            pending = tuple(source for source in sources if source.status == SourceStatus.PENDING)
            if not pending:
                break
            resumed = tuple(source for source in pending if source.request_id is not None)
            if resumed:
                # Recover already persisted responses before applying network/round budgets.
                for source in resumed:
                    result = self.repository.get_tool_result(source.request_id)
                    if result is None:
                        request = self.planner.fetch_plan(task, (source,)).actions[0].request
                        if request.id != source.request_id:
                            raise RuntimeError("persisted source request identity mismatch")
                        self.service.gateway.execute(request)
                        result = self.repository.get_tool_result(source.request_id)
                    if result is None:
                        self._coverage(task)
                        return self.service.snapshot(task.id)
                    self._process(task, source, result)
                continue
            rounds = self._round_count(task.id)
            used = sum(source.request_id is not None for source in sources)
            remaining = task.discovery_limits.max_requests - used
            if rounds >= task.discovery_limits.max_rounds or remaining <= 0:
                reason = "round_limit" if rounds >= task.discovery_limits.max_rounds else "request_limit"
                self.limit_reason = reason
                for source in pending:
                    self.repository.save_source(source.model_copy(update={"status": SourceStatus.LIMITED, "message": reason}))
                break
            selected = []
            for source in pending:
                endpoint = self.repository.get_endpoint(source.endpoint_id)
                if endpoint is not None and not baseline_eligible(endpoint, source.url):
                    self.repository.save_source(source.model_copy(update={
                        "status": SourceStatus.BLOCKED, "message": "endpoint requires manual input",
                    }))
                elif len(selected) < min(remaining, 16):
                    selected.append(source)
            if not selected:
                continue
            plan = self.planner.fetch_plan(task, tuple(selected))
            by_url = {(source.url, source.method): source for source in selected}
            selected = []
            for action in plan.actions:
                params = action.request.parameters
                url = request_url(action.request.target_ip, params.scheme, params.port, params.path, params.query)
                source = by_url[(url, params.method)].model_copy(update={"request_id": action.request.id})
                self.repository.save_source(source)
                selected.append(source)
            try:
                self.service.run(plan)
            except RuntimeError:
                # Claimed but incomplete requests cannot be retried under a new ID.
                pass
            for source in selected:
                result = self.repository.get_tool_result(source.request_id)
                if result is None:
                    self._coverage(task)
                    return self.service.snapshot(task.id)
                else:
                    self._process(task, source, result)
        self.repository.reconcile_all_templates(task.id)
        self._coverage(task)
        return self.service.snapshot(task.id)

    def _seed(self, task):
        defaults = ("/", "/robots.txt", "/sitemap.xml", "/openapi.json", "/swagger.json")
        for target in sorted(set(task.scope.allowed_ips)):
            for port in sorted(set(task.scope.allowed_ports)):
                base = request_url(target, scheme_for_port(port), port, "/")
                for value in task.discovery_seeds or defaults:
                    url = normalize_candidate(value, base)
                    if url:
                        source = DiscoverySource(task_id=task.id, url=url)
                        self._candidate(task, Candidate(url, relation="seed"), source, depth=0)

    def _candidate(self, task, candidate, source, depth):
        observation_id = stable_id(task.id, candidate.method, candidate.url)
        path = urlsplit(candidate.url).path
        unresolved_path = any(char in path for char in "{}")
        from_openapi = source.kind == DiscoveryKind.OPENAPI and candidate.relation == "operation"
        route_template = path if from_openapi and valid_template_path(path) else None
        route = urlsplit(candidate.url)
        route_url = f"{route.scheme}://{route.netloc}{route_template}" if route_template else candidate.url
        query_params = tuple(EndpointParameter(name=name, location="query", data_type="string")
                             for name, _ in parse_qsl(urlsplit(candidate.url).query, keep_blank_values=True)
                             if 0 < len(name) <= 256)
        endpoint = WebEndpointEntry(
            task_id=task.id, url=route_url, route_template=route_template, method=candidate.method,
            parameters=tuple({(param.location, param.name): param for param in (*query_params, *candidate.parameters)}.values()),
            provenance=(EndpointProvenance(source_id=source.id, kind=source.kind, relation=candidate.relation,
                                           evidence_id=source.evidence_id, request_id=source.request_id,
                                           observation_id=None if unresolved_path else observation_id),),
            requires_manual_input=candidate.manual,
        )
        if self.repository.get_endpoint(endpoint.id) is None and len(self.repository.list_endpoints(task.id)) >= task.discovery_limits.max_endpoints:
            self.limit_reason = "endpoint_limit"
            return
        endpoint = self.repository.save_endpoint(endpoint)
        if not unresolved_path:
            self.repository.save_observation(EndpointObservation(
                task_id=task.id, endpoint_id=endpoint.id, url=candidate.url, method=candidate.method,
                provenance=tuple(p for p in endpoint.provenance if p.observation_id == observation_id),
            ))
        if not baseline_eligible(endpoint, candidate.url):
            return
        known = self.repository.list_sources(task.id)
        if any(item.id == observation_id for item in known):
            return
        if len(known) >= task.discovery_limits.max_sources:
            self.limit_reason = "source_limit"
            return
        status = SourceStatus.PENDING
        if depth > task.discovery_limits.max_depth:
            status = SourceStatus.LIMITED
            self.limit_reason = "depth_limit"
        self.repository.save_source(DiscoverySource(
            task_id=task.id, url=candidate.url, method=endpoint.method, kind=candidate.kind_hint,
            route_template=route_template,
            depth=depth, status=status, message="depth_limit" if status == SourceStatus.LIMITED else "",
        ))

    def _observe(self, source: DiscoverySource, result: ToolResult):
        endpoint = self.repository.get_endpoint(source.endpoint_id)
        if endpoint is None or result.http_response is None or result.evidence_id is None:
            return
        endpoint = endpoint.model_copy(update={
            "lifecycle": EndpointLifecycle.OBSERVED,
            "in_scope": True,
            "evidence_ids": tuple(sorted(set((*endpoint.evidence_ids, result.evidence_id)))),
        })
        provenance = EndpointProvenance(source_id=source.id, kind=source.kind, relation="response",
                                        observation_id=source.id, request_id=result.request_id, evidence_id=result.evidence_id)
        observation = self.repository.save_observation(EndpointObservation(
            task_id=source.task_id, endpoint_id=endpoint.id, url=source.url, method=source.method,
            route_template=source.route_template,
            provenance=(provenance,), request_id=result.request_id, evidence_id=result.evidence_id,
            response=result.http_response, observed_at=result.finished_at, evidence_verified=True,
        ))
        endpoint = endpoint.model_copy(update={"provenance": (*endpoint.provenance, provenance)})
        response = result.http_response
        if result.status == "success" and 200 <= response.status_code < 300 and not response.truncated and baseline_eligible(endpoint, source.url):
            baseline = BaselineRequest(
                task_id=source.task_id, endpoint_id=endpoint.id, request_id=result.request_id,
                url=source.url, method=source.method, evidence_id=result.evidence_id, observation_id=observation.id,
                route_template=source.route_template,
                response=response, observed_at=result.finished_at,
            )
            self.repository.save_baseline(baseline)
            endpoint = endpoint.model_copy(update={"baseline_id": baseline.id, "lifecycle": EndpointLifecycle.BASELINED,
                                                   "baseline_url": source.url, "baseline_verified": True})
            if fuzz_ready(endpoint):
                endpoint = endpoint.model_copy(update={"lifecycle": EndpointLifecycle.FUZZ_READY})
        self.repository.save_endpoint(endpoint)

    def _process(self, task, source, result):
        source = next((item for item in self.repository.list_sources(task.id) if item.id == source.id), source)
        source = source.model_copy(update={"evidence_id": result.evidence_id})
        metadata = result.http_response
        body = b""
        if metadata and result.evidence_id:
            try:
                raw = self.service.gateway.evidence.read(result.evidence_id)
                envelope = json.loads(raw)
                body = base64.b64decode(envelope["body_base64"], validate=True)
                if (hashlib.sha256(body).hexdigest() != metadata.body_sha256 or len(body) != metadata.body_size
                        or envelope["url"] != source.url or envelope["method"] != source.method):
                    raise ValueError("HTTP evidence mismatch")
            except (ValueError, TypeError, KeyError, OSError) as exc:
                self.repository.save_source(source.model_copy(update={
                    "status": SourceStatus.ERROR, "message": f"evidence error: {type(exc).__name__}",
                }))
                return
            self._observe(source, result)
        if result.status == "denied":
            status, message = SourceStatus.BLOCKED, result.message
        elif metadata and metadata.truncated:
            status, message = SourceStatus.LIMITED, result.message
            self.limit_reason = "parser_limit"
        elif result.status != "success" or metadata is None or not result.evidence_id:
            status, message = SourceStatus.ERROR, result.message
        elif not 200 <= metadata.status_code < 300:
            status, message = SourceStatus.UNAVAILABLE, f"HTTP {metadata.status_code}; redirects are not followed"
        else:
            try:
                parsed = parse_document(body.decode("utf-8", errors="replace"), source.url, metadata.content_type, source.kind)
                source = source.model_copy(update={"kind": parsed.kind, "candidate_count": len(parsed.candidates)})
                for candidate in parsed.candidates:
                    self._candidate(task, candidate, source, source.depth + 1)
                status = SourceStatus.LIMITED if parsed.limited else SourceStatus.PARSED
                message = "parser_limit" if parsed.limited else ""
                if parsed.limited:
                    self.limit_reason = "parser_limit"
            except (ValueError, TypeError, KeyError, RecursionError, OSError, ParseError, YAMLError) as exc:
                status, message = SourceStatus.ERROR, f"parser/evidence error: {type(exc).__name__}"
        self.repository.save_source(source.model_copy(update={"status": status, "message": message}))

    def _round_count(self, task_id):
        return sum(any(action.request.capability == Capability.HTTP_FETCH for action in plan.actions)
                   for plan in self.repository.list_plans(task_id))

    def _coverage(self, task):
        sources = self.repository.list_sources(task.id)
        endpoints = self.repository.list_endpoints(task.id)
        counts = dict(Counter(source.status for source in sources))
        converged = self.limit_reason == "exhausted" and not counts.get(SourceStatus.PENDING, 0)
        self.repository.save_coverage(ReconCoverage(
            task_id=task.id, rounds=self._round_count(task.id), requests=sum(source.request_id is not None for source in sources),
            sources=len(sources), source_statuses=counts, endpoints=len(endpoints),
            route_count=len(endpoints), observation_count=len(self.repository.list_observations(task.id)),
            source_count=len(sources), baseline_count=sum(bool(item.baseline_id) for item in endpoints),
            fuzz_ready_count=sum(item.lifecycle == EndpointLifecycle.FUZZ_READY for item in endpoints),
            lifecycle_counts=dict(Counter(endpoint.lifecycle for endpoint in endpoints)),
            converged=converged,
            complete=converged and not any(counts.get(status, 0) for status in (SourceStatus.ERROR, SourceStatus.BLOCKED, SourceStatus.LIMITED)),
            stop_reason=self.limit_reason,
        ))
