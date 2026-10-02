"""Existing evidence/endpoint/baseline contracts for adaptive actions, without I/O."""

import base64
import hashlib
import json

from src.recon.browser_dom import project_browser_response
from src.recon.endpoints import baseline_eligible, fuzz_ready
from src.recon.execution import ToolRunState
from src.recon.models import Capability, CapabilityRequest
from src.recon.urls import request_url
from src.recon.web_models import (
    BaselineRequest,
    DiscoveryKind,
    EndpointLifecycle,
    EndpointObservation,
    EndpointProvenance,
    WebEndpointEntry,
)


def project_action(repository, service, request):
    if not isinstance(request, CapabilityRequest):
        return
    result = repository.get_tool_result(request.id)
    run = repository.get_tool_run(request.id)
    if not result or not run or run.state not in {ToolRunState.SUCCEEDED, ToolRunState.FAILED, ToolRunState.TIMED_OUT}:
        return
    if request.capability in {Capability.WEB_CRAWL, Capability.VHOST_DISCOVERY,
                              Capability.PARAMETER_DISCOVERY, Capability.TECHNOLOGY_SCAN}:
        from src.recon.web_tool_projection import project_web_tool
        project_web_tool(repository, service, request)
        return
    if request.capability in {Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY}:
        from src.recon.content_discovery import project_content
        project_content(repository, service, request)
        return
    if request.capability == Capability.BROWSER_EXPLORE:
        if run.state != ToolRunState.SUCCEEDED:
            return
        for child in repository.list_child_runs(request.id):
            child_result = repository.get_tool_result(child.request_id)
            if child.state != ToolRunState.SUCCEEDED or not child_result or not child_result.evidence_id:
                continue
            try:
                raw = service.gateway.evidence.read(child_result.evidence_id)
                project_browser_response(repository, CapabilityRequest.model_validate_json(child.request_payload),
                                         child_result, json.loads(raw))
            except (ValueError, TypeError, OSError):
                continue
        return
    if request.capability != Capability.HTTP_FETCH or not result.evidence_id or not result.http_response:
        return
    params = request.parameters
    url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query, target_host=request.target_host)
    response = result.http_response
    try:
        envelope = json.loads(service.gateway.evidence.read(result.evidence_id))
        body = base64.b64decode(envelope["body_base64"], validate=True)
        if (envelope["url"] != url or envelope["method"] != params.method or envelope["response"] != response.model_dump()
                or len(body) != response.body_size or hashlib.sha256(body).hexdigest() != response.body_sha256):
            return
    except (ValueError, TypeError, KeyError, OSError):
        return
    task = repository.get_task(request.task_id)
    endpoint = WebEndpointEntry(task_id=task.id, url=url, method=params.method)
    if repository.get_endpoint(endpoint.id) is None and len(repository.list_endpoints(task.id)) >= task.discovery_limits.max_endpoints:
        return
    endpoint = repository.save_endpoint(endpoint)
    observation = EndpointObservation(task_id=task.id, endpoint_id=endpoint.id, url=url, method=params.method,
        request_id=request.id, evidence_id=result.evidence_id, response=response,
        observed_at=result.finished_at, evidence_verified=True)
    provenance = EndpointProvenance(source_id=observation.id, kind=DiscoveryKind.SEED, relation="adaptive_response",
        request_id=request.id, evidence_id=result.evidence_id, observation_id=observation.id)
    repository.save_observation(observation.model_copy(update={"provenance": (provenance,)}))
    repository.reconcile_all_templates(task.id)
    observation = next(item for item in repository.list_observations(task.id) if item.id == observation.id)
    endpoint = repository.get_endpoint(observation.endpoint_id)
    endpoint = endpoint.model_copy(update={"provenance": (*endpoint.provenance, provenance),
        "lifecycle": EndpointLifecycle.OBSERVED, "evidence_ids": tuple(sorted(set((*endpoint.evidence_ids, result.evidence_id))))})
    if (result.status == "success" and run.state == ToolRunState.SUCCEEDED
            and endpoint.baseline_id is None and 200 <= response.status_code < 300 and not response.truncated
            and baseline_eligible(endpoint, url)):
        baseline = BaselineRequest(task_id=task.id, endpoint_id=endpoint.id, observation_id=observation.id,
            request_id=request.id, url=url, route_template=endpoint.route_template, method=params.method,
            evidence_id=result.evidence_id, response=response, observed_at=result.finished_at)
        repository.save_baseline(baseline)
        endpoint = endpoint.model_copy(update={"baseline_id": baseline.id, "baseline_url": url,
            "baseline_verified": True, "in_scope": True, "lifecycle": EndpointLifecycle.BASELINED})
        if fuzz_ready(endpoint):
            endpoint = endpoint.model_copy(update={"lifecycle": EndpointLifecycle.FUZZ_READY})
    repository.save_endpoint(endpoint)
