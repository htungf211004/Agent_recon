"""Strict FFUF result projection and separate deterministic HTTP verification."""

import json
from urllib.parse import urlsplit

from src.contracts.recon_assets import AssetRelation
from src.recon.asset_extraction import record_candidate
from src.recon.endpoints import baseline_eligible
from src.recon.models import Capability, HttpFetchParams, ReconPlan
from src.recon.planner import ReconPlanner
from src.recon.urls import canonical_url, path_allowed, request_url, scoped_ip
from src.recon.web_models import (
    DiscoveryKind,
    DiscoverySource,
    EndpointLifecycle,
    EndpointObservation,
    EndpointProvenance,
    WebEndpointEntry,
)
from src.recon.wordlists import load_wordlist


def candidate_urls(request):
    p = request.parameters
    return {request_url(request.target_ip, p.scheme, p.port, p.path_prefix + word, target_host=request.target_host)
            for word in load_wordlist(p.wordlist_id).entries}


def parse_ffuf(raw, request):
    if len(raw) > 262144:
        raise ValueError("FFUF output limit")
    document = json.loads(raw)
    rows = document["results"]
    if not isinstance(rows, list) or len(rows) > load_wordlist(request.parameters.wordlist_id).max_entries:
        raise ValueError("FFUF result limit")
    permitted = candidate_urls(request)
    candidates = {}
    for row in rows:
        if not isinstance(row, dict) or type(row.get("status")) is not int or not 100 <= row["status"] <= 599:
            raise ValueError("invalid FFUF status")
        url = canonical_url(row["url"])
        if url in permitted:
            candidates[url] = {"url": url, "status_code": row["status"]}
    return [candidates[key] for key in sorted(candidates)]


def project_content(repository, service, request):
    result = repository.get_tool_result(request.id)
    if result is None or result.status != "success" or not result.evidence_id:
        return
    task = repository.get_task(request.task_id)
    try:
        envelope = json.loads(service.gateway.evidence.read(result.evidence_id))
        wordlist = load_wordlist(request.parameters.wordlist_id)
        if envelope["wordlist_sha256"] != wordlist.sha256 or envelope["wordlist_id"] != wordlist.id or envelope["method"] != "HEAD":
            return
        candidates = envelope["candidates"]
        if not isinstance(candidates, list) or len(candidates) > wordlist.max_entries:
            return
        permitted = candidate_urls(request)
        for candidate in candidates:
            url = canonical_url(candidate["url"])
            if url not in permitted or not path_allowed(urlsplit(url).path, task.scope.allowed_paths):
                continue
            boundary = repository.get_authorization(task.id)
            if boundary:
                record_candidate(repository, task, boundary, url, result.evidence_id, url,
                                 AssetRelation.CONTENT_DISCOVERY)
            endpoint = WebEndpointEntry(task_id=task.id, url=url)
            if repository.get_endpoint(endpoint.id) is None and len(repository.list_endpoints(task.id)) >= task.discovery_limits.max_endpoints:
                break
            observation = EndpointObservation(task_id=task.id, endpoint_id=endpoint.id, url=url,
                                               request_id=request.id, evidence_id=result.evidence_id)
            provenance = EndpointProvenance(source_id=request.id, kind=DiscoveryKind.SEED, relation="content_discovery",
                evidence_id=result.evidence_id, request_id=request.id, observation_id=observation.id)
            endpoint = endpoint.model_copy(update={"provenance": (provenance,), "evidence_ids": (result.evidence_id,),
                                                   "lifecycle": EndpointLifecycle.OBSERVED})
            repository.save_endpoint(endpoint)
            repository.save_observation(observation.model_copy(update={"provenance": (provenance,)}), preserve_existing_response=True)
            if boundary:
                source = DiscoverySource(task_id=task.id, url=url, depth=1)
                known = repository.list_sources(task.id)
                if not any(item.id == source.id for item in known):
                    if len(known) < task.discovery_limits.max_sources:
                        repository.save_source(source)
                    else:
                        repository.add_limitation(task.id, "discovery:source_limit")
    except (ValueError, OSError, TypeError, KeyError):
        return


def baseline_content(repository, service, task):
    from src.recon.adaptive_projection import project_action

    if Capability.HTTP_FETCH not in task.scope.capabilities or "GET" not in task.scope.allowed_methods:
        return
    actions = []
    for endpoint in repository.list_endpoints(task.id):
        if not any(p.relation == "content_discovery" for p in endpoint.provenance):
            continue
        if not baseline_eligible(endpoint, endpoint.url):
            continue
        url = urlsplit(endpoint.url)
        target_ip = scoped_ip(task.scope, endpoint.url)
        binding = repository.get_binding(task.id, url.hostname, url.scheme, url.port) if target_ip is None else None
        target_ip = target_ip or (binding.address if binding else None)
        if target_ip is None:
            continue
        actions.append(ReconPlanner._action(task, target_ip, Capability.HTTP_FETCH, HttpFetchParams(
            port=url.port, scheme=url.scheme, path=url.path,
            timeout_seconds=min(5, task.execution_budget.max_timeout_seconds), max_body_bytes=task.execution_budget.max_body_bytes),
            target_host=url.hostname if binding else None))
    # Stable HTTP identity also reuses an existing static/adaptive verification; no extra network on restart.
    if actions:
        plan = ReconPlan(task_id=task.id, actions=tuple(actions))
        service.run(plan)
        for action in actions:
            project_action(repository, service, action.request)
