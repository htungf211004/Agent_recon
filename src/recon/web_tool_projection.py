"""Project normalized CLI discoveries without trusting them as verified endpoints."""

import json
from urllib.parse import urlsplit

from src.contracts.recon_assets import AssetRelation
from src.recon.asset_extraction import record_candidate
from src.recon.models import Capability, ReconObservation
from src.recon.urls import path_allowed, request_url
from src.recon.web_models import DiscoverySource


def project_web_tool(repository, service, request):
    result = repository.get_tool_result(request.id)
    boundary = repository.get_authorization(request.task_id)
    if not result or result.status != "success" or not result.evidence_id or not boundary:
        return
    task = repository.get_task(request.task_id)
    base = request_url(request.target_ip, request.parameters.scheme, request.parameters.port,
                       request.parameters.path, target_host=request.target_host)
    try:
        envelope = json.loads(service.gateway.evidence.read(result.evidence_id))
        rows = tuple(ReconObservation.model_validate(row) for row in envelope["observations"])
        expected = tuple(row.model_copy(update={"evidence_id": ""}) for row in result.observations)
        if rows != expected:
            return
        for row in rows:
            value = row.value
            if row.kind == "HOST" and request.capability == Capability.VHOST_DISCOVERY:
                value = f"{request.parameters.scheme}://{value}:{request.parameters.port}/"
            elif row.kind != "URL" or request.capability != Capability.WEB_CRAWL:
                continue
            record_candidate(repository, task, boundary, base, result.evidence_id, value,
                             AssetRelation.OTHER_REFERENCE)
            if row.kind == "URL" and urlsplit(value).netloc == urlsplit(base).netloc:
                if not path_allowed(urlsplit(value).path, task.scope.allowed_paths):
                    continue
                source = DiscoverySource(task_id=task.id, url=value, depth=1)
                known = repository.list_sources(task.id)
                if not any(item.id == source.id for item in known):
                    if len(known) < task.discovery_limits.max_sources:
                        repository.save_source(source)
                    else:
                        repository.add_limitation(task.id, "discovery:source_limit")
    except (ValueError, KeyError, TypeError, OSError):
        return
