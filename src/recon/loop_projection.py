"""Project successful Gateway evidence into Recon state without further dispatch."""

import json
from urllib.parse import urlsplit

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.external_osint import ExternalOsintExecutor
from src.recon.models import Capability, CapabilityRequest, DnsResolveParams
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.scope.models import DerivedBinding, DnsObservation
from src.recon.urls import request_url
from src.recon.web_models import DiscoverySource, SourceStatus


def ensure_root_asset(repository, task):
    boundary = repository.get_authorization(task.id)
    if boundary is None:
        return
    repository.upsert_asset(DiscoveredAsset(run_id=task.run_id, task_id=task.id,
        root_target=boundary.root.value,
        asset_type=AssetType.HOST if boundary.root.kind == "DOMAIN" else AssetType.IP,
        canonical_value=boundary.root.value, relation=AssetRelation.ROOT,
        discovered_from="operator", scope_status=AssetScopeStatus.IN_SCOPE,
        verification_status=AssetVerificationStatus.CLASSIFIED))


def normalize_action(repository, service, request):
    result = repository.get_tool_result(request.id)
    if result is None or result.status != "success" or not result.evidence_id:
        return
    try:
        raw = service.gateway.evidence.read(result.evidence_id)
    except (ValueError, OSError):
        return
    task = repository.get_task(request.task_id)
    boundary = repository.get_authorization(task.id)
    if request.capability == Capability.DNS_RESOLVE and isinstance(request.parameters, DnsResolveParams):
        try:
            payload = json.loads(raw)
            observation = DnsObservation(host=payload["host"], addresses=tuple(payload["addresses"]),
                                         evidence_ref=result.evidence_id)
            repository.save_dns_observation(task.id, observation, raw)
            if boundary and observation.addresses and observation.host != boundary.root.value:
                from src.recon.scope.deriver import ScopeDeriver

                if ScopeDeriver(boundary, repository.list_dns_observations(task.id)).classify_host(observation.host) == "IN_SCOPE":
                    address = boundary.root.value if boundary.root.kind == "IP" else observation.addresses[0]
                    for port in task.scope.allowed_ports:
                        scheme = scheme_for_port(port)
                        if repository.get_binding(task.id, observation.host, scheme, port):
                            continue
                        try:
                            repository.save_binding(DerivedBinding(task_id=task.id, host=observation.host,
                                address=address, scheme=scheme, port=port, dns_evidence_ref=result.evidence_id))
                        except ValueError:
                            break
        except (ValueError, TypeError, KeyError):
            return
    elif isinstance(request, CapabilityRequest) and request.capability == Capability.HTTP_FETCH:
        from src.recon.discovery import EndpointDiscovery
        source = DiscoverySource(task_id=task.id, url=request_url(request.target_ip,
            request.parameters.scheme, request.parameters.port, request.parameters.path,
            request.parameters.query, target_host=request.target_host), request_id=request.id)
        existing = next((row for row in repository.list_sources(task.id) if row.id == source.id), None)
        if existing and existing.status not in {SourceStatus.PENDING, SourceStatus.LIMITED}:
            return
        source = (existing or source).model_copy(update={"request_id": request.id, "status": SourceStatus.PENDING})
        repository.save_source(source)
        discovery = EndpointDiscovery(repository, ReconPlanner(), service)
        discovery.verified_origins = None
        discovery.limit_reason = "exhausted"
        discovery._process(task, source, result)
    elif boundary and request.capability in {
            Capability.PASSIVE_SUBDOMAIN_ENUM, Capability.PASSIVE_INFRA_ENUM,
            Capability.HISTORICAL_URL_DISCOVERY, Capability.WHOIS_RDAP_LOOKUP,
            Capability.EXTERNAL_ASSET_SEARCH, Capability.PUBLIC_CODE_SEARCH,
            Capability.SEARCH_ENGINE_OSINT}:
        ExternalOsintExecutor(repository, service.gateway)._project(task, boundary, result)
    if boundary and isinstance(request, CapabilityRequest) and request.capability == Capability.HTTP_PROBE:
        # A root or derived host becomes verified only after intact Gateway evidence.
        for asset in repository.list_assets(task.id):
            host = urlsplit(asset.canonical_value).hostname if "://" in asset.canonical_value else asset.canonical_value
            if asset.scope_status == "IN_SCOPE" and host == (request.target_host or request.target_ip):
                repository.upsert_asset(asset.model_copy(update={
                    "verification_status": AssetVerificationStatus.VERIFIED,
                    "verification_evidence_refs": (result.evidence_id,)}))
