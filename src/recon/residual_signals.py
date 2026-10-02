"""Deterministic, evidence-backed work signals for the Recon loop."""

import hashlib
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from src.recon.models import Capability
from src.recon.urls import request_url


class ReconResidualSignal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    signal_id: str
    kind: str
    asset_id: str | None = None
    source_evidence_refs: tuple[str, ...] = ()
    priority: int = Field(ge=1, le=5)
    suggested_capabilities: tuple[str, ...]


def residual_signals(task, repository, service) -> tuple[ReconResidualSignal, ...]:
    available = set(service.gateway.registry.available_capabilities()) & set(task.scope.capabilities)
    signals = {}
    from src.recon.models import parse_execution_request

    attempts = tuple(parse_execution_request(run.request_payload) for run in repository.list_tool_runs(task.id)
                     if run.request_payload)
    fetched_urls = {request_url(request.target_ip, request.parameters.scheme, request.parameters.port,
                                request.parameters.path, request.parameters.query,
                                target_host=request.target_host)
                    for request in attempts if request.capability == Capability.HTTP_FETCH}

    def add(kind, identity, evidence, capabilities, priority=2, asset_id=None):
        supported = tuple(cap.value for cap in capabilities if cap in available)
        if not supported:
            return
        signal_id = hashlib.sha256(f"{task.id}\0{kind}\0{identity}".encode()).hexdigest()[:24]
        signals[signal_id] = ReconResidualSignal(signal_id=signal_id, kind=kind, asset_id=asset_id,
            source_evidence_refs=tuple(evidence)[:4], priority=priority,
            suggested_capabilities=supported)

    for asset in repository.list_assets(task.id):
        if asset.scope_status != "IN_SCOPE":
            continue
        refs = tuple(ref for ref in asset.discovery_evidence_refs if repository.get_evidence(ref))
        if asset.asset_type == "HOST" and asset.relation != "ROOT" and asset.verification_status != "VERIFIED":
            if (not any(row.host == asset.canonical_value for row in repository.list_dns_observations(task.id))
                    and not any(request.capability == Capability.DNS_RESOLVE and
                                request.parameters.host == asset.canonical_value for request in attempts)):
                add("UNVERIFIED_ASSET", asset.id, refs, (Capability.DNS_RESOLVE,), 1, asset.id)
        if asset.asset_type in {"PATH", "API", "DOCUMENT"}:
            path = urlsplit(asset.canonical_value).path.lower()
            observed = any(o.url.split("?", 1)[0] == asset.canonical_value.split("?", 1)[0]
                           and o.evidence_verified and o.evidence_id and repository.get_evidence(o.evidence_id)
                           for o in repository.list_observations(task.id))
            if not observed and asset.canonical_value not in fetched_urls:
                if path.endswith(".map"):
                    add("SOURCE_MAP_REFERENCE", asset.id, refs, (Capability.HTTP_FETCH,), 1, asset.id)
                elif path.endswith(".js"):
                    add("UNPROCESSED_JS", asset.id, refs, (Capability.HTTP_FETCH, Capability.BROWSER_EXPLORE), 2, asset.id)
                elif path.endswith(("openapi.json", "swagger.json", ".wsdl")):
                    add("UNPROCESSED_DOCUMENTATION", asset.id, refs, (Capability.HTTP_FETCH,), 2, asset.id)
                elif path.endswith("/.git/head"):
                    add("SCM_EXPOSURE_INDICATOR", asset.id, refs, (Capability.HTTP_FETCH,), 2, asset.id)
    for endpoint in repository.list_endpoints(task.id):
        if (endpoint.method in {"GET", "HEAD"} and not endpoint.baseline_verified
                and not endpoint.requires_manual_input and endpoint.url not in fetched_urls):
            refs = tuple(ref for ref in endpoint.evidence_ids if repository.get_evidence(ref))
            if refs:
                add("UNBASELINED_ROUTE", endpoint.id, refs, (Capability.HTTP_FETCH,), 2)
    for request in attempts:
        result = repository.get_tool_result(request.id)
        if not result or result.status != "success" or not result.evidence_id:
            continue
        if request.capability == Capability.HTTP_FETCH and request.parameters.path.lower().endswith(".map"):
            if not any(other.capability == Capability.SOURCEMAP_ANALYZE for other in attempts):
                add("UNANALYZED_SOURCE_MAP", result.evidence_id, (result.evidence_id,),
                    (Capability.SOURCEMAP_ANALYZE,), 1)
        if request.capability == Capability.GRAPHQL_DISCOVERY and result.observations:
            if not any(other.capability == Capability.GRAPHQL_INTROSPECTION for other in attempts):
                add("GRAPHQL_INDICATOR", result.evidence_id, (result.evidence_id,),
                    (Capability.GRAPHQL_INTROSPECTION,), 1)
    return tuple(sorted(signals.values(), key=lambda row: (row.priority, row.kind, row.signal_id)))


def may_stop(rows, signals) -> bool:
    from src.recon.coverage_evaluator import score_coverage

    if not rows or signals:
        return False
    score = score_coverage(rows)
    fully_resolved = all(row.status in {"COMPLETE", "NOT_APPLICABLE"} for row in rows)
    return fully_resolved or score.score >= 90 and score.mandatory_resolved
