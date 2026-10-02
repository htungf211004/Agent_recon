"""Evidence and availability driven PT_01 coverage projection."""

from dataclasses import dataclass

from src.contracts.recon_planning import ChecklistSummary
from src.recon.checklist_v2 import project_checklist_v2
from src.recon.models import Capability

VERSION = "recon-checklist-v3"


@dataclass(frozen=True)
class ChecklistItemV3:
    id: str
    mode: str
    capabilities: tuple[Capability, ...]
    providers: tuple[str, ...] = ()


ITEMS = (
    ChecklistItemV3("PT_01-STT-01", "AUTO", (Capability.PASSIVE_SUBDOMAIN_ENUM,
                    Capability.PASSIVE_INFRA_ENUM, Capability.HISTORICAL_URL_DISCOVERY,
                    Capability.WHOIS_RDAP_LOOKUP)),
    ChecklistItemV3("PT_01-STT-02", "AUTO_CONFIGURABLE", (Capability.NMAP_SCAN,
                    Capability.CONTENT_DISCOVERY, Capability.WEB_CRAWL, Capability.VHOST_DISCOVERY,
                    Capability.PARAMETER_DISCOVERY)),
    ChecklistItemV3("PT_01-STT-03", "AUTO", (Capability.WHATWEB, Capability.TECHNOLOGY_SCAN)),
    ChecklistItemV3("PT_01-STT-04", "AUTO", (Capability.HTTP_FETCH,)),
    ChecklistItemV3("PT_01-STT-05", "AUTO", (Capability.HTTP_FETCH,)),
    ChecklistItemV3("PT_01-STT-06", "AUTO", (Capability.HTTP_FETCH,)),
    ChecklistItemV3("PT_01-STT-07", "DISCOVERY_ONLY", (Capability.HTTP_FETCH,
                    Capability.CONTENT_DISCOVERY)),
    ChecklistItemV3("PT_01-STT-08", "AUTO_CONFIGURABLE", (Capability.GRAPHQL_DISCOVERY,
                    Capability.GRAPHQL_INTROSPECTION)),
    ChecklistItemV3("PT_01-STT-09", "DISCOVERY_ONLY", (Capability.WSDL_DISCOVERY,)),
    ChecklistItemV3("PT_01-STT-10", "DISCOVERY_ONLY", (Capability.EXPOSURE_DISCOVERY,)),
    ChecklistItemV3("PT_01-STT-11", "AUTO", (Capability.CONTENT_DISCOVERY, Capability.WEB_CRAWL)),
    ChecklistItemV3("PT_01-STT-12", "DISCOVERY_ONLY", (Capability.EXPOSURE_DISCOVERY,)),
    ChecklistItemV3("PT_01-STT-13", "DISCOVERY_ONLY", (Capability.SOURCEMAP_ANALYZE,)),
    ChecklistItemV3("PT_01-STT-14", "EXTERNAL_PROVIDER", (Capability.EXTERNAL_ASSET_SEARCH,),
                    ("shodan", "censys", "fofa")),
    ChecklistItemV3("PT_01-STT-15", "EXTERNAL_PROVIDER", (Capability.PUBLIC_CODE_SEARCH,),
                    ("github", "gitlab")),
    ChecklistItemV3("PT_01-STT-16", "EXTERNAL_PROVIDER", (Capability.SEARCH_ENGINE_OSINT,),
                    ("brave",)),
)


def project_checklist_v3(task, repository, service, *, finalize=False) -> tuple[ChecklistSummary, ...]:
    legacy = {item.id: item for item in project_checklist_v2(task, repository, service, finalize=finalize)}
    boundary = repository.get_authorization(task.id) if hasattr(repository, "get_authorization") else None
    domain_root = boundary is not None and boundary.root.kind == "DOMAIN"
    verified = {}
    for result in repository.list_tool_results(task.id):
        if result.status != "success" or not result.evidence_id:
            continue
        try:
            if service.gateway.evidence.read(result.evidence_id) is not None:
                verified.setdefault(result.capability, []).append(result)
        except (ValueError, OSError):
            continue
    from src.recon.models import parse_execution_request

    executed_profiles = set()
    completed_providers = {}
    graphql_paths = set()
    verified_origins = set()
    api_checked_origins = set()
    for run in repository.list_tool_runs(task.id):
        if not run.request_payload:
            continue
        request = parse_execution_request(run.request_payload)
        result = repository.get_tool_result(request.id)
        if result not in verified.get(request.capability, ()):
            continue
        if request.capability == Capability.EXPOSURE_DISCOVERY:
            executed_profiles.add(request.parameters.wordlist_id)
        if request.capability in {Capability.HTTP_PROBE, Capability.CONTENT_DISCOVERY}:
            origin = (request.target_ip, request.target_host, request.parameters.scheme,
                      request.parameters.port)
            if request.capability == Capability.HTTP_PROBE:
                verified_origins.add(origin)
            elif request.parameters.wordlist_id == "api-common-small-v1":
                api_checked_origins.add(origin)
        if request.capability == Capability.GRAPHQL_DISCOVERY:
            graphql_paths.add(request.parameters.path)
        if hasattr(request, "provider"):
            completed_providers.setdefault(request.capability, set()).add(request.provider)
    rows = []
    for item in ITEMS:
        old = legacy[item.id]
        if boundary is not None and not domain_root and item.id in {
                "PT_01-STT-01", "PT_01-STT-14", "PT_01-STT-15", "PT_01-STT-16"}:
            rows.append(ChecklistSummary(id=item.id, status="NOT_APPLICABLE",
                        finding="NOT_TESTED", reason="domain-root intelligence does not apply to an IP root"))
            continue
        required = item.capabilities
        if item.id == "PT_01-STT-02":
            excluded = {Capability.NMAP_SCAN} if domain_root else {Capability.VHOST_DISCOVERY}
            if domain_root and not boundary.root.include_subdomains:
                excluded.add(Capability.VHOST_DISCOVERY)
            if Capability.PARAMETER_DISCOVERY not in task.scope.capabilities:
                excluded.add(Capability.PARAMETER_DISCOVERY)
            required = tuple(cap for cap in required if cap not in excluded)
            if boundary is not None and not domain_root and not verified_origins:
                required = (Capability.NMAP_SCAN,)
        if item.id == "PT_01-STT-11" and boundary is not None and not domain_root and not verified_origins:
            rows.append(ChecklistSummary(id=item.id, status="NOT_APPLICABLE", finding="NOT_TESTED",
                        reason="no verified HTTP origin available for endpoint discovery"))
            continue
        # A new tool must not silently replace required legacy coverage.
        added = tuple(cap for cap in required if cap not in {
            Capability.HTTP_FETCH, Capability.NMAP_SCAN, Capability.CONTENT_DISCOVERY, Capability.WHATWEB})
        missing = [cap for cap in required if cap not in task.scope.capabilities]
        unavailable = [f"{cap.value}:{service.gateway.registry.availability(cap)}" for cap in required
                       if service.gateway.registry.availability(cap) != "AVAILABLE"]
        unavailable += [f"{provider}:{service.gateway.registry.availability(item.capabilities[0], provider)}"
                        for provider in item.providers
                        if service.gateway.registry.availability(item.capabilities[0], provider) != "AVAILABLE"]
        ran = all(cap in verified for cap in required)
        infrastructure_partial = (item.id == "PT_01-STT-01" and
            any(getattr(row, "message", "") == "passive_infra:metadata_unavailable"
                for row in verified.get(Capability.PASSIVE_INFRA_ENUM, ())) and
            not any(obs.kind in {"IP", "METADATA"} for row in verified.get(Capability.PASSIVE_INFRA_ENUM, ())
                    for obs in row.observations))
        if item.providers:
            ran = set(item.providers) <= completed_providers.get(item.capabilities[0], set())
        if item.id == "PT_01-STT-10":
            ran = "backup-small-v2" in executed_profiles
        if item.id == "PT_01-STT-12":
            ran = "scm-small-v1" in executed_profiles
        if item.id == "PT_01-STT-07":
            ran = bool(verified_origins) and verified_origins <= api_checked_origins
        if item.id == "PT_01-STT-08" and Capability.GRAPHQL_DISCOVERY in verified:
            found = any(row.observations for row in verified[Capability.GRAPHQL_DISCOVERY])
            if found and Capability.GRAPHQL_INTROSPECTION in verified:
                status, finding, reason = "COMPLETE", "FOUND", "verified GraphQL discovery and schema evidence"
            elif not found and len(graphql_paths) == 4:
                status, finding, reason = "NOT_APPLICABLE", "NOT_FOUND", "bounded GraphQL paths checked without indicator"
            else:
                status, finding, reason = ("BLOCKED" if finalize else "PENDING"), "NOT_TESTED", \
                    "GraphQL indication needs typed Recon follow-up" if found else "GraphQL paths remain unchecked"
        elif infrastructure_partial and ran:
            status, finding, reason = "MANUAL_REVIEW", "NOT_TESTED", \
                "passive infrastructure profile returned no IP/ASN-capable metadata; provider coverage remains incomplete"
        elif (ran and (item.id not in {"PT_01-STT-02", "PT_01-STT-03", "PT_01-STT-11"}
                       or old.status == "COMPLETE")) or (not added and old.status in {
                           "COMPLETE", "NOT_APPLICABLE", "MANUAL_REVIEW"} and item.id != "PT_01-STT-07"):
            status = "COMPLETE" if ran else old.status
            evidence_results = [row for cap in required for row in verified.get(cap, ())]
            finding = ("FOUND" if any(row.observations for row in evidence_results) else
                       old.finding if old.finding != "NOT_TESTED" else "NOT_FOUND" if ran else "NOT_TESTED")
            reason = "verified capability evidence" if ran else old.reason
            if item.id == "PT_01-STT-02" and domain_root and ran:
                reason = "verified domain web coverage; IP-wide Nmap is not authorized by a domain root"
        elif missing:
            status, finding, reason = "UNSUPPORTED", "NOT_TESTED", "capability outside task scope: " + ", ".join(
                cap.value for cap in missing)
        elif unavailable:
            status, finding, reason = "UNSUPPORTED", "NOT_TESTED", "; ".join(unavailable)
        else:
            status, finding, reason = ("BLOCKED" if finalize else "PENDING"), "NOT_TESTED", \
                "required capability has no verified execution evidence"
        rows.append(ChecklistSummary(id=item.id, status=status, reason=reason, finding=finding))
    return tuple(rows)
