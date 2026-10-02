"""Only trusted structured state enters a retrieval query."""

import re

from src.contracts.execution import Risk
from src.recon.rag.models import ReconKnowledgeQuery

GAP_CATEGORIES = {
    "PT_01-STT-01": ("passive_subdomains", "passive_infrastructure", "historical_routes", "domain_dns"),
    "PT_01-STT-02": ("port_service", "http_origin", "bounded_crawl", "virtual_host_candidates"),
    "PT_01-STT-03": ("technology_fingerprint", "technology_cpe_reference"),
    "PT_01-STT-04": ("robots",),
    "PT_01-STT-05": ("sitemap",),
    "PT_01-STT-06": ("well_known",),
    "PT_01-STT-07": ("api_documentation", "openapi_metadata"),
    "PT_01-STT-08": ("graphql_indicator", "graphql_schema_review"),
    "PT_01-STT-09": ("wsdl_soap_indicator",),
    "PT_01-STT-10": ("backup_exposure_indicator",),
    "PT_01-STT-11": ("javascript_routes", "browser_routes", "bounded_crawl", "content_discovery"),
    "PT_01-STT-12": ("git_exposure_indicator",),
    "PT_01-STT-13": ("source_map_reference",),
    "PT_01-STT-14": ("external_asset_references",),
    "PT_01-STT-15": ("public_code_references",),
    "PT_01-STT-16": ("public_search_references",),
}


def _fact(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9 _./:-]{1,100}", value):
        return "redacted"
    if re.search(r"(?i)(password|secret|token|cookie|authorization|api.?key)", value):
        return "redacted"
    return value


def build_query(context, assets=()) -> ReconKnowledgeQuery:
    pending = [item.id for item in context.checklist if item.status == "PENDING"]
    # Route discovery is a mandatory goal and must survive the bounded category window.
    gaps = tuple(sorted(pending, key=lambda item: (item != "PT_01-STT-11", item)))[:16]
    categories = tuple(dict.fromkeys(cat for gap in gaps for cat in GAP_CATEGORIES.get(gap, ())))[:16]
    risk = Risk.R2 if any(tool.risk == "R2" and tool.availability == "AVAILABLE" for tool in context.tools) else (
        Risk.R1 if any(tool.risk == "R1" and tool.availability == "AVAILABLE" for tool in context.tools) else Risk.R0)
    return ReconKnowledgeQuery(
        categories=categories,
        risk_ceiling=risk,
        available_capabilities=tuple(context.capabilities)[:32],
        checklist_gaps=gaps,
        asset_types=tuple(sorted({asset.asset_type.value for asset in assets}))[:16],
        verified_technologies=tuple(_fact(item.technology) for item in context.technologies[:16]),
        verified_services=tuple(_fact(item.service) for item in context.services[:16]),
        route_categories=tuple(sorted({_fact(route.path.split("/")[1][:40]) for route in context.routes
                                       if route.path.startswith("/") and len(route.path) > 1}))[:16],
        limitations=tuple(_fact(item) for item in context.coverage.limitations[:16]),
    )
