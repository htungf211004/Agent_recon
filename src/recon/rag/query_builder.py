"""Only trusted structured state enters a retrieval query."""

import re

from src.recon.rag.models import ReconKnowledgeQuery


def _fact(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9 _./:-]{1,100}", value):
        return "redacted"
    if re.search(r"(?i)(password|secret|token|cookie|authorization|api.?key)", value):
        return "redacted"
    return value


def build_query(context, assets=()) -> ReconKnowledgeQuery:
    return ReconKnowledgeQuery(
        available_capabilities=tuple(context.capabilities)[:32],
        checklist_gaps=tuple(item.id for item in context.checklist if item.status != "COMPLETE")[:16],
        asset_types=tuple(sorted({asset.asset_type.value for asset in assets}))[:16],
        verified_technologies=tuple(_fact(item.technology) for item in context.technologies[:16]),
        verified_services=tuple(_fact(item.service) for item in context.services[:16]),
        route_categories=tuple(sorted({_fact(route.path.split("/")[1][:40]) for route in context.routes
                                       if route.path.startswith("/") and len(route.path) > 1}))[:16],
        limitations=tuple(_fact(item) for item in context.coverage.limitations[:16]),
    )
