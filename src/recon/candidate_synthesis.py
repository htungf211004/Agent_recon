"""Deterministic Recon synthesis from verified Gateway evidence and inventory."""

import hashlib
import json

from src.contracts.recon_candidates import AttackSurfaceCandidate
from src.recon.models import ReconPlan


def synthesize_candidates(task, result, repository, service, store=()):
    verified = set()
    for item in result.tool_results:
        if item.status != "success" or not item.evidence_id:
            continue
        try:
            service.gateway.evidence.read(item.evidence_id)
            verified.add(item.evidence_id)
        except (ValueError, OSError):
            pass
    assets = repository.list_assets(task.id)
    by_value = {asset.canonical_value.lower(): asset.id for asset in assets}
    root_id = next((asset.id for asset in assets if asset.relation == "ROOT"), None)
    knowledge = {}
    for row in store.rounds(task.id) if store else ():
        if not row["plan"] or not row["context"]:
            continue
        from src.contracts.recon_planning import ReconPlanningContext

        context = ReconPlanningContext.model_validate_json(row["context"])
        refs = tuple(ref.knowledge_id for ref in context.knowledge_refs)
        for action in ReconPlan.model_validate_json(row["plan"]).actions:
            knowledge[action.request.id] = refs
    candidates = {}

    def add(category, asset_id, title, observation, refs, capability, checklist, confidence="MEDIUM", stage="VALIDATION",
            request_id=None):
        refs = tuple(sorted(set(refs) & verified))
        if not refs or not asset_id:
            return
        identity = hashlib.sha256(json.dumps([task.id, category, asset_id, refs], sort_keys=True).encode()).hexdigest()[:24]
        candidates[identity] = AttackSurfaceCandidate(id=identity, category=category, asset_id=asset_id,
            title=title, observation=observation, confidence=confidence,
            verification_status="OBSERVED", evidence_refs=refs,
            knowledge_refs=knowledge.get(request_id, ()), source_capabilities=(capability,),
            checklist_refs=(checklist,), recommended_next_stage=stage)

    for entry in result.attack_surface_inventory.entries:
        good = tuple(obs for obs in entry.observations if obs.response_status and 200 <= obs.response_status < 300
                     and set(obs.evidence_refs) & verified)
        if not good:
            continue
        refs = tuple(ref for obs in good for ref in obs.evidence_refs)
        path = entry.canonical_path.lower()
        asset_id = by_value.get(f"{entry.scheme}://{entry.authority}{entry.canonical_path}".lower(), entry.id)
        request_id = good[0].request_ref
        if path.endswith("/.git/head"):
            add("SCM_EXPOSURE", asset_id, "Git metadata route responds", f"GET {entry.canonical_path} returned HTTP 2xx",
                refs, "http_fetch", "PT_01-STT-12", "MEDIUM", request_id=request_id)
        elif path.endswith((".zip", ".tar", ".gz", ".sql", ".bak")):
            add("BACKUP_FILE_CANDIDATE", asset_id, "Backup-like route responds",
                f"{entry.canonical_path} returned HTTP 2xx", refs, "http_fetch", "PT_01-STT-10",
                request_id=request_id)
        elif path.endswith(("openapi.json", "swagger.json")):
            add("API_DOCUMENTATION", asset_id, "Public API document observed",
                f"{entry.canonical_path} returned HTTP 2xx", refs, "http_fetch", "PT_01-STT-07",
                "HIGH", "FUZZING", request_id=request_id)
        elif path.endswith(".map"):
            add("SOURCE_MAP_REFERENCE", asset_id, "Source map route responds",
                f"{entry.canonical_path} returned HTTP 2xx", refs, "http_fetch", "PT_01-STT-13",
                request_id=request_id)
    for item in result.tool_results:
        if item.evidence_id not in verified:
            continue
        for tech in item.technologies:
            add("TECHNOLOGY_OBSERVATION", root_id, "Technology observed",
                f"{tech.name} {tech.version}".strip(), (item.evidence_id,), item.capability.value,
                "PT_01-STT-03", "MEDIUM", "REVIEW", request_id=item.request_id)
        for obs in item.observations:
            if obs.kind == "PROTOCOL" and "graphql" in obs.value.lower():
                add("GRAPHQL_ENDPOINT", by_value.get(obs.value.lower(), root_id), "GraphQL endpoint observed",
                    "GraphQL protocol indicator returned by typed discovery", (item.evidence_id,),
                    item.capability.value, "PT_01-STT-08", request_id=item.request_id)
    return tuple(sorted(candidates.values(), key=lambda row: (row.category, row.asset_id, row.id)))
