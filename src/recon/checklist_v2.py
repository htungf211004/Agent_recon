"""PT_01 STT 1–16, with evidence-driven status and explicit adapter gaps."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from src.contracts.recon_planning import ChecklistSummary
from src.recon.models import Capability


class ChecklistItemV2(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    stt: int
    title: str
    mode: Literal["AUTO", "DISCOVERY_ONLY", "MANUAL_HITL", "UNSUPPORTED_ADAPTER"]


VERSION = "recon-checklist-v2"
ITEMS = tuple(ChecklistItemV2(id=f"PT_01-STT-{number:02d}", stt=number, title=title, mode=mode)
              for number, title, mode in (
                  (1, "Passive Recon", "UNSUPPORTED_ADAPTER"),
                  (2, "Active Recon", "AUTO"),
                  (3, "Fingerprinting", "AUTO"),
                  (4, "Robots.txt", "AUTO"),
                  (5, "Sitemap.xml", "AUTO"),
                  (6, ".well-known", "AUTO"),
                  (7, "Swagger/OpenAPI", "DISCOVERY_ONLY"),
                  (8, "GraphQL", "MANUAL_HITL"),
                  (9, "WSDL", "MANUAL_HITL"),
                  (10, "Backup Files", "DISCOVERY_ONLY"),
                  (11, "Hidden Endpoints", "AUTO"),
                  (12, "Git/SCM Exposure", "DISCOVERY_ONLY"),
                  (13, "Source Map Files", "DISCOVERY_ONLY"),
                  (14, "Shodan/FOFA/Censys", "UNSUPPORTED_ADAPTER"),
                  (15, "GitHub/GitLab Leak", "UNSUPPORTED_ADAPTER"),
                  (16, "Google Dorking", "UNSUPPORTED_ADAPTER"),
              ))


def project_checklist_v2(task, repository, service, *, finalize=False) -> tuple[ChecklistSummary, ...]:
    sources = repository.list_sources(task.id)
    assets = repository.list_assets(task.id)
    results = repository.list_tool_results(task.id)
    verified = []
    for result in results:
        if result.status == "success" and result.evidence_id:
            try:
                service.gateway.evidence.read(result.evidence_id)
                verified.append(result)
            except (ValueError, OSError):
                pass
    verified_refs = {result.evidence_id for result in verified}
    def source_done(path):
        return any(source.url.split("?", 1)[0].endswith(path) and source.evidence_id in verified_refs
                   and source.status in {"PARSED", "UNAVAILABLE"} for source in sources)
    def asset_done(*suffixes):
        return any(asset.canonical_value.lower().endswith(suffixes)
                   and asset.verification_status == "VERIFIED"
                   and any(ref in verified_refs for ref in asset.verification_evidence_refs) for asset in assets)
    def attempted(*suffixes):
        return any(source.url.lower().split("?", 1)[0].endswith(suffixes)
                   and source.evidence_id in verified_refs and source.status in {"PARSED", "UNAVAILABLE"}
                   for source in sources) or any(
                   asset.canonical_value.lower().split("?", 1)[0].endswith(suffixes)
                   and any(ref in verified_refs for ref in asset.verification_evidence_refs)
                   and asset.verification_status in {"VERIFIED", "UNREACHABLE"}
                   for asset in assets)
    statuses = []
    for item in ITEMS:
        finding = "NOT_TESTED"
        if item.mode == "UNSUPPORTED_ADAPTER":
            status, reason = "UNSUPPORTED", "external provider adapter unavailable"
        elif item.stt == 11 and task.scope.web_origin is None and service.gateway is not None and not getattr(
                service.gateway.registry.get(Capability.CONTENT_DISCOVERY), "ip_available", True):
            status, reason = "UNSUPPORTED", "FFUF adapter unavailable for IP transport"
        elif item.mode == "MANUAL_HITL":
            suffix = "/graphql" if item.stt == 8 else ".wsdl"
            if asset_done(suffix):
                status, reason, finding = "MANUAL_REVIEW", "verified API surface; active testing requires review", "FOUND"
            elif attempted(suffix):
                status, reason, finding = "NOT_APPLICABLE", "bounded candidate returned no API surface", "NOT_FOUND"
            else:
                status, reason = ("BLOCKED", "candidate was not checked") if finalize else ("PENDING", "candidate check remains")
        else:
            done = {
                2: any(result.capability in {Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.HTTP_FETCH}
                       for result in verified),
                3: any(result.capability in {Capability.WHATWEB, Capability.HTTP_PROBE} for result in verified),
                4: source_done("/robots.txt"),
                5: source_done("/sitemap.xml"),
                6: all(source_done(path) for path in ("/.well-known/security.txt",
                                                       "/.well-known/openid-configuration",
                                                       "/.well-known/jwks.json")),
                7: any(source.kind == "OPENAPI" and source.status == "PARSED"
                       and source.evidence_id in verified_refs for source in sources),
                10: asset_done(".zip", ".tar", ".gz", ".sql", ".bak"),
                11: any(result.capability == Capability.CONTENT_DISCOVERY for result in verified),
                12: asset_done("/.git/head"),
                13: asset_done(".map"),
            }.get(item.stt, False)
            candidate_suffixes = {7: ("/openapi.json", "/swagger.json"),
                                  10: (".zip", ".tar", ".gz", ".sql", ".bak"),
                                  12: ("/.git/head",), 13: (".map",)}
            checked = (all(attempted(suffix) for suffix in candidate_suffixes[item.stt]) if item.stt == 7
                       else attempted(*candidate_suffixes[item.stt]) if item.stt in candidate_suffixes else False)
            if done:
                status, reason, finding = "COMPLETE", "verified Recon evidence", "FOUND" if item.stt in candidate_suffixes else "NOT_TESTED"
            elif checked:
                status, reason, finding = "COMPLETE", "bounded candidate checked without finding", "NOT_FOUND"
            elif item.stt == 13 and finalize and not any(asset.canonical_value.lower().endswith(".js") for asset in assets):
                status, reason = "NOT_APPLICABLE", "no JavaScript asset found for source map check"
            elif finalize:
                status, reason = "BLOCKED", "bounded run ended without qualifying evidence"
            else:
                status, reason = "PENDING", "qualifying evidence or bounded attempt remains"
        statuses.append(ChecklistSummary(id=item.id, status=status, reason=reason, finding=finding))
    return tuple(statuses)
