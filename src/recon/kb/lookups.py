"""Non-authoritative reference helpers: no Run scope, findings, or tool intents are accepted."""

from src.contracts.recon_kb import KBModel
from src.recon.kb.adapters import cve_id
from src.recon.models import TechnologyObservation


def kev_enrichment(records, exact_cve_id):
    key = cve_id(exact_cve_id)
    return next((record for record in records if record.dataset == "CISA_KEV" and record.lookup_keys == {"cve_id": key}), None)


def registered_service_reference(records, port, transport):
    return tuple(record for record in records if record.dataset == "IANA_PORTS"
                 and record.value["transport"] == transport
                 and record.value["port_start"] <= port <= record.value["port_end"])


def registrable_domain(records, host, *, include_private=True):
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    labels = host.split(".")
    matches, exceptions = [1], []
    for record in records:
        if record.dataset != "PSL" or (record.value["section"] == "PRIVATE" and not include_private):
            continue
        suffix = record.value["suffix"]
        count = len(suffix.split("."))
        if host != suffix and not host.endswith("." + suffix):
            continue
        kind = record.value["rule_type"]
        if kind == "EXCEPTION":
            exceptions.append(count - 1)
        elif kind == "WILDCARD" and len(labels) > count:
            matches.append(count + 1)
        elif kind == "EXACT":
            matches.append(count)
    suffix_length = max(exceptions) if exceptions else max(matches)
    return ".".join(labels[-suffix_length - 1:]) if len(labels) > suffix_length else None


def cpe_candidates(observation: TechnologyObservation, records):
    if not observation.evidence_id:
        raise ValueError("CPE candidate requires technology evidence")
    # Even an exact text match is a candidate until a separate evidence-backed normalizer proves identity/version.
    return tuple({"cpe_name_id": record.value["cpe_name_id"], "cpe23_uri": record.value["cpe23_uri"],
                  "match_status": "CANDIDATE", "evidence_ref": observation.evidence_id}
                 for record in records if record.dataset == "NVD_CPE" and not record.value["deprecated"]
                 and record.value["product"].replace("_", " ").casefold() in observation.name.casefold())


class RuntimeTechnologyMetadata(KBModel):
    technology: str
    categories: tuple[str, ...]
    cpe_candidate: str | None = None
    confidence: str = "DETECTED"
    evidence_ref: str


def wappalyzer_runtime_metadata(observation: TechnologyObservation, *, categories=()):
    if not observation.evidence_id:
        raise ValueError("runtime technology requires evidence")
    return RuntimeTechnologyMetadata(technology=observation.name, categories=categories,
                                     evidence_ref=observation.evidence_id)
