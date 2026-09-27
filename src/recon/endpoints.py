"""Endpoint identity, provenance merge, and conservative baseline eligibility."""

from urllib.parse import parse_qsl, urlsplit

from src.recon.web_models import EndpointLifecycle, EndpointParameter, WebEndpointEntry


def merge_endpoints(old: WebEndpointEntry, new: WebEndpointEntry) -> WebEndpointEntry:
    if old.id != new.id:
        raise ValueError("cannot merge different endpoint identities")
    params = {(p.location, p.name): p for p in old.parameters}
    for param in new.parameters:
        key = (param.location, param.name)
        previous = params.get(key)
        if previous:
            data_type = param.data_type if previous.data_type == "unknown" else previous.data_type
            if param.data_type not in {"unknown", data_type}:
                data_type = "unknown"
            param = EndpointParameter(name=param.name, location=param.location,
                                      required=previous.required or param.required, data_type=data_type)
        params[key] = param
    provenance = {p.model_dump_json(): p for p in (*old.provenance, *new.provenance)}
    rank = list(EndpointLifecycle)
    lifecycle = max((old.lifecycle, new.lifecycle), key=rank.index)
    manual = old.requires_manual_input or new.requires_manual_input
    merged = old.model_dump()
    merged.update(
        parameters=tuple(params[key] for key in sorted(params)),
        provenance=tuple(provenance[key] for key in sorted(provenance)),
        evidence_ids=tuple(sorted(set(old.evidence_ids + new.evidence_ids))),
        baseline_id=old.baseline_id or new.baseline_id,
        requires_manual_input=manual,
        lifecycle=EndpointLifecycle.BASELINED if lifecycle == EndpointLifecycle.FUZZ_READY else lifecycle,
    )
    endpoint = WebEndpointEntry.model_validate(merged)
    if endpoint.baseline_id:
        endpoint = endpoint.model_copy(update={
            "lifecycle": EndpointLifecycle.FUZZ_READY if fuzz_ready(endpoint) else EndpointLifecycle.BASELINED,
        })
    return endpoint


def baseline_eligible(endpoint: WebEndpointEntry) -> bool:
    if endpoint.method not in {"GET", "HEAD"} or endpoint.requires_manual_input:
        return False
    if any(char in endpoint.url for char in "{}"):
        return False
    query = dict(parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True))
    for param in endpoint.parameters:
        if param.location in {"body", "formData"}:
            return False
        if param.required and (param.location != "query" or not query.get(param.name)):
            return False
    return True


def fuzz_ready(endpoint: WebEndpointEntry) -> bool:
    """Readiness describes a recorded baseline, and never dispatches fuzzing."""
    query = dict(parse_qsl(urlsplit(endpoint.url).query, keep_blank_values=True))
    return bool(endpoint.baseline_id and endpoint.evidence_ids and baseline_eligible(endpoint)
                and endpoint.parameters and all(p.location == "query" and p.name in query for p in endpoint.parameters))
