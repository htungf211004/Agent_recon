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
        baseline_url=old.baseline_url if old.baseline_id else new.baseline_url,
        baseline_verified=old.baseline_verified if old.baseline_id else new.baseline_verified,
        in_scope=old.in_scope or new.in_scope,
        is_testable=old.is_testable and new.is_testable,
        requires_manual_input=manual,
        lifecycle=EndpointLifecycle.BASELINED if lifecycle == EndpointLifecycle.FUZZ_READY else lifecycle,
    )
    endpoint = WebEndpointEntry.model_validate(merged)
    if endpoint.baseline_id:
        endpoint = endpoint.model_copy(update={
            "lifecycle": EndpointLifecycle.FUZZ_READY if fuzz_ready(endpoint) else EndpointLifecycle.BASELINED,
        })
    return endpoint


def has_unresolved_required_input(endpoint: WebEndpointEntry, concrete_url: str | None = None) -> bool:
    if any(char in endpoint.url for char in "{}"):
        return True
    query = dict(parse_qsl(urlsplit(concrete_url or endpoint.baseline_url or endpoint.url).query, keep_blank_values=True))
    for param in endpoint.parameters:
        if param.required and (param.location != "query" or not query.get(param.name)):
            return True
    return False


def is_testable(endpoint: WebEndpointEntry) -> bool:
    return bool(endpoint.method in {"GET", "HEAD"} and not endpoint.requires_manual_input and endpoint.is_testable
                and not any(param.location in {"body", "formData"} for param in endpoint.parameters))


def baseline_eligible(endpoint: WebEndpointEntry, concrete_url: str | None = None) -> bool:
    return is_testable(endpoint) and not has_unresolved_required_input(endpoint, concrete_url)


def fuzz_ready(endpoint: WebEndpointEntry) -> bool:
    """Readiness describes a recorded baseline, and never dispatches fuzzing."""
    return bool(endpoint.in_scope and endpoint.baseline_verified and endpoint.baseline_id
                and endpoint.evidence_ids and baseline_eligible(endpoint))
