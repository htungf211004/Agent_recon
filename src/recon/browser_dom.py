"""Fixed, bounded DOM reads and projection into the shared endpoint inventory."""

from datetime import UTC, datetime
from urllib.parse import parse_qsl

from src.recon.models import CapabilityRequest, ToolResult
from src.recon.urls import normalize_candidate, request_url
from src.recon.web_models import (
    DiscoveryKind,
    EndpointLifecycle,
    EndpointObservation,
    EndpointParameter,
    EndpointProvenance,
    WebEndpointEntry,
    stable_id,
)

INVENTORY_RESOURCE_TYPES = frozenset({"document", "xhr", "fetch"})

# Runs in a fresh isolated world: page code cannot replace these DOM accessors.
# No caller supplied expression, field values, clicks or form submissions.
DOM_EXPRESSION = """(() => {
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 128)
    .filter(a => !a.hasAttribute('download'))
    .map(a => ({url: a.href.slice(0, 4096), method: 'GET', relation: 'anchor', fields: []}));
  const forms = Array.from(document.forms).slice(0, 32).map(f => ({
    url: f.action.slice(0, 4096), method: f.method.toUpperCase(), relation: 'form',
    fields: Array.from(f.elements).slice(0, 64).filter(e => e.name && !e.disabled)
      .map(e => ({name: e.name.slice(0, 256), required: !!e.required}))
  }));
  return links.concat(forms);
})()"""


def extract_dom(session, timeout_ms: int) -> list[dict]:
    frame = session.send("Page.getFrameTree")["frameTree"]["frame"]["id"]
    world = session.send("Page.createIsolatedWorld", {"frameId": frame, "worldName": "recon-passive-dom"})
    result = session.send("Runtime.evaluate", {
        "expression": DOM_EXPRESSION, "contextId": world["executionContextId"],
        "returnByValue": True, "timeout": timeout_ms,
    })
    if "exceptionDetails" in result:
        raise ValueError("DOM extraction failed")
    value = result["result"].get("value")
    if not isinstance(value, list) or len(value) > 160:
        raise ValueError("invalid DOM observation")
    return value


def project_browser_response(repository, request: CapabilityRequest, result: ToolResult, envelope: dict) -> None:
    """Idempotent projection; preserve earlier verified HTTP baseline observations."""
    if result.status != "success" or not result.evidence_id or not result.http_response:
        return
    params = request.parameters
    if params.resource_type not in INVENTORY_RESOURCE_TYPES:
        return
    url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query, target_host=request.target_host)
    if envelope.get("url") != url or envelope.get("method") != params.method:
        raise ValueError("browser evidence identity mismatch")

    def save(concrete, method, relation, fields=(), observed=False):
        observation_id = stable_id(request.task_id, method, concrete)
        provenance = EndpointProvenance(
            source_id=stable_id(request.task_id, "browser", request.parent_request_id),
            kind=DiscoveryKind.BROWSER, relation=relation, evidence_id=result.evidence_id,
            request_id=request.id, observation_id=observation_id,
        )
        parameters = {(item.location, item.name): item for item in fields}
        for name, _ in parse_qsl(concrete.partition("?")[2], keep_blank_values=True):
            if name and len(name) <= 256:
                parameters.setdefault(("query", name), EndpointParameter(name=name, location="query"))
        endpoint = repository.save_endpoint(WebEndpointEntry(
            task_id=request.task_id, url=concrete, method=method,
            parameters=tuple(parameters[key] for key in sorted(parameters)),
            provenance=(provenance,), requires_manual_input=relation == "form",
            lifecycle=EndpointLifecycle.OBSERVED if observed else EndpointLifecycle.DISCOVERED,
            evidence_ids=(result.evidence_id,),
        ))
        repository.save_observation(EndpointObservation(
            task_id=request.task_id, endpoint_id=endpoint.id, url=concrete, method=method,
            provenance=(provenance,), request_id=request.id if observed else None,
            evidence_id=result.evidence_id if observed else None,
            response=result.http_response if observed else None,
            observed_at=datetime.now(UTC) if observed else None,
        ), preserve_existing_response=True)

    save(url, params.method, "network_request", observed=True)
    for candidate in envelope.get("dom", []):
        concrete = normalize_candidate(candidate["url"], url)
        method, relation = candidate["method"], candidate["relation"]
        if concrete is None or method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}:
            continue
        fields = tuple(EndpointParameter(
            name=item["name"], location="query" if method == "GET" else "formData", required=item["required"],
        ) for item in candidate.get("fields", []))
        save(concrete, method, relation, fields)
