"""Bounded summaries only: never raw evidence, HTML, cookies, headers or query values."""

import json
import re
from urllib.parse import urljoin, urlsplit

from src.contracts.recon_planning import (
    PlanningAction,
    PlanningAsset,
    PlanningBudget,
    PlanningCoverage,
    PlanningProgress,
    PlanningRedirect,
    PlanningRoute,
    PlanningScope,
    PlanningService,
    PlanningTechnology,
    ReconPlanningContext,
)
from src.recon.checklist import project_checklist
from src.recon.checklist_v3 import VERSION as CHECKLIST_V3_VERSION
from src.recon.checklist_v3 import project_checklist_v3
from src.recon.models import Capability
from src.recon.rag.models import KnowledgeReference
from src.recon.rag.query_builder import build_query
from src.recon.rag.retriever import NoopKnowledgeRetriever
from src.recon.urls import canonical_url, known_transport_ip, path_allowed, scoped_ip
from src.recon.wordlists import TRUSTED


def safe_fact(value):
    # Facts are identifiers, never arbitrary banners. Drop suspicious long tokens/assignments.
    if len(value) > 100 or not re.fullmatch(r"[A-Za-z0-9 ._+/():-]{0,100}", value):
        return "unknown"
    if re.search(r"(?i)(bearer|cookie|password|secret|api.?key|authorization|sk-|AIza)", value):
        return "redacted"
    return value


def planning_route(entry, task, repository, evidence):
    route = repository.get_endpoint(entry.id)
    observations = [o for o in repository.list_observations(task.id) if o.endpoint_id == entry.id and o.evidence_verified]
    observations.sort(key=lambda o: (o.observed_at.isoformat() if o.observed_at else "", o.id))
    latest = observations[-1] if observations else None
    status = latest.response.status_code if latest and latest.response else None
    redirect = PlanningRedirect()
    if latest and latest.evidence_id and status and 300 <= status < 400:
        try:
            location = json.loads(evidence.read(latest.evidence_id)).get("location", "")
            if location:
                target = urlsplit(canonical_url(urljoin(latest.url, location)))
                known_ip = known_transport_ip(task.scope, target.geturl())
                allowed = (scoped_ip(task.scope, target.geturl()) is not None
                           and path_allowed(target.path, task.scope.allowed_paths))
                redirect = PlanningRedirect(present=True, target_scheme=target.scheme, target_port=target.port,
                    same_target_ip=known_ip == entry.resolved_ip, scope_status="IN_SCOPE" if allowed else "OUT_OF_SCOPE")
        except (ValueError, TypeError, KeyError, OSError):
            redirect = PlanningRedirect(present=True, scope_status="INVALID")
    blocker = None
    if not entry.has_verified_baseline:
        blocker = ("MANUAL_INPUT" if route.requires_manual_input else "REQUIRED_INPUT" if entry.has_unresolved_required_input
                   else "NO_RESPONSE" if status is None else "NON_2XX" if not 200 <= status < 300
                   else "TRUNCATED" if latest.response.truncated else "NO_VERIFIED_BASELINE")
    return PlanningRoute(method=entry.method, path=entry.canonical_path,
        origin=f"{entry.scheme}://{entry.authority}", status=entry.status,
        parameters=tuple(p.name[:80] for p in entry.parameters[:16]), last_status_code=status,
        baseline_verified=entry.has_verified_baseline, baseline_blocker=blocker, redirect=redirect,
        requires_manual_input=route.requires_manual_input, required_inputs=entry.has_unresolved_required_input)


def assemble_context(task, repository, service, limits, round_number, actions_used, retriever=None):
    result = service.snapshot(task.id)
    entries = result.attack_surface_inventory.entries
    available = set(service.gateway.registry.available_capabilities()) & set(task.scope.capabilities)
    available.discard(Capability.BROWSER_REQUEST)
    if Capability.BROWSER_REQUEST not in task.scope.capabilities:
        available.discard(Capability.BROWSER_EXPLORE)
    verified_facts = set()
    for item in result.tool_results:
        if item.status == "success" and item.evidence_id:
            try:
                service.gateway.evidence.read(item.evidence_id)
                verified_facts.add(item.evidence_id)
            except (ValueError, OSError):
                pass
    previous = []
    for run in repository.list_tool_runs(task.id):
        if not run.request_payload:
            continue
        from src.recon.models import parse_target_request

        request = parse_target_request(run.request_payload)
        if request is None:
            continue
        params = request.parameters
        previous.append(PlanningAction(request_id=request.id, capability=request.capability.value,
            target_ip=request.target_ip, port=getattr(params, "port", None), method=getattr(params, "method", None),
            path=getattr(params, "path", None), status=run.state.value))
    context = ReconPlanningContext(
        task_id=task.id, run_id=task.run_id, planning_round=round_number,
        planning=PlanningProgress(current_round=round_number, max_rounds=limits.max_llm_rounds,
                                  future_rounds_remaining=max(0, limits.max_llm_rounds - round_number)),
        scope=PlanningScope(targets=tuple(sorted(task.scope.allowed_ips)), ports=tuple(sorted(task.scope.allowed_ports)),
                            allowed_paths=task.scope.allowed_paths, allowed_methods=task.scope.allowed_methods,
                            capabilities=tuple(sorted(task.scope.capabilities)), scope_version=task.scope_version,
                            policy_version=task.policy_version),
        capabilities=tuple(sorted(available)),
        available_actions=tuple(action for cap, action in ((Capability.HTTP_FETCH, "safe_http_probe"),
            (Capability.BROWSER_EXPLORE, "browser_explore"), (Capability.CONTENT_DISCOVERY, "content_discovery"))
            if cap in available) + ("stop",),
        checklist_version=CHECKLIST_V3_VERSION if repository.get_authorization(task.id) else "recon-checklist-v1",
        checklist=tuple(item.model_copy(update={"reason": item.reason[:48]}) for item in
                        project_checklist_v3(task, repository, service)) if repository.get_authorization(task.id)
                  else project_checklist(task, repository, service),
        trusted_wordlists=tuple(sorted(TRUSTED)) if Capability.CONTENT_DISCOVERY in available else (),
        coverage=PlanningCoverage(routes=len(entries), observations=len(result.observations),
            fuzz_ready=sum(entry.status == "FUZZ_READY" for entry in entries),
            limitations=tuple(item[:160] for item in result.coverage.limitations[:16]) if result.coverage else (),
            static_status="COMPLETE" if result.coverage and result.coverage.static_complete else "INCOMPLETE",
            browser_status="COMPLETE" if result.coverage and result.coverage.browser_complete else "INCOMPLETE"),
        services=tuple(PlanningService(target_ip=e.target_ip, port=e.port, protocol=e.protocol,
            service=safe_fact(e.service.lower()), version=safe_fact(e.version), evidence_ref=e.evidence_id)
            for e in result.attack_surface[:32] if e.evidence_id in verified_facts),
        technologies=tuple(PlanningTechnology(technology=safe_fact(e.name), version=safe_fact(e.version),
            source=e.source.value, evidence_ref=e.evidence_id) for e in result.technologies[:32] if e.evidence_id in verified_facts),
        assets=tuple(PlanningAsset(asset_id=a.id, asset_type=a.asset_type.value, value=a.canonical_value[:200],
                                   scope_status=a.scope_status.value, verification_status=a.verification_status.value)
                     for a in repository.list_assets(task.id)[:64]),
        routes=tuple(planning_route(entry, task, repository, service.gateway.evidence)
                     for entry in sorted(entries, key=lambda e: e.id)[:64]),
        previous_actions=tuple(previous[-64:]),
        remaining_budget=PlanningBudget(requests=max(0, task.execution_budget.max_requests - repository.budget_usage(task.id)),
            actions=max(0, limits.max_total_llm_actions - actions_used)),
        context_truncated=len(entries) > 64 or len(previous) > 64,
    )
    retriever = retriever or NoopKnowledgeRetriever()
    query = build_query(context, repository.list_assets(task.id))
    chunks = tuple(retriever.retrieve(query, limit=4))[:4]
    context = context.model_copy(update={
        "knowledge_query": query,
        "knowledge_refs": tuple(KnowledgeReference(knowledge_id=chunk.knowledge_id, source_id=chunk.source_id,
                                                     content_hash=chunk.content_hash, namespace=chunk.namespace)
                                for chunk in chunks),
        "knowledge_excerpts": tuple(chunk.excerpt for chunk in chunks),
        "retriever_id": retriever.implementation_id,
    })
    for field in ("knowledge_excerpts", "knowledge_refs", "assets", "previous_actions", "routes", "services", "technologies"):
        while len(context.model_dump_json().encode()) > limits.max_context_bytes and getattr(context, field):
            context = context.model_copy(update={field: getattr(context, field)[:-1], "context_truncated": True})
    if len(context.model_dump_json().encode()) > limits.max_context_bytes:
        raise ValueError("scope exceeds planning context limit")
    return context
