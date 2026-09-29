"""Bounded summaries only: never raw evidence, HTML, cookies, headers or query values."""

from src.contracts.recon_planning import (
    PlanningAction,
    PlanningBudget,
    PlanningCoverage,
    PlanningRoute,
    PlanningScope,
    ReconPlanningContext,
)
from src.recon.models import Capability, CapabilityRequest


def assemble_context(task, repository, service, limits, round_number, actions_used):
    result = service.snapshot(task.id)
    entries = result.attack_surface_inventory.entries
    available = set(service.gateway.registry.available_capabilities()) & set(task.scope.capabilities)
    available.discard(Capability.BROWSER_REQUEST)
    previous = []
    for run in repository.list_tool_runs(task.id):
        if not run.request_payload:
            continue
        request = CapabilityRequest.model_validate_json(run.request_payload)
        params = request.parameters
        previous.append(PlanningAction(request_id=request.id, capability=request.capability.value,
            target_ip=request.target_ip, port=getattr(params, "port", None), method=getattr(params, "method", None),
            path=getattr(params, "path", None), status=run.state.value))
    context = ReconPlanningContext(
        task_id=task.id, run_id=task.run_id, planning_round=round_number,
        scope=PlanningScope(targets=tuple(sorted(task.scope.allowed_ips)), ports=tuple(sorted(task.scope.allowed_ports)),
                            allowed_paths=task.scope.allowed_paths, allowed_methods=task.scope.allowed_methods),
        capabilities=tuple(sorted(available)),
        coverage=PlanningCoverage(routes=len(entries), observations=len(result.observations),
            fuzz_ready=sum(entry.status == "FUZZ_READY" for entry in entries),
            limitations=tuple(item[:160] for item in result.coverage.limitations[:16]) if result.coverage else ()),
        services=tuple(sorted({f"{entry.target_ip}:{entry.port} {entry.service[:80]}" for entry in result.attack_surface})[:32]),
        technologies=tuple(sorted({entry.name[:80] for entry in result.technologies})[:32]),
        routes=tuple(PlanningRoute(method=entry.method, path=entry.canonical_path,
            origin=f"{entry.scheme}://{entry.authority}", status=entry.status,
            parameters=tuple(p.name[:80] for p in entry.parameters[:16])) for entry in sorted(entries, key=lambda e: e.id)[:64]),
        previous_actions=tuple(previous[-64:]),
        remaining_budget=PlanningBudget(requests=max(0, task.execution_budget.max_requests - repository.budget_usage(task.id)),
            planning_rounds=max(0, limits.max_llm_rounds - round_number),
            actions=max(0, limits.max_total_llm_actions - actions_used)),
        context_truncated=len(entries) > 64 or len(previous) > 64,
    )
    for field in ("previous_actions", "routes", "services", "technologies"):
        while len(context.model_dump_json().encode()) > limits.max_context_bytes and getattr(context, field):
            context = context.model_copy(update={field: getattr(context, field)[:-1], "context_truncated": True})
    if len(context.model_dump_json().encode()) > limits.max_context_bytes:
        raise ValueError("scope exceeds planning context limit")
    return context
