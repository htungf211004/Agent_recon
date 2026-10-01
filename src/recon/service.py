"""Runs a typed Recon plan and records its combined observations."""

from __future__ import annotations

import json
from collections import Counter

from src.recon.gateway import ToolExecutionGateway
from src.recon.handoff import build_inventory
from src.recon.models import Capability, ReconPlan, ReconResult
from src.recon.storage import ReconRepository
from src.recon.web_models import EndpointLifecycle, ReconCoverage, SourceStatus


class ReconService:
    def __init__(self, repository: ReconRepository, gateway: ToolExecutionGateway) -> None:
        self.repository = repository
        self.gateway = gateway

    def run(self, plan: ReconPlan) -> ReconResult:
        task = self.repository.get_task(plan.task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        self.repository.save_plan(plan)
        for action in plan.actions:
            result = self.gateway.execute(action.request)
            if self.repository.get_tool_result(result.request_id) is None:
                # An in-flight claim is not a completed round or a durable tool result.
                raise RuntimeError("Recon round has an incomplete request")
        return self.snapshot(task.id)

    def snapshot(self, task_id: str) -> ReconResult:
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        if not any(source.status == SourceStatus.PENDING for source in self.repository.list_sources(task_id)):
            self.repository.reconcile_all_templates(task_id)
        results = self.repository.list_tool_results(task_id)
        inventory = build_inventory(task, self.repository, self.gateway.evidence)
        endpoints = self.repository.list_endpoints(task_id)
        coverage = self.repository.get_coverage(task_id)
        with self.repository._connect() as connection:
            session = connection.execute("SELECT stop_reason FROM recon_planning_sessions WHERE task_id = ?", (task.id,)).fetchone()
        if coverage is None and session:
            coverage = ReconCoverage(task_id=task.id)
        if coverage is None and Capability.BROWSER_EXPLORE in task.scope.capabilities:
            static_enabled = Capability.HTTP_FETCH in task.scope.capabilities
            coverage = ReconCoverage(task_id=task_id, converged=not static_enabled, complete=not static_enabled)
        if coverage is not None:
            if session and session[0] in {"model_error", "model_outcome_unknown", "context_limit"}:
                coverage = coverage.model_copy(update={"limitations": tuple(sorted(set((*coverage.limitations, "adaptive:" + session[0]))))})
            coverage = coverage.model_copy(update={
                **self._browser_coverage(task, coverage, results),
                "route_count": len(endpoints), "endpoints": len(endpoints),
                "observation_count": len(self.repository.list_observations(task_id)),
                "baseline_count": sum(entry.baseline_verified for entry in endpoints),
                "fuzz_ready_count": sum(entry.lifecycle == EndpointLifecycle.FUZZ_READY for entry in endpoints),
                "lifecycle_counts": dict(Counter(entry.lifecycle for entry in endpoints)),
                "runtime_attempts": self.repository.budget_usage(task_id),
            })
            self.repository.save_coverage(coverage)
        result = ReconResult(
            task_id=task.id,
            run_id=task.run_id,
            tool_results=results,
            attack_surface=tuple(entry for item in results for entry in item.attack_surface),
            technologies=tuple(tech for item in results for tech in item.technologies),
            evidence_ids=tuple(item.evidence_id for item in results if item.evidence_id),
            endpoints=endpoints,
            coverage=coverage,
            observations=self.repository.list_observations(task_id),
            attack_surface_inventory=inventory,
        )
        self.repository.save_recon_result(result)
        return result

    def _browser_coverage(self, task, coverage, results) -> dict:
        available = self.gateway.registry.get(Capability.BROWSER_EXPLORE) is not None
        requested = Capability.BROWSER_EXPLORE in task.scope.capabilities
        requests = {action.request.id for plan in self.repository.list_plans(task.id) for action in plan.actions
                    if action.request.capability == Capability.BROWSER_EXPLORE}
        parents = {item.request_id: item for item in results if item.capability == Capability.BROWSER_EXPLORE}
        requests.update(parents)
        configured = bool(requests) or (requested and available)
        reasons = set()
        for request_id in sorted(requests):
            result = parents.get(request_id)
            if result is None:
                reasons.add("incomplete")
                continue
            if result.status != "success":
                reasons.add(result.status)
            if result.evidence_id:
                try:
                    payload = json.loads(self.gateway.evidence.read(result.evidence_id))
                    reason = payload["stop_reason"]
                    if payload["parent_request_id"] != request_id or not isinstance(reason, str) or not reason or len(reason) > 256:
                        raise ValueError("invalid browser summary")
                    reasons.add(reason)
                except (ValueError, OSError, TypeError, KeyError):
                    reasons.add("invalid_evidence")
            elif result.status == "success":
                reasons.add("missing_evidence")
        if configured and not requests:
            reasons.add("not_started")
        complete = configured and bool(requests) and reasons == {"converged"}
        static_converged = coverage.converged if coverage.static_converged is None else coverage.static_converged
        static_complete = coverage.complete if coverage.static_complete is None else coverage.static_complete
        limitations = {item for item in coverage.limitations if not item.startswith(("browser:", "static:"))}
        limitations.update(f"browser:{reason}" for reason in reasons if reason != "converged")
        if requested and not available and not requests:
            limitations.add("browser:unavailable")
        if not static_complete:
            limitations.add(f"static:{coverage.stop_reason}" if not static_converged else "static:source_errors")
        return {
            "static_converged": static_converged, "static_complete": static_complete,
            "browser_available": available, "browser_configured": configured,
            "browser_runs": sum(self.repository.get_tool_run(key) is not None for key in requests),
            "browser_complete": complete, "browser_stop_reasons": tuple(sorted(reasons)),
            "limitations": tuple(sorted(limitations)),
            "converged": static_converged and (not configured or complete),
            "complete": static_complete and (not configured or complete),
        }
