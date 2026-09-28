"""Runs a typed Recon plan and records its combined observations."""

from __future__ import annotations

from collections import Counter

from src.recon.gateway import ToolExecutionGateway
from src.recon.handoff import build_inventory
from src.recon.models import ReconPlan, ReconResult
from src.recon.storage import ReconRepository
from src.recon.web_models import EndpointLifecycle


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
        results = self.repository.list_tool_results(task_id)
        inventory = build_inventory(task, self.repository, self.gateway.evidence)
        endpoints = self.repository.list_endpoints(task_id)
        coverage = self.repository.get_coverage(task_id)
        if coverage:
            coverage = coverage.model_copy(update={
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
