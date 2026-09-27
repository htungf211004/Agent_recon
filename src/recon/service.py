"""Runs a typed Recon plan and records its combined observations."""

from __future__ import annotations

from src.recon.gateway import ToolExecutionGateway
from src.recon.models import ReconPlan, ReconResult
from src.recon.storage import ReconRepository


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
        result = ReconResult(
            task_id=task.id,
            run_id=task.run_id,
            tool_results=results,
            attack_surface=tuple(entry for item in results for entry in item.attack_surface),
            technologies=tuple(tech for item in results for tech in item.technologies),
            evidence_ids=tuple(item.evidence_id for item in results if item.evidence_id),
            endpoints=self.repository.list_endpoints(task_id),
            coverage=self.repository.get_coverage(task_id),
        )
        self.repository.save_recon_result(result)
        return result
