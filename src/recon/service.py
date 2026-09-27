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
        existing = self.repository.get_recon_result(plan.task_id)
        if existing is not None:
            return existing
        results = tuple(self.gateway.execute(action.request) for action in plan.actions)
        result = ReconResult(
            task_id=task.id,
            run_id=task.run_id,
            tool_results=results,
            attack_surface=tuple(entry for item in results for entry in item.attack_surface),
            technologies=tuple(tech for item in results for tech in item.technologies),
            evidence_ids=tuple(item.evidence_id for item in results if item.evidence_id),
        )
        self.repository.save_recon_result(result)
        return result
