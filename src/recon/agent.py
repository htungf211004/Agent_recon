"""Task-driven entry point for the Day-1 Recon Agent."""

from __future__ import annotations

from src.recon.discovery import EndpointDiscovery
from src.recon.models import Capability, ReconResult
from src.recon.planner import ReconPlanner
from src.recon.service import ReconService
from src.recon.storage import ReconRepository


class ReconAgent:
    def __init__(
        self,
        repository: ReconRepository,
        planner: ReconPlanner,
        service: ReconService,
    ) -> None:
        self.repository = repository
        self.planner = planner
        self.service = service

    def run(self, task_id: str) -> ReconResult:
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        plan = self.planner.initial_plan(task)
        if plan.actions:
            result = self.service.run(plan)
        else:
            result = self.service.snapshot(task.id)
        if Capability.HTTP_FETCH in task.scope.capabilities:
            return EndpointDiscovery(self.repository, self.planner, self.service).run(task)
        return result
