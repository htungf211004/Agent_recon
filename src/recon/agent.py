"""Task-driven entry point for the Day-1 Recon Agent."""

from __future__ import annotations

from src.recon.browser_discovery import BrowserDiscovery
from src.recon.discovery import EndpointDiscovery
from src.recon.models import BrowserLimits, Capability, ReconResult
from src.recon.planner import ReconPlanner
from src.recon.service import ReconService
from src.recon.storage import ReconRepository


class ReconAgent:
    def __init__(
        self,
        repository: ReconRepository,
        planner: ReconPlanner,
        service: ReconService,
        *,
        browser_limits: BrowserLimits | None = None,
    ) -> None:
        self.repository = repository
        self.planner = planner
        self.service = service
        self.browser_limits = browser_limits

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
            result = EndpointDiscovery(self.repository, self.planner, self.service).run(task)
        if (Capability.BROWSER_EXPLORE in task.scope.capabilities
                and self.service.gateway.registry.get(Capability.BROWSER_EXPLORE) is not None):
            result = BrowserDiscovery(self.repository, self.service, self.browser_limits).run(task)
        return result
