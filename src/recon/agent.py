"""Task-driven entry point for the Day-1 Recon Agent."""

from __future__ import annotations

from src.recon.baseline_promotion import BrowserBaselinePromotion
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

    def run_service_discovery(self, task_id):
        from src.recon.sensing import ReconSensing
        return ReconSensing(self).service_discovery(task_id)

    def run_web_service_discovery(self, task_id):
        from src.recon.sensing import ReconSensing
        return ReconSensing(self).web_service_discovery(task_id)

    def run_technology_fingerprinting(self, task_id):
        from src.recon.sensing import ReconSensing
        return ReconSensing(self).technology_fingerprinting(task_id)

    def run_static_discovery(self, task_id, origins=None):
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        if Capability.HTTP_FETCH in task.scope.capabilities:
            return EndpointDiscovery(self.repository, self.planner, self.service).run(task, origins=origins)
        return self.refresh_inventory(task_id)

    def run_browser_action(self, plan):
        from src.recon.adaptive_projection import project_action
        if any(a.request.capability != Capability.BROWSER_EXPLORE for a in plan.actions):
            raise ValueError("browser stage requires typed browser actions")
        self.service.run(plan)
        for action in plan.actions:
            project_action(self.repository, self.service, action.request)
        return self.refresh_inventory(plan.task_id)

    def refresh_inventory(self, task_id):
        return self.service.snapshot(task_id)

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
        if Capability.HTTP_FETCH in task.scope.capabilities:
            result = BrowserBaselinePromotion(self.repository, self.planner, self.service).run(task)
        return result
