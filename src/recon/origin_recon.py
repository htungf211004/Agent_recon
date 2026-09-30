"""Replayable discovery of derived origins through the root EndpointDiscovery engine."""

from src.recon.asset_verification import AssetVerifier
from src.recon.discovery import EndpointDiscovery
from src.recon.models import Capability, HttpProbeParams, ReconPlan, WhatWebParams
from src.recon.planner import ReconPlanner
from src.recon.urls import request_url
from src.recon.web_models import SourceStatus


class OriginReconCoordinator:
    def __init__(self, repository, service, planner=None):
        self.repository, self.service = repository, service
        self.planner = planner or ReconPlanner()

    def run(self, task):
        boundary = self.repository.get_authorization(task.id)
        if boundary is None:
            return
        visited = set()
        for _ in range(boundary.max_new_origins):
            task = self.repository.get_task(task.id)
            for binding in self.repository.list_bindings(task.id):
                self.repository.ensure_origin_work(binding, task.scope_version)
            item = next((work for work in self.repository.list_origin_work(task.id)
                         if work.status in {"PENDING", "RUNNING"}
                         and (work.host, work.scheme, work.port) not in visited), None)
            if item is None:
                break
            visited.add((item.host, item.scheme, item.port))
            self.repository.save_origin_work(item.model_copy(update={"status": "RUNNING"}))
            probed = self._probe(task, item)
            if probed is None:
                continue
            if not probed:
                self.repository.save_origin_work(item.model_copy(update={
                    "status": "LIMITED", "reason": "origin probe unavailable or unverified"}))
                continue
            origin = request_url(item.resolved_ip, item.scheme, item.port, "/", target_host=item.host)
            discovery = EndpointDiscovery(self.repository, self.planner, self.service)
            try:
                discovery.run(task, origins=(origin,))
            except RuntimeError:
                # An in-flight ToolRun remains attached to its persisted source for restart.
                continue
            sources = tuple(source for source in self.repository.list_sources(task.id)
                            if source.url.startswith(origin))
            if any(source.status == SourceStatus.PENDING for source in sources):
                continue
            limited = discovery.limit_reason != "exhausted" or any(
                          source.status in {SourceStatus.LIMITED, SourceStatus.BLOCKED, SourceStatus.ERROR}
                          for source in sources)
            self.repository.save_origin_work(item.model_copy(update={
                "status": "LIMITED" if limited else "COMPLETE",
                "reason": "source or budget limit" if limited else "",
            }))
            AssetVerifier(self.repository, self.service).verify(self.repository.get_task(task.id))

    def _probe(self, task, item):
        if Capability.HTTP_PROBE not in task.scope.capabilities:
            return False
        probe = ReconPlanner._action(task, item.resolved_ip, Capability.HTTP_PROBE,
                                     HttpProbeParams(port=item.port, scheme=item.scheme), target_host=item.host)
        if not self.service.gateway.policy.decide(probe.request).allowed:
            return False
        try:
            self.service.run(ReconPlan(task_id=task.id, actions=(probe,)))
        except RuntimeError:
            return None
        result = self.repository.get_tool_result(probe.request.id)
        if result is None:
            return None
        if result.status != "success" or not result.attack_surface or not result.evidence_id:
            return False
        try:
            self.service.gateway.evidence.read(result.evidence_id)
        except (ValueError, OSError):
            return False
        if Capability.WHATWEB in task.scope.capabilities and self.service.gateway.registry.get(Capability.WHATWEB):
            action = ReconPlanner._action(task, item.resolved_ip, Capability.WHATWEB,
                                          WhatWebParams(port=item.port, scheme=item.scheme), target_host=item.host)
            if self.service.gateway.policy.decide(action.request).allowed:
                try:
                    self.service.run(ReconPlan(task_id=task.id, actions=(action,)))
                except RuntimeError:
                    pass
        return True
