"""Mandatory bounded Recon checks independent of model proposals."""

from src.recon.adaptive_projection import project_action
from src.recon.asset_verification import AssetVerifier
from src.recon.baseline_promotion import BrowserBaselinePromotion
from src.recon.content_discovery import baseline_content
from src.recon.discovery import EndpointDiscovery
from src.recon.models import (
    BrowserExploreParams,
    BrowserLimits,
    Capability,
    ContentDiscoveryParams,
    ExposureDiscoveryParams,
    ReconPlan,
)
from src.recon.origin_recon import OriginReconCoordinator
from src.recon.planner import ReconPlanner
from src.recon.urls import request_url


class DeterministicCoverageExecutor:
    WORDLIST = "web-common-small-v1"

    def __init__(self, engine):
        self.engine = engine
        self.repository, self.service = engine.repository, engine.service

    def run(self, task):
        boundary = self.repository.get_authorization(task.id)
        if boundary is None:
            return
        visited = set()
        for _ in range(boundary.max_new_origins + len(task.scope.allowed_ports)):
            task = self.repository.get_task(task.id)
            origin = next((row for row in self._verified_origins(task)
                           if row[0] not in visited), None)
            if origin is None:
                break
            visited.add(origin[0])
            _, target_ip, host, scheme, port = origin
            self._run_content(task, target_ip, host, scheme, port)
            self._run_content(task, target_ip, host, scheme, port, wordlist="api-common-small-v1")
            for profile in ("backup-small-v2", "scm-small-v1"):
                self._run_content(task, target_ip, host, scheme, port,
                                  capability=Capability.EXPOSURE_DISCOVERY, wordlist=profile)
            EndpointDiscovery(self.repository, self.engine.planner, self.service).run(
                task, origins=(origin[0],), max_origin_requests=24)
            self._run_browser(task, target_ip, host, scheme, port)
            BrowserBaselinePromotion(self.repository, self.engine.planner, self.service).run(task)
            baseline_content(self.repository, self.service, self.repository.get_task(task.id))
            AssetVerifier(self.repository, self.service).verify(self.repository.get_task(task.id))
            OriginReconCoordinator(self.repository, self.service, self.engine.planner).run(
                self.repository.get_task(task.id))
        if any(row[0] not in visited for row in self._verified_origins(self.repository.get_task(task.id))):
            self.repository.add_limitation(task.id, "coverage:origin_limit")

    def _verified_origins(self, task):
        rows = {}
        for run in self.repository.list_tool_runs(task.id):
            if not run.request_payload:
                continue
            from src.recon.models import parse_target_request

            request = parse_target_request(run.request_payload)
            if request is None:
                continue
            if request.capability != Capability.HTTP_PROBE:
                continue
            result = self.repository.get_tool_result(request.id)
            if not result or result.status != "success" or not result.attack_surface or not result.evidence_id:
                continue
            try:
                self.service.gateway.evidence.read(result.evidence_id)
            except (ValueError, OSError):
                continue
            params = request.parameters
            origin = request_url(request.target_ip, params.scheme, params.port, "/", target_host=request.target_host)
            rows[origin] = (origin, request.target_ip, request.target_host, params.scheme, params.port)
        return tuple(rows[key] for key in sorted(rows))

    def _prior(self, task_id, capability, target_ip, host, scheme, port, wordlist=None):
        for run in self.repository.list_tool_runs(task_id):
            if not run.request_payload:
                continue
            from src.recon.models import parse_target_request

            request = parse_target_request(run.request_payload)
            if request is None:
                continue
            if (request.capability == capability and request.target_ip == target_ip
                    and request.target_host == host and request.parameters.scheme == scheme
                    and request.parameters.port == port
                    and (capability not in {Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY} or
                         (request.parameters.path_prefix == "/" and request.parameters.wordlist_id == (wordlist or self.WORDLIST)))
                    and (capability != Capability.BROWSER_EXPLORE or request.parameters.path == "/")):
                return request
        return None

    def _execute(self, task, action):
        request = action.request
        if not self.service.gateway.policy.decide(request).allowed:
            self.repository.add_limitation(task.id, "coverage:policy_or_budget_limit")
            return
        try:
            self.service.run(ReconPlan(task_id=task.id, actions=(action,)))
        except RuntimeError:
            return
        project_action(self.repository, self.service, request)
        result = self.repository.get_tool_result(request.id)
        if result and result.status != "success":
            self.repository.add_limitation(task.id, "coverage:mandatory_action_failed")

    def _project_prior(self, task, request):
        project_action(self.repository, self.service, request)
        result = self.repository.get_tool_result(request.id)
        if result and result.status != "success":
            self.repository.add_limitation(task.id, "coverage:mandatory_action_failed")

    def _run_content(self, task, target_ip, host, scheme, port, *, capability=Capability.CONTENT_DISCOVERY,
                     wordlist=None):
        if capability not in task.scope.capabilities:
            return
        adapter = self.service.gateway.registry.get(capability)
        if adapter is None:
            return
        prior = self._prior(task.id, capability, target_ip, host, scheme, port, wordlist)
        if prior:
            self._project_prior(task, prior)
            return
        params = (ExposureDiscoveryParams(port=port, scheme=scheme, path_prefix="/", wordlist_id=wordlist)
                  if capability == Capability.EXPOSURE_DISCOVERY else
                  ContentDiscoveryParams(port=port, scheme=scheme, path_prefix="/", wordlist_id=wordlist or self.WORDLIST))
        action = ReconPlanner._action(task, target_ip, capability, params, target_host=host)
        if hasattr(adapter, "supports") and not adapter.supports(action.request):
            return
        self._execute(task, action)

    def _run_browser(self, task, target_ip, host, scheme, port):
        if Capability.BROWSER_EXPLORE not in task.scope.capabilities:
            return
        if self.service.gateway.registry.get(Capability.BROWSER_EXPLORE) is None:
            return
        prior = self._prior(task.id, Capability.BROWSER_EXPLORE, target_ip, host, scheme, port)
        if prior:
            self._project_prior(task, prior)
            return
        configured = getattr(self.engine, "browser_limits", None) or BrowserLimits(
            max_pages=2, max_depth=1, max_requests=8, max_runtime_seconds=10,
            max_response_bytes=65536, max_total_bytes=131072)
        limits = configured.model_copy(update={
            "max_runtime_seconds": min(configured.max_runtime_seconds, task.execution_budget.max_timeout_seconds),
            "max_response_bytes": min(configured.max_response_bytes, task.execution_budget.max_body_bytes),
        })
        action = ReconPlanner._action(task, target_ip, Capability.BROWSER_EXPLORE,
                                      BrowserExploreParams(port=port, scheme=scheme, path="/", limits=limits),
                                      target_host=host)
        self._execute(task, action)
