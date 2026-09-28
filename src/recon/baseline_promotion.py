"""Promote verified browser observations via separate bounded HTTP_FETCH plans."""

import base64
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import urlsplit

from src.recon.endpoints import baseline_eligible, fuzz_ready
from src.recon.execution import ToolRunState
from src.recon.models import Capability, CapabilityRequest, HttpFetchParams, ReconAction, ReconPlan, ReconTask
from src.recon.policy import PolicyService
from src.recon.urls import path_allowed, request_url
from src.recon.web_models import (
    BaselineRequest,
    DiscoveryKind,
    EndpointLifecycle,
    EndpointProvenance,
    stable_id,
)

PREFIX = "browser-baseline-"


class BrowserBaselinePromotion:
    def __init__(self, repository, planner, service):
        self.repository, self.planner, self.service = repository, planner, service

    def run(self, task: ReconTask):
        task = self.repository.get_task(task.id)
        if Capability.HTTP_FETCH not in task.scope.capabilities:
            return self.service.snapshot(task.id)
        self.repository.recover_expired_runs(task.id)
        self.repository.reconcile_all_templates(task.id)
        self.service.snapshot(task.id)  # Refresh verified baseline state before selecting candidates.
        plans = [plan for plan in self.repository.list_plans(task.id)
                 if plan.actions and all(action.request.id.startswith(PREFIX) for action in plan.actions)]
        observations = self.repository.list_observations(task.id)
        by_id = {item.id: item for item in observations}
        selected_routes = set()
        for plan in plans:
            for action in plan.actions:
                observation = by_id.get(self._observation_id(action.request))
                if observation:
                    selected_routes.add(observation.endpoint_id)
        actions = []
        for observation in sorted(observations, key=lambda item: (item.method != "GET", item.url, item.id)):
            endpoint = self.repository.get_endpoint(observation.endpoint_id)
            if (endpoint is None or endpoint.id in selected_routes or endpoint.baseline_id is not None
                    or endpoint.method not in {"GET", "HEAD"} or not baseline_eligible(endpoint, observation.url)
                    or not self._browser_observation(task, observation)):
                continue
            parts = urlsplit(observation.url)
            identity = PREFIX + stable_id("browser-baseline-v1", task.id, endpoint.id, observation.id,
                                          observation.url, endpoint.method)
            request = CapabilityRequest(
                id=identity, task_id=task.id, capability=Capability.HTTP_FETCH, target_ip=parts.hostname,
                parameters=HttpFetchParams(port=parts.port, scheme=parts.scheme, method=endpoint.method,
                                           path=parts.path, query=parts.query,
                                           timeout_seconds=min(5.0, task.execution_budget.max_timeout_seconds),
                                           max_body_bytes=task.execution_budget.max_body_bytes),
            )
            actions.append(ReconAction(id=identity, request=self.service.gateway.policy.bind(request)))
            selected_routes.add(endpoint.id)
        if actions:
            plan = ReconPlan(task_id=task.id, actions=tuple(actions))
            # Freeze concrete selection before dispatch, even when execution fails or crashes.
            self.repository.save_plan(plan)
            plans.append(plan)
        for plan in plans:
            try:
                self.service.run(plan)
            except RuntimeError:
                if not any(self.repository.get_tool_result(action.request.id) is None for action in plan.actions):
                    raise
                return self.service.snapshot(task.id)
            for action in plan.actions:
                self._promote(task, action.request)
        return self.service.snapshot(task.id)

    @staticmethod
    def _observation_id(request):
        params = request.parameters
        url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query)
        return stable_id(request.task_id, params.method, url)

    def _verified_exchange(self, task, result, url, method):
        if result is None or result.status != "success" or not result.evidence_id or not result.http_response:
            return None
        run = self.repository.get_tool_run(result.request_id)
        decision = self.repository.get_policy_decision(result.request_id)
        artifact = self.repository.get_evidence(result.evidence_id)
        if (run is None or run.state != ToolRunState.SUCCEEDED or not run.request_payload
                or decision is None or not decision.allowed or artifact is None):
            return None
        try:
            request = CapabilityRequest.model_validate_json(run.request_payload)
            params = request.parameters
            if (result.task_id != task.id or run.task_id != task.id or artifact.task_id != task.id
                    or artifact.run_id != task.run_id or artifact.request_id != result.request_id
                    or artifact.tool_run_id != result.request_id or artifact.kind != "http_exchange"
                    or result.capability != request.capability or request.task_id != task.id
                    or request.action_fingerprint != decision.action_fingerprint
                    or request_url(request.target_ip, params.scheme, params.port, params.path, params.query) != url
                    or params.method != method):
                return None
            envelope = json.loads(self.service.gateway.evidence.read(result.evidence_id))
            body = base64.b64decode(envelope["body_base64"], validate=True)
            metadata = result.http_response
            if (envelope["url"] != url or envelope["method"] != method or envelope["response"] != metadata.model_dump()
                    or len(body) != metadata.body_size or hashlib.sha256(body).hexdigest() != metadata.body_sha256):
                return None
            return request
        except (ValueError, TypeError, KeyError, OSError, AttributeError):
            return None

    def _browser_observation(self, task, observation):
        if not observation.request_id or not observation.evidence_id:
            return False
        result = self.repository.get_tool_result(observation.request_id)
        if (result is None or result.capability != Capability.BROWSER_REQUEST
                or result.evidence_id != observation.evidence_id or result.http_response != observation.response
                or observation.response is None or not 200 <= observation.response.status_code < 300):
            return False
        request = self._verified_exchange(task, result, observation.url, observation.method)
        parent = self.repository.get_tool_run(request.parent_request_id) if request else None
        return bool(request and request.parameters.resource_type in {"document", "xhr", "fetch"}
                    and parent and parent.state == ToolRunState.SUCCEEDED
                    and any(item.kind == DiscoveryKind.BROWSER and item.relation == "network_request"
                            and item.request_id == result.request_id and item.evidence_id == result.evidence_id
                            for item in observation.provenance))

    def _promote(self, task, request):
        observation = next((item for item in self.repository.list_observations(task.id)
                            if item.id == self._observation_id(request)), None)
        if observation is None:
            return
        endpoint = self.repository.get_endpoint(observation.endpoint_id)
        result = self.repository.get_tool_result(request.id)
        if endpoint is None:
            return
        if endpoint.baseline_id:
            baseline = self.repository.get_baseline(endpoint.baseline_id)
            if baseline is None or baseline.request_id != request.id:
                return
        current = self.repository.get_task(task.id)
        params = request.parameters
        if (current.policy_version != PolicyService.VERSION or current.expires_at <= datetime.now(UTC)
                or Capability.HTTP_FETCH not in current.scope.capabilities or request.target_ip not in current.scope.allowed_ips
                or params.port not in current.scope.allowed_ports or params.method not in current.scope.allowed_methods
                or not path_allowed(params.path, current.scope.allowed_paths)
                or not baseline_eligible(endpoint, observation.url)):
            return
        verified = self._verified_exchange(task, result, observation.url, endpoint.method)
        if (verified is None or verified.capability != Capability.HTTP_FETCH
                or not 200 <= result.http_response.status_code < 300 or result.http_response.truncated):
            return
        provenance = EndpointProvenance(
            source_id=observation.id, kind=DiscoveryKind.BROWSER, relation="baseline",
            observation_id=observation.id, request_id=result.request_id, evidence_id=result.evidence_id,
        )
        observation = self.repository.save_observation(observation.model_copy(update={
            "request_id": result.request_id, "evidence_id": result.evidence_id, "response": result.http_response,
            "observed_at": result.finished_at, "evidence_verified": True, "provenance": (provenance,),
        }), preserve_existing_response=False)
        baseline = BaselineRequest(
            task_id=task.id, endpoint_id=endpoint.id, observation_id=observation.id, request_id=result.request_id,
            url=observation.url, route_template=endpoint.route_template, method=endpoint.method,
            evidence_id=result.evidence_id, response=result.http_response, observed_at=result.finished_at,
        )
        self.repository.save_baseline(baseline)
        endpoint = endpoint.model_copy(update={
            "in_scope": True, "baseline_id": baseline.id, "baseline_url": observation.url, "baseline_verified": True,
            "lifecycle": EndpointLifecycle.BASELINED,
            "evidence_ids": tuple(sorted(set((*endpoint.evidence_ids, result.evidence_id)))),
            "provenance": (*endpoint.provenance, provenance),
        })
        if fuzz_ready(endpoint):
            endpoint = endpoint.model_copy(update={"lifecycle": EndpointLifecycle.FUZZ_READY})
        self.repository.save_endpoint(endpoint)
