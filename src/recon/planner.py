"""Deterministic Day-1 plans derived only from a trusted Recon task."""

from __future__ import annotations

import json
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid5

from src.recon.models import (
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    HttpProbeParams,
    NmapScanParams,
    ReconAction,
    ReconPlan,
    ReconTask,
    WhatWebParams,
)
from src.recon.urls import scoped_ip
from src.recon.web_models import DiscoverySource


def scheme_for_port(port: int) -> str:
    return "https" if port in {443, 8443, 9443} else "http"


class ReconPlanner:
    def fetch_plan(self, task: ReconTask, sources: tuple[DiscoverySource, ...]) -> ReconPlan:
        actions = []
        for source in sorted(sources, key=lambda item: (item.depth, item.url, item.method)):
            url = urlsplit(source.url)
            target = scoped_ip(task.scope, source.url)
            if target is None:
                # Keep literal-IP off-scope sources flowing through Policy for audit.
                target = url.hostname
            actions.append(self._action(task, target, Capability.HTTP_FETCH, HttpFetchParams(
                port=url.port, scheme=url.scheme, path=url.path, query=url.query, method=source.method,
                timeout_seconds=min(5.0, task.execution_budget.max_timeout_seconds),
                max_body_bytes=task.execution_budget.max_body_bytes,
            )))
        return ReconPlan(task_id=task.id, actions=tuple(actions))

    def initial_plan(self, task: ReconTask) -> ReconPlan:
        actions: list[ReconAction] = []
        ports = tuple(sorted(set(task.scope.allowed_ports)))
        capabilities = set(task.scope.capabilities)

        for target_ip in sorted(set(task.scope.allowed_ips)):
            if Capability.NMAP_SCAN in capabilities:
                actions.append(self._action(
                    task, target_ip, Capability.NMAP_SCAN,
                    NmapScanParams(ports=ports[:32]),
                ))
            for port in ports:
                scheme = scheme_for_port(port)
                if Capability.HTTP_PROBE in capabilities:
                    actions.append(self._action(
                        task, target_ip, Capability.HTTP_PROBE,
                        HttpProbeParams(port=port, scheme=scheme),
                    ))
                if Capability.WHATWEB in capabilities:
                    actions.append(self._action(
                        task, target_ip, Capability.WHATWEB,
                        WhatWebParams(port=port, scheme=scheme),
                    ))

        return ReconPlan(task_id=task.id, actions=tuple(actions))

    @staticmethod
    def _action(task: ReconTask, target_ip: str, capability: Capability, parameters) -> ReconAction:
        origin = task.scope.web_origin
        identity = json.dumps(
            [task.id, target_ip, capability.value, parameters.model_dump()],
            sort_keys=True,
            separators=(",", ":"),
        )
        request_id = str(uuid5(NAMESPACE_URL, identity))
        request = CapabilityRequest(
            id=request_id,
            task_id=task.id,
            capability=capability,
            target_ip=target_ip,
            target_host=origin.host if origin else None,
            parameters=parameters,
            run_id=task.run_id,
            scope_version=task.scope_version,
        )
        from src.recon.policy import PolicyService

        request = request.model_copy(update={"action_fingerprint": PolicyService.expected_fingerprint(request, task)})
        return ReconAction(id=request_id, request=request)
