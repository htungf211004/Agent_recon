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
from src.recon.web_models import DiscoverySource


def scheme_for_port(port: int) -> str:
    return "https" if port in {443, 8443, 9443} else "http"


class ReconPlanner:
    def fetch_plan(self, task: ReconTask, sources: tuple[DiscoverySource, ...]) -> ReconPlan:
        actions = []
        for source in sorted(sources, key=lambda item: (item.depth, item.url, item.method)):
            url = urlsplit(source.url)
            actions.append(self._action(task, url.hostname, Capability.HTTP_FETCH, HttpFetchParams(
                port=url.port, scheme=url.scheme, path=url.path, query=url.query, method=source.method,
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
            parameters=parameters,
        )
        return ReconAction(id=request_id, request=request)
