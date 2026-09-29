"""Sequential evidence-backed sensing. Frozen stage plans survive process restarts."""

from urllib.parse import urlsplit

from src.recon.models import (
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    HttpProbeParams,
    NmapScanParams,
    ReconPlan,
    WhatWebParams,
)
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.urls import path_allowed, request_url

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443}
WEB_SERVICES = {"http", "https", "http-proxy", "http-alt", "ssl/http", "https-alt"}
UNKNOWN_SERVICES = {"unknown", "tcpwrapped", "", "?"}


def derive_web_candidates(task, nmap_results, requests):
    if task.scope.web_origin:
        o = task.scope.web_origin
        return ((o.pinned_ip, o.port, o.scheme),)
    candidates = []
    for ip in sorted(set(task.scope.allowed_ips)):
        scanned, facts = set(), {}
        for result in nmap_results:
            if result.target_ip != ip or result.status != "success":
                continue
            request = requests.get(result.request_id)
            if request is None:
                continue
            scanned.update(request.parameters.ports)
            facts.update({entry.port: entry for entry in result.attack_surface})
        for port in sorted(set(task.scope.allowed_ports)):
            fact = facts.get(port)
            if port in scanned and fact is None:
                continue  # A successfully scanned port without an open fact is not a candidate.
            if fact and fact.service.lower() not in WEB_SERVICES | UNKNOWN_SERVICES:
                continue
            if fact and fact.service.lower() in WEB_SERVICES:
                scheme = "https" if fact.service.lower() in {"https", "ssl/http", "https-alt"} else "http"
            elif not nmap_results or port in WEB_PORTS:
                scheme = scheme_for_port(port)
            else:
                continue
            candidates.append((ip, port, scheme))
    return tuple(candidates)


class ReconSensing:
    def __init__(self, engine):
        self.engine = engine
        self.repository, self.service = engine.repository, engine.service

    def _requests(self, task_id):
        return {run.request_id: CapabilityRequest.model_validate_json(run.request_payload)
                for run in self.repository.list_tool_runs(task_id) if run.request_payload}

    def _results(self, task_id):
        # Facts must still have intact evidence when used to drive another stage.
        results = []
        for result in self.repository.list_tool_results(task_id):
            if result.evidence_id:
                try:
                    self.service.gateway.evidence.read(result.evidence_id)
                except (ValueError, OSError):
                    continue
                results.append(result)
        return results

    def available(self, task, cap):
        return cap in task.scope.capabilities and self.service.gateway.registry.get(cap) is not None

    def candidates(self, task):
        return derive_web_candidates(task, [r for r in self._results(task.id) if r.capability == Capability.NMAP_SCAN],
                                     self._requests(task.id))

    def verified_origins(self, task):
        requests = self._requests(task.id)
        origins = set()
        for result in self._results(task.id):
            if result.status != "success" or result.request_id not in requests:
                continue
            request = requests[result.request_id]
            if result.capability == Capability.HTTP_PROBE and result.attack_surface or (
                result.capability == Capability.HTTP_FETCH and result.http_response is not None
            ):
                p = request.parameters
                origins.add(request_url(request.target_ip, p.scheme, p.port, "/", target_host=request.target_host))
        return tuple(sorted(origins))

    def run_stage(self, task_id, name, build):
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        with self.repository._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT plan FROM recon_stages WHERE task_id = ? AND name = ?", (task_id, name)).fetchone()
            if row is None:
                plan = ReconPlan(task_id=task_id, actions=tuple(build(task)))
                connection.execute("INSERT INTO recon_stages (task_id, name, plan) VALUES (?, ?, ?)",
                                   (task_id, name, plan.model_dump_json()))
            else:
                plan = ReconPlan.model_validate_json(row[0])
        result = self.service.run(plan)
        with self.repository._connect() as connection:
            connection.execute("UPDATE recon_stages SET state = 'COMPLETE' WHERE task_id = ? AND name = ?", (task_id, name))
        return result

    def service_discovery(self, task_id):
        def build(task):
            if self.available(task, Capability.NMAP_SCAN):
                ports = sorted(set(task.scope.allowed_ports))
                for ip in sorted(set(task.scope.allowed_ips)):
                    for start in range(0, len(ports), 32):
                        yield ReconPlanner._action(task, ip, Capability.NMAP_SCAN, NmapScanParams(ports=tuple(ports[start:start + 32])))
        return self.run_stage(task_id, "service_discovery", build)

    def web_service_discovery(self, task_id):
        def build(task):
            for ip, port, scheme in self.candidates(task):
                if self.available(task, Capability.HTTP_PROBE) and path_allowed("/", task.scope.allowed_paths):
                    yield ReconPlanner._action(task, ip, Capability.HTTP_PROBE, HttpProbeParams(port=port, scheme=scheme))
                elif self.available(task, Capability.HTTP_FETCH):
                    seed = urlsplit((task.discovery_seeds or task.scope.allowed_paths or ("/",))[0])
                    yield ReconPlanner._action(task, ip, Capability.HTTP_FETCH, HttpFetchParams(
                        port=port, scheme=scheme, path=seed.path, query=seed.query,
                        method="GET" if "GET" in task.scope.allowed_methods else "HEAD",
                        timeout_seconds=min(5, task.execution_budget.max_timeout_seconds),
                        max_body_bytes=task.execution_budget.max_body_bytes))
        return self.run_stage(task_id, "web_service_discovery", build)

    def technology_fingerprinting(self, task_id):
        def build(task):
            if self.available(task, Capability.WHATWEB):
                for origin in self.verified_origins(task):
                    url = urlsplit(origin)
                    yield ReconPlanner._action(task, url.hostname, Capability.WHATWEB,
                                               WhatWebParams(port=url.port, scheme=url.scheme))
        return self.run_stage(task_id, "technology_fingerprinting", build)
