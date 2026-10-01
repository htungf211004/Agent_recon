"""Mandatory final-image smoke: all public adapters through the production Gateway."""

import json
import socket
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingTCPServer
from tempfile import TemporaryDirectory
from threading import Thread

from src.contracts.execution import CURRENT_RECON_POLICY_VERSION
from src.recon.agent import ReconAgent
from src.recon.bootstrap import create_recon_service
from src.recon.models import (
    BrowserExploreParams,
    Capability,
    CapabilityRequest,
    ContentDiscoveryParams,
    HttpFetchParams,
    HttpProbeParams,
    NmapScanParams,
    ReconTask,
    Scope,
    WhatWebParams,
)
from src.recon.planner import ReconPlanner

FINAL_CAPABILITIES = frozenset({
    Capability.DNS_RESOLVE,
    Capability.HTTP_PROBE, Capability.HTTP_FETCH, Capability.NMAP_SCAN,
    Capability.WHATWEB, Capability.BROWSER_EXPLORE, Capability.CONTENT_DISCOVERY,
})
CORE_CAPABILITIES = frozenset({Capability.DNS_RESOLVE, Capability.HTTP_PROBE,
                                Capability.HTTP_FETCH, Capability.BROWSER_EXPLORE})
LOCAL_TOOL_CAPABILITIES = frozenset({Capability.NMAP_SCAN, Capability.WHATWEB,
                                     Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                                     Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION,
                                     Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY})
EXTERNAL_PROVIDER_CAPABILITIES = frozenset({Capability.WHOIS_RDAP_LOOKUP,
                                            Capability.EXTERNAL_ASSET_SEARCH,
                                            Capability.PUBLIC_CODE_SEARCH,
                                            Capability.SEARCH_ENGINE_OSINT})


def require_final_capabilities(registry):
    available = set(registry.available_capabilities())
    unexpected = available - FINAL_CAPABILITIES - {Capability.SOURCEMAP_ANALYZE,
        Capability.WSDL_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
        Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION,
        Capability.WHOIS_RDAP_LOOKUP,
        Capability.EXTERNAL_ASSET_SEARCH, Capability.PUBLIC_CODE_SEARCH, Capability.SEARCH_ENGINE_OSINT}
    if not FINAL_CAPABILITIES <= available or unexpected:
        raise RuntimeError(f"invalid final capabilities: missing={sorted(FINAL_CAPABILITIES - available)}, "
                           f"unexpected={sorted(unexpected)}")
    return sorted(available)


class SmokeHandler(BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except ConnectionError:
            pass  # Nmap closes service-detection connections before reading.

    def do_GET(self):
        self.server.requests += 1
        if self.server.redirect_to:
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"<!doctype html><html><head><title>Recon smoke</title></head><body>OK</body></html>"
        self.send_response(200 if self.path in {"/", "/hidden"} else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, *_args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
    sink = ThreadingHTTPServer(("127.0.0.1", 0), SmokeHandler)
    for fixture in (server, sink):
        fixture.requests = 0
        fixture.redirect_to = None
    thread = Thread(target=server.serve_forever, daemon=True)
    sink_thread = Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    sink_thread.start()
    try:
        with TemporaryDirectory(prefix="recon-runtime-") as directory:
            root = Path(directory)
            repository, service = create_recon_service(root / "recon.db", root / "evidence")
            gateway = service.gateway
            manifest = require_final_capabilities(gateway.registry)
            port = server.server_port
            task = ReconTask(
                id="runtime-smoke", run_id="runtime-smoke",
                scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port,),
                            allowed_paths=("/",), capabilities=tuple(FINAL_CAPABILITIES) + (Capability.BROWSER_REQUEST,)),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
            repository.save_task(task)
            parameters = (
                HttpProbeParams(port=port), HttpFetchParams(port=port), NmapScanParams(ports=(port,)),
                WhatWebParams(port=port), BrowserExploreParams(port=port),
                ContentDiscoveryParams(port=port, wordlist_id="web-common-small-v1"),
            )
            for params in parameters:
                request = CapabilityRequest(id=f"smoke-{params.kind}", task_id=task.id, target_ip="127.0.0.1",
                                            capability=Capability(params.kind), parameters=params)
                result = gateway.execute(request)
                evidence = gateway.evidence.read(result.evidence_id) if result.evidence_id else None
                if result.status != "success":
                    raise RuntimeError(f"{params.kind}: {result.message}; evidence={evidence!r}")
                decision = repository.get_policy_decision(request.id)
                assert decision.allowed and decision.policy_version == CURRENT_RECON_POLICY_VERSION
                assert evidence is not None
                if request.capability == Capability.NMAP_SCAN:
                    assert any(entry.port == port for entry in result.attack_surface)
                if request.capability == Capability.WHATWEB:
                    assert result.technologies, evidence
                if request.capability == Capability.CONTENT_DISCOVERY:
                    from src.recon.content_discovery import baseline_content, project_content
                    project_content(repository, service, request)
                    inventory = service.snapshot(task.id).attack_surface_inventory
                    hidden = next(e for e in inventory.entries if e.canonical_path == "/hidden")
                    assert hidden.status != "FUZZ_READY" and hidden.baseline_ref is None
                    baseline_content(repository, service, task)
                    inventory = service.snapshot(task.id).attack_surface_inventory
                    hidden = next(e for e in inventory.entries if e.canonical_path == "/hidden")
                    assert hidden.status == "FUZZ_READY" and hidden.baseline_ref
                assert gateway.execute(request) == result
            # A real WhatWeb invocation must not follow a redirect outside the scoped port.
            server.redirect_to = f"http://127.0.0.1:{sink.server_port}/"
            before = server.requests
            redirect = CapabilityRequest(id="smoke-whatweb-redirect", task_id=task.id, target_ip="127.0.0.1",
                                         capability=Capability.WHATWEB, parameters=WhatWebParams(port=port))
            redirected = gateway.execute(redirect)
            assert redirected.status == "success"
            assert server.requests == before + 1 and sink.requests == 0
            assert gateway.execute(redirect) == redirected
            assert server.requests == before + 1 and sink.requests == 0
            server.redirect_to = None
            check_sequential_bootstrap(root, repository, service, port)
            print(json.dumps({"capabilities": manifest,
                              "runtime_classes": {
                                  "core": sorted(CORE_CAPABILITIES),
                                  "local_tool": sorted(LOCAL_TOOL_CAPABILITIES & set(manifest)),
                                  "external_provider": sorted(EXTERNAL_PROVIDER_CAPABILITIES & set(manifest))},
                              "availability": gateway.registry.availability_manifest(),
                              "real_adapter_smoke": "passed"}))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        sink.shutdown()
        sink.server_close()
        sink_thread.join(timeout=5)


def check_sequential_bootstrap(root, repository, service, port):
    class SshBanner(BaseRequestHandler):
        def handle(self):
            try:
                self.request.sendall(b"SSH-2.0-OpenSSH_9.2\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

    ssh = ThreadingTCPServer(("127.0.0.1", 0), SshBanner)
    thread = Thread(target=ssh.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as closed:
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
    try:
        task = ReconTask(id="bootstrap-real", run_id="bootstrap-real",
            scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port, ssh.server_address[1], closed_port),
                        capabilities=(Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB, Capability.HTTP_FETCH)),
            expires_at=datetime.now(UTC) + timedelta(minutes=5))
        repository.save_task(task)
        engine = ReconAgent(repository, ReconPlanner(), service)
        engine.run_service_discovery(task.id)
        facts = service.snapshot(task.id).attack_surface
        assert any(f.port == ssh.server_address[1] and f.service == "ssh" for f in facts), facts
        engine.run_web_service_discovery(task.id)
        engine.run_technology_fingerprinting(task.id)
        from src.recon.sensing import ReconSensing
        engine.run_static_discovery(task.id, ReconSensing(engine).verified_origins(task))
        results = repository.list_tool_results(task.id)
        assert [r.capability for r in results[:3]] == [Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB]
        for run in repository.list_tool_runs(task.id):
            request = CapabilityRequest.model_validate_json(run.request_payload)
            if request.capability != Capability.NMAP_SCAN:
                assert request.parameters.port == port
        assert all(f":{port}/" in s.url for s in repository.list_sources(task.id))
        before = len(repository.list_tool_runs(task.id))
        engine.run_service_discovery(task.id)
        engine.run_web_service_discovery(task.id)
        engine.run_technology_fingerprinting(task.id)
        assert len(repository.list_tool_runs(task.id)) == before
    finally:
        ssh.shutdown()
        ssh.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
