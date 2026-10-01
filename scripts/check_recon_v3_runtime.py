"""Real CLI adapter smoke against an isolated local fixture, through the production Gateway."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from src.recon.adaptive_projection import project_action
from src.recon.models import (
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    HttpProbeParams,
    LocalOsintCapabilityRequest,
    LocalOsintParams,
    ParameterDiscoveryParams,
    ReconTask,
    Scope,
    TechnologyScanParams,
    VhostDiscoveryParams,
    WebCrawlParams,
    WebOrigin,
)
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget


def run_passive_smoke(repository, service):
    """Offline process smoke; empty/error results do not certify provider coverage."""
    from src.recon.adapters import _run_fixed

    root = "recon-smoke.invalid"
    task = ReconTask(id="v3-passive", run_id="v3-passive", scope=Scope(allowed_ips=("127.0.0.1",),
        allowed_ports=(80,), capabilities=(Capability.PASSIVE_SUBDOMAIN_ENUM, Capability.PASSIVE_INFRA_ENUM,
                                          Capability.HISTORICAL_URL_DISCOVERY)),
        expires_at=datetime.now(UTC) + timedelta(minutes=1))
    repository.save_task(task)
    repository.save_authorization(AuthorizationBoundary(task_id=task.id,
        root=AuthorizedTarget(kind="DOMAIN", value=root)))
    for tool, capability, flag, version in (
        ("subfinder", Capability.PASSIVE_SUBDOMAIN_ENUM, "-version", "2.6.6"),
        ("amass", Capability.PASSIVE_INFRA_ENUM, "-version", "3.23.3"),
        ("gau", Capability.HISTORICAL_URL_DISCOVERY, "--version", "2.2.4"),
    ):
        identity = _run_fixed([tool, flag], timeout=5)
        assert identity.status == "success" and version.encode() in identity.raw_output, (tool, identity)
        request = LocalOsintCapabilityRequest(id="v3-passive-" + tool, task_id=task.id,
            root_domain=root, capability=capability, tool=tool,
            parameters=LocalOsintParams(timeout_seconds=2, max_results=4))
        result = service.gateway.execute(request)
        assert result.status in {"success", "error"}, (tool, result.message)
        assert repository.get_policy_decision(request.id).allowed
        assert not result.observations
        assert service.gateway.execute(request) == result
        print(tool, "real passive adapter process", result.status, flush=True)


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests += 1
        host = self.headers.get("Host", "").split(":")[0]
        params = parse_qs(urlsplit(self.path).query)
        body = b'<html><a href="/crawl-only">crawl</a>OK</html>'
        if "id" in params:
            body += b" parameter recognized" * 20
        status = 200 if host in {"recon.example.test", "api.recon.example.test"} else 404
        if status == 404:
            body = b"missing"
        self.send_response(status)
        self.send_header("Server", "nginx")
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.server.writes += 1
        self.send_error(405)

    def log_message(self, *_args):
        pass


def run_active_smoke(repository, service, _server=None):
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    fixture.requests, fixture.writes = 0, 0
    thread = Thread(target=fixture.serve_forever, daemon=True)
    thread.start()
    try:
        port, host = fixture.server_port, "recon.example.test"
        task = ReconTask(id="v3-active", run_id="v3-active", scope=Scope(
            allowed_ips=("127.0.0.1",), allowed_ports=(port,), allowed_paths=("/",),
            web_origin=WebOrigin(host=host, scheme="http", port=port, pinned_ip="127.0.0.1"),
            capabilities=(Capability.HTTP_PROBE, Capability.HTTP_FETCH, Capability.WEB_CRAWL,
                          Capability.VHOST_DISCOVERY, Capability.PARAMETER_DISCOVERY, Capability.TECHNOLOGY_SCAN)),
            expires_at=datetime.now(UTC) + timedelta(minutes=5))
        repository.save_task(task)
        repository.save_authorization(AuthorizationBoundary(task_id=task.id,
            root=AuthorizedTarget(kind="DOMAIN", value=host, include_subdomains=True)))

        def execute(params):
            request = CapabilityRequest(id="v3-" + params.kind, task_id=task.id, target_ip="127.0.0.1",
                                        target_host=host, capability=Capability(params.kind), parameters=params)
            result = service.gateway.execute(request)
            assert result.status == "success", (params.kind, result.message)
            assert result.evidence_id and service.gateway.evidence.read(result.evidence_id)
            before = fixture.requests
            assert service.gateway.execute(request) == result and fixture.requests == before
            project_action(repository, service, request)
            print(params.kind, "success", len(result.observations), flush=True)
            return result

        execute(HttpProbeParams(port=port))
        baseline = execute(HttpFetchParams(port=port))
        crawl = execute(WebCrawlParams(port=port))
        assert any(row.value.endswith("/crawl-only") for row in crawl.observations)
        vhosts = execute(VhostDiscoveryParams(port=port, root_domain=host, max_requests=8))
        assert {row.value for row in vhosts.observations} == {"api." + host}
        assert any(asset.asset_type == "HOST" and asset.canonical_value == "api." + host
                   and asset.verification_status != "VERIFIED" for asset in repository.list_assets(task.id))
        parameters = execute(ParameterDiscoveryParams(port=port, baseline_evidence_ref=baseline.evidence_id,
                                                      max_requests=32, timeout_seconds=30))
        assert any(row.value == "parameter:id" for row in parameters.observations)
        technologies = execute(TechnologyScanParams(port=port))
        assert any(row.name == "nginx" for row in technologies.technologies)
        assert fixture.writes == 0
    finally:
        fixture.shutdown()
        fixture.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from src.recon.bootstrap import create_recon_service

    with TemporaryDirectory() as directory:
        root = Path(directory)
        repository, service = create_recon_service(root / "task.db", root / "evidence")
        run_active_smoke(repository, service)
        run_passive_smoke(repository, service)
