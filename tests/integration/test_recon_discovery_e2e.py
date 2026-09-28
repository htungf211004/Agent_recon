import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from src.recon.bootstrap import create_recon_agent
from src.recon.models import Capability, ReconTask, Scope
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import DiscoveryKind, DiscoveryLimits, EndpointLifecycle, SourceStatus


@pytest.fixture
def discovery_server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path))
            documents = {
                "/": ("text/html", '''<html><a href="/shared">shared</a><a href="/query?q=one">query</a>
                    <a href="/query?q=two">query two</a><a href="/profile">profile</a>
                    <a href="/missing">missing</a><a href="/redirect">redirect</a>
                    <a href="http://127.0.0.2/outside">outside</a><script src="/app.js"></script>
                    <form method="post" action="/mutate"><input name="value" required></form>
                    <form method="get" action="/logout"><input name="confirm"></form></html>'''),
                "/robots.txt": ("text/plain", "User-agent: *\nAllow: /shared\nSitemap: /sitemap.xml"),
                "/sitemap.xml": ("application/xml", '<sitemapindex><sitemap><loc>/part.xml</loc></sitemap><sitemap><loc>/sitemap.xml</loc></sitemap></sitemapindex>'),
                "/part.xml": ("application/xml", '<urlset><url><loc>/shared</loc></url><url><loc>/from-sitemap</loc></url></urlset>'),
                "/openapi.json": ("application/json", json.dumps({
                    "openapi": "3.0.3", "paths": {
                        "/shared": {"get": {}},
                        "/required": {"get": {"parameters": [{"name": "q", "in": "query", "required": True}]}},
                        "/api/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True}]}},
                        "/mutate": {"post": {"requestBody": {"required": True}}},
                    },
                })),
                "/app.js": ("application/javascript", "fetch('/shared'); fetch('/from-js'); fetch('/mutate', {method:'POST'});"),
                "/shared": ("text/plain", "shared response"),
                "/query?q=one": ("application/json", '{"q":"one"}'),
                "/query?q=two": ("application/json", '{"q":"two"}'),
                "/profile": ("text/plain", "profile without query parameters"),
                "/from-js": ("text/plain", "JavaScript candidate"),
                "/from-sitemap": ("text/plain", "sitemap candidate"),
            }
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/should-not-follow")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            content_type, text = documents.get(self.path, ("text/plain", "not found"))
            body = text.encode()
            self.send_response(200 if self.path in documents else 404)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            calls.append(("POST", self.path))
            self.send_response(405)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    while server.server_address[1] in {443, 8443, 9443}:
        server.server_close()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def discovery_task(port, **limits):
    return ReconTask(
        id="discovery", run_id="run-discovery", expires_at=datetime.now(UTC) + timedelta(minutes=5),
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port,), capabilities=(Capability.HTTP_FETCH,), allowed_paths=("/",)),
        discovery_limits=DiscoveryLimits(**limits),
    )


def test_local_multisource_discovery_merge_lifecycle_evidence_and_replay(tmp_path, discovery_server):
    port, calls = discovery_server
    repository, agent = create_recon_agent(tmp_path / "recon.db", tmp_path / "evidence")
    task = discovery_task(port)
    repository.save_task(task)
    result = agent.run(task.id)
    origin = f"http://127.0.0.1:{port}"
    endpoints = {(entry.url.removeprefix(origin), entry.method): entry for entry in result.endpoints}
    shared = endpoints[("/shared", "GET")]
    assert {p.kind for p in shared.provenance} >= {
        DiscoveryKind.HTML, DiscoveryKind.ROBOTS, DiscoveryKind.SITEMAP, DiscoveryKind.OPENAPI, DiscoveryKind.JAVASCRIPT,
    }
    assert shared.lifecycle == EndpointLifecycle.FUZZ_READY
    query = endpoints[("/query", "GET")]
    assert query.lifecycle == EndpointLifecycle.FUZZ_READY
    observations = [item for item in result.observations if item.endpoint_id == query.id]
    assert {item.url for item in observations} == {origin + "/query?q=one", origin + "/query?q=two"}
    assert endpoints[("/profile", "GET")].lifecycle == EndpointLifecycle.FUZZ_READY
    assert endpoints[("/missing", "GET")].lifecycle == EndpointLifecycle.OBSERVED
    assert endpoints[("/redirect", "GET")].lifecycle == EndpointLifecycle.OBSERVED
    assert endpoints[("/mutate", "POST")].lifecycle == EndpointLifecycle.DISCOVERED
    assert len(endpoints[("/mutate", "POST")].provenance) == 3
    assert endpoints[("/api/{id}", "GET")].lifecycle == EndpointLifecycle.DISCOVERED
    assert endpoints[("/required", "GET")].lifecycle == EndpointLifecycle.DISCOVERED
    assert endpoints[("/logout", "GET")].requires_manual_input is True
    assert endpoints[("/from-js", "GET")].lifecycle == EndpointLifecycle.FUZZ_READY
    assert endpoints[("/from-sitemap", "GET")].lifecycle == EndpointLifecycle.FUZZ_READY
    assert not any(path in {"/should-not-follow", "/mutate", "/logout", "/required", "/api/{id}"} for _, path in calls)
    assert all(method == "GET" for method, _ in calls)
    assert all(count == 1 for count in Counter(calls).values())
    assert result.coverage.converged is True
    assert result.coverage.complete is True
    assert result.coverage.rounds >= 3
    assert result.coverage.requests == len(calls)
    assert result.coverage.route_count == len(result.endpoints)
    assert result.coverage.observation_count == len(result.observations) == len(result.endpoints) + 1
    assert result.coverage.runtime_attempts == len(calls)
    assert result.coverage.fuzz_ready_count == sum(item.lifecycle == EndpointLifecycle.FUZZ_READY for item in result.endpoints)
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    for endpoint in result.endpoints:
        for provenance in endpoint.provenance:
            if provenance.evidence_id:
                assert evidence.read(provenance.evidence_id)
        if endpoint.baseline_id:
            baseline = repository.get_baseline(endpoint.baseline_id)
            assert baseline.endpoint_id == endpoint.id
            assert baseline.evidence_id in endpoint.evidence_ids
            assert repository.get_policy_decision(baseline.request_id).allowed is True
            assert evidence.read(baseline.evidence_id)
    for entry in result.attack_surface_inventory.entries:
        ids = {item.id for item in entry.observations}
        for provenance in entry.provenance:
            assert provenance.observation_ref in ids
            tool_result = repository.get_tool_result(provenance.request_ref)
            assert tool_result.evidence_id == provenance.evidence_ref
            assert evidence.read(provenance.evidence_ref)
        if entry.status == EndpointLifecycle.FUZZ_READY:
            assert entry.baseline_observation_ref in ids
            assert repository.get_baseline(entry.baseline_ref).observation_id == entry.baseline_observation_ref
    assert any(source.kind == DiscoveryKind.SITEMAP_INDEX for source in repository.list_sources(task.id))
    assert ReconRepository(repository.database_path).get_coverage(task.id) == result.coverage
    call_count = len(calls)
    _, restarted_agent = create_recon_agent(repository.database_path, tmp_path / "evidence")
    assert restarted_agent.run(task.id) == result
    assert len(calls) == call_count


@pytest.mark.parametrize("limits,reason", [
    ({"max_requests": 2}, "request_limit"),
    ({"max_rounds": 1}, "round_limit"),
    ({"max_depth": 0}, "depth_limit"),
    ({"max_sources": 2}, "source_limit"),
    ({"max_endpoints": 2}, "endpoint_limit"),
])
def test_discovery_limits_report_incomplete_coverage(tmp_path, discovery_server, limits, reason):
    port, calls = discovery_server
    repository, agent = create_recon_agent(tmp_path / "recon.db", tmp_path / "evidence")
    task = discovery_task(port, **limits)
    repository.save_task(task)
    result = agent.run(task.id)
    assert result.coverage.converged is False
    assert result.coverage.complete is False
    assert result.coverage.stop_reason == reason
    assert result.coverage.requests <= task.discovery_limits.max_requests
    assert result.coverage.sources <= task.discovery_limits.max_sources
    assert result.coverage.endpoints <= task.discovery_limits.max_endpoints
    assert all(source.status != SourceStatus.PENDING for source in repository.list_sources(task.id))
    count = len(calls)
    assert agent.run(task.id) == result
    assert len(calls) == count
