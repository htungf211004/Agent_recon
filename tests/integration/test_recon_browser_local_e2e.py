"""Real localhost Chromium gate for passive browser request interception."""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import urlopen

import pytest

from src.recon.adapters import HttpFetchAdapter
from src.recon.agent import ReconAgent
from src.recon.browser import BrowserExploreAdapter
from src.recon.browser_runtime import chromium_available
from src.recon.discovery import EndpointDiscovery
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, BrowserLimits, Capability, CapabilityRequest, ReconTask, Scope
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import WebEndpointEntry


@pytest.fixture(scope="session")
def chromium_gate():
    if not chromium_available():
        if os.environ.get("RECON_REQUIRE_CHROMIUM") == "1" or os.environ.get("CI") == "true":
            pytest.fail("Chromium is mandatory in CI; install the runtime and its system dependencies")
        pytest.skip("local Chromium unavailable; CI requires this gate")


@pytest.fixture
def forbidden_sink():
    calls = []

    class Sink(BaseHTTPRequestHandler):
        def handle_request(self):
            calls.append((self.command, self.path))
            self.send_response(204)
            self.end_headers()

        do_GET = do_HEAD = do_POST = do_OPTIONS = handle_request  # noqa: N815

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Positive control: the forbidden server really accepts connections and logs them.
        with urlopen(f"http://127.0.0.1:{server.server_port}/health", timeout=2) as response:
            assert response.status == 204
        assert calls == [("GET", "/health")]
        calls.clear()
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


@pytest.fixture
def browser_server(forbidden_sink):
    calls = []
    sink_url, _ = forbidden_sink

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path))
            if self.path == "/browser-only":
                body = (b"<html><script>const route=String.fromCharCode(47)+['dy','namic'].join('');"
                        b"fetch(route+'?source=browser');</script></html>")
                content_type = "text/html"
            elif self.path == "/dynamic?source=browser":
                body, content_type = b'{"discovered":"only at runtime"}', "application/json"
            elif self.path == "/hardening":
                body = (b"<html><head><link rel='stylesheet' href='/hardening.css'></head><body>font test"
                        b"<img src='/logo.png'><script src='/shared-data'></script>"
                        b"<script>fetch('/shared-data');const x=new XMLHttpRequest();"
                        b"x.open('GET','/api/profile');x.send();</script></body></html>")
                content_type = "text/html"
            elif self.path == "/shared-data":
                body, content_type = b"window.dataLoaded=true;", "application/javascript"
            elif self.path == "/hardening.css":
                body = b"@font-face{font-family:test;src:url('/font.woff2')}body{font-family:test}"
                content_type = "text/css"
            elif self.path in {"/logo.png", "/font.woff2"}:
                body, content_type = b"fixture-asset", "application/octet-stream"
            elif self.path == "/api/profile":
                body, content_type = b'{"profile":true}', "application/json"
            elif self.path.startswith("/crawl"):
                links = {
                    "/crawl": "<a href='/crawl/b'>b</a><a href='/crawl/a'>a</a><a href='/crawl/a#again'>a</a>",
                    "/crawl/a": "<a href='/crawl/deep'>deep</a><a href='/crawl'>cycle</a>",
                    "/crawl/b": "<a href='/crawl/deep'>deep</a>",
                }.get(self.path, "")
                body = (f"<html>{links}<script src='/shared.js'></script>"
                        "<form method='post' action='/write'><input name='secret' required></form>"
                        "<form method='get' action='/search'><input name='q'></form>"
                        "<a download href='/archive'>archive</a>"
                        f"<a href='{sink_url}/anchor'>outside</a>"
                        "<script>const a=document.createElement('a');a.href='/users/7';"
                        "a.textContent='dynamic';document.body.appendChild(a);</script></html>").encode()
                content_type = "text/html"
            elif self.path == "/shared.js":
                body = b"fetch('/api');fetch('/write',{method:'POST'}).catch(()=>{});"
                content_type = "application/javascript"
            elif self.path == "/users/7":
                body, content_type = b"<html>user</html>", "text/html"
            elif self.path == "/":
                body = (
                    b"<html><script src='/app.js'></script>"
                    b"<link rel='stylesheet' href='/style.css'>"
                    b"<a href='/download'>download</a></html>"
                )
                content_type = "text/html"
            elif self.path == "/app.js":
                body = (
                    "fetch('/api');"
                    "fetch('/redirect').catch(()=>{});"
                    "fetch('/submit',{method:'POST'}).catch(()=>{});"
                    f"fetch({json.dumps(sink_url + '/outside')}).catch(()=>{{}});"
                    f"try{{new WebSocket({json.dumps(sink_url.replace('http:', 'ws:') + '/ws')})}}catch(e){{}};"
                    "if(navigator.serviceWorker){navigator.serviceWorker.register('/sw.js').catch(()=>{})};"
                    "setTimeout(()=>location.assign('/download'),100);"
                ).encode()
                content_type = "application/javascript"
            elif self.path == "/style.css":
                body, content_type = b"body{color:black}", "text/css"
            elif self.path == "/api":
                body, content_type = b'{"ok":true}', "application/json"
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", sink_url + "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            else:
                body, content_type = b"not found", "text/plain"
            self.send_response(200 if self.path.startswith("/crawl") or self.path in {
                "/", "/app.js", "/style.css", "/api", "/shared.js", "/users/7",
                "/hardening", "/shared-data", "/hardening.css", "/logo.png", "/font.woff2", "/api/profile",
                "/browser-only", "/dynamic?source=browser",
            } else 404)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            calls.append(("POST", self.path))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, calls
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_real_chromium_intercepts_each_local_request_once(tmp_path, browser_server, forbidden_sink, chromium_gate):
    port, calls = browser_server
    repository = ReconRepository(tmp_path / "browser.db")
    task = ReconTask(
        id="real-browser", run_id="real-run",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port,),
                    capabilities=(Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST),
                    allowed_paths=("/",)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    registry = CapabilityRegistry()
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, evidence, repository)
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway))
    request = CapabilityRequest(
        id="real-explore", task_id=task.id, capability=Capability.BROWSER_EXPLORE,
        target_ip="127.0.0.1", parameters=BrowserExploreParams(port=port),
    )
    result = gateway.execute(request)
    assert result.status == "success", result.message
    paths = Counter(calls)
    assert paths[("GET", "/")] == 1
    assert paths[("GET", "/app.js")] == 1
    assert paths[("GET", "/style.css")] == 1
    assert paths[("GET", "/api")] == 1
    assert paths[("GET", "/redirect")] == 1
    assert not any(method == "POST" or path in {"/outside", "/download", "/ws", "/sw.js"} for method, path in calls)
    children = repository.list_child_runs(request.id)
    assert len(children) >= 4
    assert all(repository.get_policy_decision(child.request_id).allowed for child in children)
    assert all(evidence.read(repository.get_tool_result(child.request_id).evidence_id) for child in children)
    endpoint_paths = {item.canonical_path for item in repository.list_endpoints(task.id)}
    assert {"/", "/api"} <= endpoint_paths
    assert not endpoint_paths & {"/app.js", "/style.css"}
    reopened = ReconRepository(tmp_path / "browser.db")
    assert len(reopened.list_child_runs(request.id)) == len(children)
    assert gateway.execute(request) == result
    assert Counter(calls) == paths
    assert forbidden_sink[1] == []


def test_real_static_assets_and_same_url_resource_identity(tmp_path, browser_server, forbidden_sink, chromium_gate):
    port, calls = browser_server
    repository, gateway, agent, task = browser_agent(tmp_path, port, BrowserLimits())
    request = CapabilityRequest(id="asset-parent", task_id=task.id, capability=Capability.BROWSER_EXPLORE,
                                target_ip="127.0.0.1", parameters=BrowserExploreParams(port=port, path="/hardening"))
    result = gateway.execute(request)
    assert result.status == "success", result.message
    counts = Counter(calls)
    assert counts[("GET", "/shared-data")] == 2
    for path in ("/hardening", "/hardening.css", "/logo.png", "/font.woff2", "/api/profile"):
        assert counts[("GET", path)] == 1
    children = [CapabilityRequest.model_validate_json(run.request_payload)
                for run in repository.list_child_runs(request.id)]
    shared = [child for child in children if child.parameters.path == "/shared-data"]
    assert {child.parameters.resource_type for child in shared} == {"script", "fetch"}
    assert len({child.id for child in shared}) == len({child.action_fingerprint for child in shared}) == 2
    for child in children:
        proof = repository.get_tool_result(child.id)
        assert repository.get_policy_decision(child.id).allowed
        assert gateway.evidence.read(proof.evidence_id)
    snapshot = agent.service.snapshot(task.id)
    routes = {item.canonical_path for item in snapshot.attack_surface_inventory.entries}
    assert routes == {"/hardening", "/shared-data", "/api/profile"}
    assert {item.canonical_path for item in snapshot.endpoints} == routes
    assert len(snapshot.observations) == 3
    assert forbidden_sink[1] == []


def browser_agent(tmp_path, port, limits, *, http=False, seeds=("/crawl",)):
    repository = ReconRepository(tmp_path / "agent.db")
    task = ReconTask(
        id="browser-agent", run_id="browser-run", discovery_seeds=seeds,
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(port,), allowed_paths=("/",),
                    capabilities=(Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST,
                                  *((Capability.HTTP_FETCH,) if http else ()))),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    registry = CapabilityRegistry()
    gateway = ToolExecutionGateway(PolicyService(repository), registry,
                                   EvidenceStore(tmp_path / "evidence", repository), repository)
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway))
    if http:
        registry.register(Capability.HTTP_FETCH, HttpFetchAdapter())
    agent = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway), browser_limits=limits)
    return repository, gateway, agent, task


def test_agent_browser_bfs_shared_inventory_evidence_and_restart(tmp_path, browser_server, forbidden_sink, chromium_gate):
    port, calls = browser_server
    limits = BrowserLimits(max_pages=5, max_depth=2, max_requests=32)
    repository, gateway, agent, task = browser_agent(tmp_path, port, limits)
    repository.save_endpoint(WebEndpointEntry(
        task_id=task.id, url=f"http://127.0.0.1:{port}/users/{{id}}", route_template="/users/{id}",
    ))
    result = agent.run(task.id)
    parent = next(item for item in result.tool_results if item.capability == Capability.BROWSER_EXPLORE)
    assert parent.status == "success", parent.message
    summary = json.loads(gateway.evidence.read(parent.evidence_id))
    expected = ["/crawl", "/crawl/a", "/crawl/b", "/users/7", "/crawl/deep"]
    assert [item["url"].split(str(port), 1)[1] for item in summary["pages"]] == expected
    assert [item["depth"] for item in summary["pages"]] == [0, 1, 1, 1, 2]
    counts = Counter(calls)
    assert all(counts[("GET", path)] == 1 for path in expected)
    assert counts[("GET", "/shared.js")] == counts[("GET", "/api")] == 4
    assert not any(method != "GET" or path in {"/search", "/write", "/archive"} for method, path in calls)
    assert forbidden_sink[1] == []
    children = repository.list_child_runs(parent.request_id)
    api = [CapabilityRequest.model_validate_json(item.request_payload) for item in children
           if CapabilityRequest.model_validate_json(item.request_payload).parameters.path == "/api"]
    assert len({item.id for item in api}) == len({item.action_fingerprint for item in api}) == 4
    assert {item.parameters.page_sequence for item in api} == {0, 1, 2, 4}
    for child in children:
        proof = repository.get_tool_result(child.request_id)
        assert proof.status == "success"
        artifact = repository.get_evidence(proof.evidence_id)
        assert artifact.kind == "http_exchange"
        assert artifact.metadata["parent_request_id"] == parent.request_id
        assert artifact.metadata["resource_type"]
        assert artifact.metadata["page_sequence"].isdigit()
        assert gateway.evidence.read(artifact.id)
    inventory = result.attack_surface_inventory
    assert inventory.schema_version == "1.0"
    routes = {(item.method, item.canonical_path): item for item in inventory.entries}
    assert ("GET", "/users/7") not in routes
    assert routes[("GET", "/users/{id}")].status == "OBSERVED"
    assert routes[("GET", "/users/{id}")].in_scope
    assert routes[("POST", "/write")].status == "DISCOVERED"
    assert routes[("POST", "/write")].parameters[0].name == "secret"
    assert routes[("GET", "/search")].status == "DISCOVERED"
    assert all(item.has_valid_evidence for item in inventory.entries)
    assert not any(item.has_verified_baseline for item in inventory.entries)
    reopened = ReconRepository(tmp_path / "agent.db")
    replay_gateway = ToolExecutionGateway(PolicyService(reopened), gateway.registry,
                                          EvidenceStore(tmp_path / "evidence", reopened), reopened)
    restarted = ReconAgent(reopened, ReconPlanner(), ReconService(reopened, replay_gateway))
    assert restarted.run(task.id).attack_surface_inventory == inventory
    assert Counter(calls) == counts


@pytest.mark.parametrize("limits,max_pages,max_depth,max_requests,reason", [
    (BrowserLimits(max_pages=2, max_depth=2), 2, 1, 16, "depth_or_page_limit"),
    (BrowserLimits(max_pages=8, max_depth=0), 1, 0, 16, "depth_or_page_limit"),
    (BrowserLimits(max_pages=8, max_depth=2, max_requests=1), 1, 0, 1, "request_limit"),
    (BrowserLimits(max_pages=8, max_depth=2, max_total_bytes=1), 1, 0, 1, "total_byte_limit"),
    (BrowserLimits(max_pages=8, max_depth=2, max_response_bytes=1), 1, 0, 1, "response_byte_limit"),
])
def test_real_browser_bfs_bounds(tmp_path, browser_server, chromium_gate, limits, max_pages, max_depth, max_requests, reason):
    port, calls = browser_server
    _, gateway, agent, task = browser_agent(tmp_path, port, limits)
    result = agent.run(task.id)
    parent = next(item for item in result.tool_results if item.capability == Capability.BROWSER_EXPLORE)
    summary = json.loads(gateway.evidence.read(parent.evidence_id))
    assert len(summary["pages"]) <= max_pages
    assert max(item["depth"] for item in summary["pages"]) <= max_depth
    assert len(calls) <= max_requests
    assert summary["admitted_body_bytes"] <= limits.max_total_bytes
    assert summary["stop_reason"] == reason
    assert result.coverage.browser_configured
    assert not result.coverage.browser_complete and not result.coverage.complete
    assert reason in result.coverage.browser_stop_reasons
    assert f"browser:{reason}" in result.coverage.limitations


def test_browser_preserves_day2_verified_baseline(tmp_path, browser_server, chromium_gate):
    port, _ = browser_server
    repository, gateway, agent, task = browser_agent(tmp_path, port, BrowserLimits(max_pages=2, max_depth=1), http=True)
    before = EndpointDiscovery(repository, agent.planner, agent.service).run(task)
    api_before = next(item for item in before.attack_surface_inventory.entries if item.canonical_path == "/api")
    assert api_before.has_verified_baseline and api_before.status == "FUZZ_READY"
    observation = next(item for item in before.observations if item.url.endswith("/api"))
    after = agent.run(task.id)
    api_after = next(item for item in after.attack_surface_inventory.entries if item.canonical_path == "/api")
    assert api_after.baseline_ref == api_before.baseline_ref
    assert api_after.has_verified_baseline and api_after.status == "FUZZ_READY"
    assert {item.kind for item in api_after.provenance} >= {"browser", "javascript"}
    assert next(item for item in after.observations if item.id == observation.id).request_id == observation.request_id
    assert any(item.capability == Capability.BROWSER_REQUEST for item in after.tool_results)


def test_browser_cancel_between_pages_and_restart(tmp_path, browser_server, chromium_gate, monkeypatch):
    port, calls = browser_server
    repository, gateway, agent, task = browser_agent(tmp_path, port, BrowserLimits(max_pages=5, max_depth=2))
    original = gateway.finish_external_dispatch

    def cancel_document(permit, output):
        if permit.request.parameters.resource_type == "document":
            gateway.cancel(permit.request.parent_request_id)
        return original(permit, output)

    monkeypatch.setattr(gateway, "finish_external_dispatch", cancel_document)
    result = agent.run(task.id)
    parent = next(item for item in result.tool_results if item.capability == Capability.BROWSER_EXPLORE)
    assert parent.status == "cancelled"
    assert ("GET", "/crawl/a") not in calls and ("GET", "/crawl/b") not in calls
    document = next(item for item in repository.list_child_runs(parent.request_id)
                    if CapabilityRequest.model_validate_json(item.request_payload).parameters.resource_type == "document")
    assert document.state == "CANCELLED"
    assert repository.get_tool_result(document.request_id).evidence_id is None
    before = list(calls)
    assert agent.run(task.id).tool_results == result.tool_results
    assert calls == before


def test_missing_chromium_is_a_ci_failure(monkeypatch):
    monkeypatch.setattr(__name__ + ".chromium_available", lambda: False)
    monkeypatch.setenv("RECON_REQUIRE_CHROMIUM", "1")
    with pytest.raises(pytest.fail.Exception, match="Chromium is mandatory"):
        chromium_gate.__wrapped__()


def test_browser_only_endpoint_gets_one_complete_baseline_and_replays(tmp_path, browser_server, forbidden_sink, chromium_gate):
    port, calls = browser_server
    repository, gateway, agent, task = browser_agent(tmp_path, port, BrowserLimits(), http=True, seeds=("/browser-only",))
    before = EndpointDiscovery(repository, agent.planner, agent.service).run(task)
    assert not any(item.canonical_path == "/dynamic" for item in before.endpoints)
    assert ("GET", "/dynamic?source=browser") not in calls
    result = agent.run(task.id)
    endpoint = next(item for item in result.attack_surface_inventory.entries if item.canonical_path == "/dynamic")
    assert endpoint.status == "FUZZ_READY" and endpoint.has_verified_baseline
    assert len(endpoint.observations) == 1
    assert endpoint.observations[0].concrete_url == f"http://127.0.0.1:{port}/dynamic?source=browser"
    assert Counter(calls)[("GET", "/dynamic?source=browser")] == 2
    proofs = [repository.get_tool_result(p.request_ref) for p in endpoint.provenance]
    assert {proof.capability for proof in proofs} == {Capability.BROWSER_REQUEST, Capability.HTTP_FETCH}
    baseline = repository.get_baseline(endpoint.baseline_ref)
    assert baseline.request_id.startswith("browser-baseline-")
    assert baseline.response.body_size > 0 and not baseline.response.truncated
    assert repository.get_policy_decision(baseline.request_id).policy_version == "recon-3.1"
    assert gateway.evidence.read(baseline.evidence_id)
    assert result.coverage.sources == before.coverage.sources and result.coverage.rounds == before.coverage.rounds
    assert not any("/dynamic" in source.url for source in repository.list_sources(task.id))
    counts = Counter(calls)
    reopened = ReconRepository(repository.database_path)
    resumed_gateway = ToolExecutionGateway(PolicyService(reopened), gateway.registry,
                                           EvidenceStore(gateway.evidence.directory, reopened), reopened)
    resumed = ReconAgent(reopened, ReconPlanner(), ReconService(reopened, resumed_gateway))
    assert resumed.run(task.id).attack_surface_inventory == result.attack_surface_inventory
    assert Counter(calls) == counts
    assert forbidden_sink[1] == []


def test_adaptive_browser_proposal_uses_real_boundary_and_baseline(tmp_path, browser_server, forbidden_sink, chromium_gate):
    from src.recon.adaptive_agent import AdaptiveReconAgent
    from src.recon.llm_planner import LLMReconPlanner
    from src.recon.models import ReconPlan
    from tests.test_recon_adaptive_planning import STOP, FakeModel, proposal

    port, calls = browser_server
    repository, gateway, engine, task = browser_agent(tmp_path, port, BrowserLimits(), http=True)
    model = FakeModel({"proposals": [proposal("/browser-only", kind="browser_explore", port=port)]}, STOP)
    original_invoke = model.invoke

    def checked_invoke(messages):
        if not model.contexts:
            assert not any(r.capability == Capability.BROWSER_EXPLORE for r in repository.list_tool_results(task.id))
            assert not any(e.canonical_path == "/dynamic" for e in engine.service.snapshot(task.id).attack_surface_inventory.entries)
        return original_invoke(messages)

    model.invoke = checked_invoke
    agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="fake-browser-v1"))
    result = agent.run(task.id)
    dynamic = next(e for e in result.attack_surface_inventory.entries if e.canonical_path == "/dynamic")
    assert dynamic.status == "FUZZ_READY" and dynamic.has_verified_baseline
    assert Counter(calls)[("GET", "/dynamic?source=browser")] == 2
    row = agent.store.rounds(task.id)[0]
    plan = ReconPlan.model_validate_json(row["plan"])
    parent = plan.actions[0].request
    assert parent.capability == Capability.BROWSER_EXPLORE
    assert repository.get_policy_decision(parent.id).allowed
    assert repository.list_child_runs(parent.id)
    assert any(e["path"] == "/dynamic" for e in model.contexts[1]["routes"])
    count = list(calls)
    reopened = ReconRepository(repository.database_path)
    resumed_gateway = ToolExecutionGateway(PolicyService(reopened), gateway.registry,
        EvidenceStore(gateway.evidence.directory, reopened), reopened)
    resumed = AdaptiveReconAgent(ReconAgent(reopened, ReconPlanner(), ReconService(reopened, resumed_gateway)), agent.planner)
    assert resumed.run(task.id).attack_surface_inventory == result.attack_surface_inventory
    assert calls == count and len(model.contexts) == 2
    assert forbidden_sink[1] == []
