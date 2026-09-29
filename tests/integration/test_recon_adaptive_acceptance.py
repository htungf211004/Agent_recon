"""Real localhost worker acceptance: dynamic root, redirect sink and crash recovery."""

import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseRequestHandler, ThreadingTCPServer
from threading import Thread

import pytest

from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.llm_planner import LLMReconPlanner
from src.recon.models import BrowserLimits, Capability
from tests.integration.test_recon_browser_local_e2e import browser_agent, chromium_gate  # noqa: F401
from tests.test_recon_adaptive_planning import STOP, FakeModel, proposal


@pytest.fixture
def root_server():
    calls, sink_connections = [], []

    class Sink(BaseRequestHandler):
        def handle(self):
            sink_connections.append(True)  # Records a TCP accept, including attempted TLS traffic.

    sink = ThreadingTCPServer(("127.0.0.1", 0), Sink)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.command, self.path))
            if self.path == "/redirect":
                self.send_response(301)
                self.send_header("Location", f"https://127.0.0.1:{sink.server_address[1]}/forbidden")
                body = b""
            else:
                self.send_response(200)
                body = (b"<html><script>const u=String.fromCharCode(47)+['dy','namic'].join('');fetch(u);</script>"
                        b"<form method='post' action='/write'><input name='q'></form></html>"
                        if self.path == "/" else b'{"ok":true}')
                self.send_header("Content-Type", "text/html" if self.path == "/" else "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threads = [Thread(target=s.serve_forever, daemon=True) for s in (server, sink)]
    for thread in threads:
        thread.start()
    try:
        yield server.server_port, calls, sink.server_address[1], sink_connections
    finally:
        for s in (server, sink):
            s.shutdown()
            s.server_close()
        for thread in threads:
            thread.join(timeout=5)


@pytest.mark.parametrize("crash_at", ["none", "browser_projection", "baseline_projection", "executed"])
def test_root_dynamic_browser_runs_only_after_durable_decision_and_restart(tmp_path, root_server, chromium_gate, monkeypatch, crash_at):  # noqa: F811
    from src.recon import adaptive_agent, baseline_promotion

    port, calls, _, sink_calls = root_server
    repository, gateway, engine, task = browser_agent(tmp_path, port, BrowserLimits(), http=True, seeds=("/",))
    model = FakeModel({"proposals": [proposal("/", kind="browser_explore", port=port)]}, STOP)
    agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="root-acceptance-v1"))
    invoke = model.invoke

    def checked(messages):
        if not model.contexts:
            assert not repository.list_child_runs("anything")
            assert not any(r.capability == Capability.BROWSER_EXPLORE for r in repository.list_tool_results(task.id))
            assert not any(r["path"] == "/dynamic" for r in json.loads(messages[1][1])["routes"])
        return invoke(messages)

    model.invoke = checked
    adapter = gateway.registry.get(Capability.BROWSER_EXPLORE)
    dispatch = adapter.execute

    def authorized_dispatch(request):
        row = agent.store.rounds(task.id)[0]
        assert row["state"] == "VALIDATED" and row["decision"] and row["plan"]
        return dispatch(request)

    monkeypatch.setattr(adapter, "execute", authorized_dispatch)
    if crash_at != "none":
        target, name = {
            "browser_projection": (adaptive_agent, "project_action"),
            "baseline_projection": (baseline_promotion.BrowserBaselinePromotion, "_promote"),
            "executed": (agent.store, "executed"),
        }[crash_at]
        original = getattr(target, name)

        def crash(*_args, **_kwargs):
            raise RuntimeError("acceptance crash")

        monkeypatch.setattr(target, name, crash)
        with pytest.raises(RuntimeError, match="acceptance crash"):
            agent.run(task.id)
        assert len(model.contexts) == 1
        monkeypatch.setattr(target, name, original)
    result = agent.run(task.id)
    dynamic = next(e for e in result.attack_surface_inventory.entries if e.canonical_path == "/dynamic")
    assert dynamic.status == "FUZZ_READY" and dynamic.has_verified_baseline
    assert result.worker_status == "COMPLETED" and result.handoff_ready
    assert Counter(calls)[("GET", "/dynamic")] == 2  # Browser response plus independent HTTP baseline.
    assert not any(method != "GET" or path == "/write" for method, path in calls)
    before = list(calls)
    assert agent.run(task.id).attack_surface_inventory == result.attack_surface_inventory
    assert calls == before and len(model.contexts) == 2 and sink_calls == []


def test_real_offscope_https_redirect_has_zero_sink_tcp_dispatch_and_no_handoff(tmp_path, root_server):
    port, calls, sink_port, sink_calls = root_server
    _, _, engine, task = browser_agent(tmp_path, port, BrowserLimits(), http=True, seeds=("/redirect",))
    model = FakeModel(STOP)
    agent = AdaptiveReconAgent(engine, LLMReconPlanner(model, planner_id="redirect-acceptance"))
    result = agent.run(task.id)
    route = model.contexts[0]["routes"][0]
    assert route["last_status_code"] == 301 and route["baseline_blocker"] == "NON_2XX"
    assert route["redirect"] == {"present": True, "target_scheme": "https", "target_port": sink_port,
                                  "same_target_ip": True, "scope_status": "OUT_OF_SCOPE"}
    assert result.worker_status == "COMPLETED" and not result.handoff_ready
    assert "handoff:no_fuzz_ready" in result.coverage.limitations
    assert calls == [("GET", "/redirect")] and sink_calls == []
