"""Real localhost Chromium gate for passive browser request interception."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from src.recon.browser import BrowserExploreAdapter
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, Capability, CapabilityRequest, ReconTask, Scope
from src.recon.policy import PolicyService
from src.recon.storage import EvidenceStore, ReconRepository


@pytest.fixture
def browser_server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path))
            if self.path == "/":
                body = (
                    b"<html><script src='/app.js'></script>"
                    b"<link rel='stylesheet' href='/style.css'>"
                    b"<a href='/download'>download</a></html>"
                )
                content_type = "text/html"
            elif self.path == "/app.js":
                body = (
                    b"fetch('/api');"
                    b"fetch('/redirect').catch(()=>{});"
                    b"fetch('/submit',{method:'POST'}).catch(()=>{});"
                    b"fetch('http://127.0.0.2:6553/outside').catch(()=>{});"
                    b"try{new WebSocket('ws://127.0.0.1:6553/ws')}catch(e){};"
                    b"if(navigator.serviceWorker){navigator.serviceWorker.register('/sw.js').catch(()=>{})};"
                    b"setTimeout(()=>location.assign('/download'),100);"
                )
                content_type = "application/javascript"
            elif self.path == "/style.css":
                body, content_type = b"body{color:black}", "text/css"
            elif self.path == "/api":
                body, content_type = b'{"ok":true}', "application/json"
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.2:6553/outside")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            else:
                body, content_type = b"not found", "text/plain"
            self.send_response(200 if self.path in {"/", "/app.js", "/style.css", "/api"} else 404)
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


def test_real_chromium_intercepts_each_local_request_once(tmp_path, browser_server):
    playwright = pytest.importorskip("playwright.sync_api")
    try:
        with playwright.sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            browser.close()
    except Exception as exc:
        pytest.skip(f"local Chromium unavailable: {exc}")


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
    assert len(repository.list_endpoints(task.id)) >= 4
    reopened = ReconRepository(tmp_path / "browser.db")
    assert len(reopened.list_child_runs(request.id)) == len(children)
    assert gateway.execute(request) == result
    assert Counter(calls) == paths
