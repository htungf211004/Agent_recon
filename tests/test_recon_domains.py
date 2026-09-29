"""Pinned hostname admission, real HTTP/TLS, and Chromium authorization gates."""

import hashlib
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from scripts.run_recon_live import scoped_task
from src.recon.adapters import HttpFetchAdapter
from src.recon.agent import ReconAgent
from src.recon.browser import BrowserExploreAdapter, child_request
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, BrowserLimits, Capability, HttpFetchParams
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.urls import canonical_url, scoped_ip
from tests.integration.test_recon_browser_local_e2e import chromium_gate, forbidden_sink  # noqa: F401

TLS = Path(__file__).parent / "fixtures" / "tls"


@pytest.fixture
def domain_server(forbidden_sink):  # noqa: F811
    sink, sink_calls = forbidden_sink
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get("Host")))
            content = "text/html"
            if self.path == "/":
                body = (f'<html><a href="/about">About</a><script>fetch("/dynamic");'
                        f'fetch("{sink}/forbidden").catch(()=>{{}});'
                        f'fetch("http://outside.test:{self.server.server_port}/outside").catch(()=>{{}});'
                        'fetch("/write",{method:"POST"}).catch(()=>{});</script></html>').encode()
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", sink + "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            else:
                body, content = b'{"ok":true}', "application/json"
            self.send_response(200)
            self.send_header("Content-Type", content)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_HEAD = do_GET  # noqa: N815

        def do_POST(self):
            calls.append((self.command, self.path, self.headers.get("Host")))
            self.send_response(405)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, calls, sink_calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def engine(tmp_path, task, adapter=None, browser=False):
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, adapter or HttpFetchAdapter())
    gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    if browser:
        registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway))
    return ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))


def test_operator_url_supports_domain_fragment_and_explicit_scheme(monkeypatch):
    resolutions = []
    def resolve(host, port):
        resolutions.append((host, port))
        return "192.0.2.10"
    monkeypatch.setattr("scripts.run_recon_live.resolve_pin", resolve)
    task = scoped_task("https://juice-shop.herokuapp.com/#/", "domain-demo", browser=True)
    assert task.scope.web_origin.host == "juice-shop.herokuapp.com"
    assert task.scope.allowed_ips == ("192.0.2.10",)
    assert task.discovery_seeds == ("/",)
    assert resolutions == [("juice-shop.herokuapp.com", 443)]
    custom = scoped_task("https://recon.test:9001/path", "custom", pinned_ip="127.0.0.1")
    assert custom.scope.web_origin.scheme == "https" and custom.scope.allowed_ports == (9001,)
    assert canonical_url("https://EXAMPLE.com/#/") == "https://example.com:443/"
    assert scoped_ip(task.scope, "https://juice-shop.herokuapp.com/") == "192.0.2.10"
    assert scoped_ip(task.scope, "https://other.herokuapp.com/") is None


@pytest.mark.parametrize("url", ["http://127.1/", "http://2130706433/", "http://0x7f000001/",
                                     "http://bad%00.test/", "file:///tmp/secret", "https://u:p@recon.test/"])
def test_ambiguous_urls_are_still_rejected(url):
    with pytest.raises(ValueError):
        scoped_task(url, "bad", pinned_ip="127.0.0.1")


def test_hostname_http_dispatch_pins_ip_and_replays_without_dns(tmp_path, domain_server, monkeypatch):
    port, calls, sink = domain_server
    task = scoped_task(f"http://recon.test:{port}/", "http-domain", pinned_ip="127.0.0.1")
    agent = engine(tmp_path, task)
    request = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH, HttpFetchParams(port=port, max_body_bytes=65536)).request
    original = socket.getaddrinfo
    def guarded(host, *args, **kwargs):
        assert host != "recon.test", "runtime must not re-resolve the domain"
        return original(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", guarded)
    first = agent.service.gateway.execute(request)
    assert first.status == "success", first.message
    assert agent.service.gateway.execute(request) == first
    assert calls == [("GET", "/", f"recon.test:{port}")]
    evidence = json.loads(agent.service.gateway.evidence.read(first.evidence_id))
    assert evidence["url"] == f"http://recon.test:{port}/"
    assert evidence["pinned_ip"] == "127.0.0.1"
    redirect = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                                   HttpFetchParams(port=port, path="/redirect", max_body_bytes=65536)).request
    assert agent.service.gateway.execute(redirect).http_response.status_code == 302
    assert sink == []
    for field, value in (("target_host", "outside.test"), ("target_host", None), ("target_ip", "127.0.0.2")):
        forged = request.model_copy(update={"id": field + str(value), field: value, "action_fingerprint": None})
        assert agent.service.gateway.execute(forged).status == "denied"
    assert len(calls) == 2


def test_real_tls_pinned_ip_preserves_sni_and_certificate_validation(tmp_path):
    calls, sni = [], []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(self.headers["Host"])
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS / "recon-test-cert.pem", TLS / "recon-test-key.pem")
    context.set_servername_callback(lambda _socket, name, _ctx: sni.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        trusted = ssl.create_default_context(cafile=str(TLS / "recon-test-cert.pem"))
        for name, host, trust, expected in (("valid", "recon.test", True, "success"),
                                           ("untrusted", "recon.test", False, "error"),
                                           ("mismatch", "wrong.test", True, "error")):
            task = scoped_task(f"https://{host}:{server.server_port}/", name, pinned_ip="127.0.0.1")
            adapter = HttpFetchAdapter(httpx.HTTPTransport(verify=trusted)) if trust else HttpFetchAdapter()
            agent = engine(tmp_path / name, task, adapter)
            request = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                                           HttpFetchParams(port=server.server_port, scheme="https", max_body_bytes=65536)).request
            result = agent.service.gateway.execute(request)
            assert result.status == expected, result.message
        assert calls == [f"recon.test:{server.server_port}"]
        assert sni == ["recon.test", "recon.test", "wrong.test"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_hostname_browser_policy_child_identity_inventory_and_zero_sink(tmp_path, domain_server, chromium_gate):  # noqa: F811
    port, calls, sink = domain_server
    task = scoped_task(f"http://recon.test:{port}/", "browser-domain", pinned_ip="127.0.0.1", browser=True)
    agent = engine(tmp_path, task, browser=True)
    request = ReconPlanner._action(task, "127.0.0.1", Capability.BROWSER_EXPLORE,
        BrowserExploreParams(port=port, limits=BrowserLimits(max_pages=2, max_depth=1))).request
    child = child_request(request, f"http://recon.test:{port}/dynamic", "GET", "fetch")
    assert child.target_host == "recon.test" and child.target_ip == "127.0.0.1"
    assert child.id != child_request(request, f"http://recon.test:{port}/dynamic", "GET", "fetch", 1).id
    with pytest.raises(ValueError):
        child_request(request, f"http://other.test:{port}/", "GET", "document")
    with pytest.raises(ValueError):
        child_request(request, f"http://recon.test:{port}/write", "POST", "fetch")
    result = agent.service.gateway.execute(request)
    assert result.status == "success", result.message
    assert calls and all(method == "GET" and host == f"recon.test:{port}" for method, _, host in calls)
    assert not any(path in {"/write", "/outside"} for _, path, _ in calls) and sink == []
    before = list(calls)
    assert agent.service.gateway.execute(request) == result
    assert calls == before
    from src.recon.baseline_promotion import BrowserBaselinePromotion
    inventory = BrowserBaselinePromotion(agent.repository, agent.planner, agent.service).run(task).attack_surface_inventory
    dynamic = next(e for e in inventory.entries if e.canonical_path == "/dynamic")
    assert dynamic.authority == f"recon.test:{port}" and dynamic.resolved_ip == "127.0.0.1"
    assert dynamic.status == "FUZZ_READY" and dynamic.has_verified_baseline
    for reference in dynamic.evidence_refs:
        raw = agent.service.gateway.evidence.read(reference)
        assert hashlib.sha256(raw).hexdigest() == agent.repository.get_evidence(reference).sha256
