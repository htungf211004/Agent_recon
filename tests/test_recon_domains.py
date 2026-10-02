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
from src.recon.urls import canonical_url, known_transport_ip, scoped_ip
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


@pytest.mark.parametrize(("url", "known_ip", "in_scope"), [
    ("https://recon.test/", "192.0.2.10", True),
    ("https://recon.test:8443/", "192.0.2.10", False),
    ("http://192.0.2.10/", "192.0.2.10", False),
    ("https://192.0.2.10/", "192.0.2.10", False),
    ("https://other.test/", None, False),
    ("https://recon.test:bad/", None, False),
])
def test_known_redirect_transport_is_independent_of_execution_scope(url, known_ip, in_scope):
    task = scoped_task("https://recon.test/", "redirect-facts", pinned_ip="192.0.2.10")
    if known_ip is None and url.endswith(":bad/"):
        with pytest.raises(ValueError):
            known_transport_ip(task.scope, url)
        return
    assert known_transport_ip(task.scope, url) == known_ip
    assert (scoped_ip(task.scope, url) is not None) == in_scope


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


def test_tls_pinned_ip_preserves_sni_and_certificate_validation(tmp_path):
    # MemoryBIO avoids Windows loopback TLS interception while using real OpenSSL verification.
    sni = []
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(TLS / "recon-test-cert.pem", TLS / "recon-test-key.pem")
    server_context.set_servername_callback(lambda _socket, name, _ctx: sni.append(name))

    def handshake(host, trust):
        client_context = (ssl.create_default_context(cafile=str(TLS / "recon-test-ca.pem"))
                          if trust else ssl.create_default_context())
        client_input, client_output = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_input, server_output = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_context.wrap_bio(client_input, client_output, server_side=False, server_hostname=host)
        server = server_context.wrap_bio(server_input, server_output, server_side=True)
        client_done = server_done = False
        for _ in range(20):
            if not client_done:
                try:
                    client.do_handshake()
                    client_done = True
                except ssl.SSLWantReadError:
                    pass
            data = client_output.read()
            if data:
                server_input.write(data)
            if not server_done:
                try:
                    server.do_handshake()
                    server_done = True
                except ssl.SSLWantReadError:
                    pass
            data = server_output.read()
            if data:
                client_input.write(data)
            if client_done and server_done:
                return
        raise AssertionError("TLS handshake did not finish")

    handshake("recon.test", True)
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake("recon.test", False)
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake("wrong.test", True)
    assert sni == ["recon.test", "recon.test", "wrong.test"]

    seen = []

    def inspect(request):
        seen.append((request.url.host, request.headers["Host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    task = scoped_task("https://recon.test:443/", "tls-pinned", pinned_ip="127.0.0.1")
    agent = engine(tmp_path, task, HttpFetchAdapter(httpx.MockTransport(inspect)))
    request = ReconPlanner._action(task, "127.0.0.1", Capability.HTTP_FETCH,
                                   HttpFetchParams(port=443, scheme="https", max_body_bytes=65536)).request
    result = agent.service.gateway.execute(request)
    assert result.status == "success", result.message
    assert seen == [("127.0.0.1", "recon.test:443", "recon.test")]


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
