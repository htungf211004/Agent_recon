"""A hostname-only subprocess must never choose its own transport destination."""

from __future__ import annotations

import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from shutil import which

import pytest

from src.recon.adapters import WhatWebAdapter
from src.recon.gateway import AdapterOutput
from src.recon.models import Capability, CapabilityRequest, WhatWebParams
from src.recon.pinned_proxy import pinned_proxy


class _Target(BaseHTTPRequestHandler):
    calls = []

    def do_GET(self):
        self.calls.append((self.path, self.headers.get("Host")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(b"pinned target")))
        self.end_headers()
        self.wfile.write(b"pinned target")
        self.wfile.flush()
        if isinstance(self.connection, ssl.SSLSocket):
            self.connection.unwrap()

    def log_message(self, *_args):
        pass


def _ask(proxy_url: str, request: bytes) -> bytes:
    host, port = proxy_url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=2) as connection:
        connection.settimeout(2)
        connection.sendall(request)
        output = bytearray()
        while True:
            try:
                chunk = connection.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            output.extend(chunk)
        return bytes(output)


def test_pinned_proxy_forwards_only_exact_host_port_read():
    _Target.calls.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with pinned_proxy("example.test", "127.0.0.1", server.server_port) as proxy:
            port = server.server_port
            good = _ask(proxy, f"GET http://example.test:{port}/admin HTTP/1.1\r\n"
                               f"Host: example.test:{port}\r\n\r\n".encode())
            foreign = _ask(proxy, f"GET http://foreign.test:{port}/ HTTP/1.1\r\n"
                                  f"Host: foreign.test:{port}\r\n\r\n".encode())
            write = _ask(proxy, f"POST http://example.test:{port}/ HTTP/1.1\r\n"
                                f"Host: example.test:{port}\r\nContent-Length: 0\r\n\r\n".encode())
            connect = _ask(proxy, f"CONNECT foreign.test:{port} HTTP/1.1\r\n\r\n".encode())
        assert b"pinned target" in good
        assert foreign == write == connect == b""
        assert _Target.calls == [("/admin", f"example.test:{port}")]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_whatweb_hostname_uses_pinned_proxy(monkeypatch):
    _Target.calls.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        def fake_run(command, timeout, *, env):
            assert timeout == 20
            assert command[:4] == ["whatweb", "-a", "1", "--follow-redirect=never"]
            assert command[4] == "--proxy"
            assert command[6] == f"http://example.test:{server.server_port}/"
            assert env["RECON_PIN_HOST"] == "example.test"
            assert env["RECON_PIN_IP"] == "127.0.0.1"
            assert "whatweb_pin.rb" in env["RUBYOPT"]
            result = _ask("http://" + command[5], f"GET {command[6]} HTTP/1.1\r\n"
                                      f"Host: example.test:{server.server_port}\r\n\r\n".encode())
            assert b"pinned target" in result
            return AdapterOutput(status="success", raw_output=b"Apache[2.4]")

        monkeypatch.setattr("src.recon.adapters._run_fixed", fake_run)
        request = CapabilityRequest(id="req", task_id="task", target_ip="127.0.0.1",
                                    target_host="example.test", capability=Capability.WHATWEB,
                                    parameters=WhatWebParams(port=server.server_port))
        result = WhatWebAdapter().execute(request)
        assert result.status == "success"
        assert _Target.calls == [("/", f"example.test:{server.server_port}")]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.mark.skipif(which("whatweb") is None, reason="WhatWeb binary unavailable")
def test_real_whatweb_hostname_uses_pinned_transport():
    _Target.calls.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        request = CapabilityRequest(id="req", task_id="task", target_ip="127.0.0.1",
                                    target_host="example.test", capability=Capability.WHATWEB,
                                    parameters=WhatWebParams(port=server.server_port))
        result = WhatWebAdapter().execute(request)
        assert result.status == "success", result.message + ": " + result.raw_output.decode(errors="replace")
        assert _Target.calls and all(host == f"example.test:{server.server_port}"
                                     for _path, host in _Target.calls), result.raw_output.decode(errors="replace")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


@pytest.mark.skipif(which("whatweb") is None, reason="WhatWeb binary unavailable")
def test_real_whatweb_https_hostname_uses_pinned_transport():
    _Target.calls.clear()
    sni = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Target)
    fixture = Path(__file__).parent / "fixtures" / "tls"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(fixture / "recon-test-cert.pem", fixture / "recon-test-key.pem")
    context.set_servername_callback(lambda _socket, name, _context: sni.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        request = CapabilityRequest(id="req", task_id="task", target_ip="127.0.0.1",
                                    target_host="recon.test", capability=Capability.WHATWEB,
                                    parameters=WhatWebParams(port=server.server_port, scheme="https"))
        result = WhatWebAdapter().execute(request)
        assert result.status == "success", result.message + ": " + result.raw_output.decode(errors="replace")
        assert _Target.calls and all(host == f"recon.test:{server.server_port}"
                                     for _path, host in _Target.calls), result.raw_output.decode(errors="replace")
        assert sni and all(name == "recon.test" for name in sni)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
