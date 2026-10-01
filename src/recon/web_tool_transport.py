"""Bounded HTTP bridge from a local CLI to one trusted pinned origin."""

import re
import ssl
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from src.recon.models import Capability
from src.recon.urls import path_allowed, request_url, validate_path
from src.recon.wordlists import load_wordlist


class WebToolBridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, request, task, *, hosts=(), transport=None):
        self.request, self.task, self.hosts = request, task, set(hosts)
        self.transport = transport
        self.count = 0
        self.failed = False
        self.lock = threading.Lock()
        self.deadline = time.monotonic() + request.parameters.timeout_seconds
        self.next_request = time.monotonic()
        super().__init__(("127.0.0.1", 0), _Handler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.target_origin = request_url(request.target_ip, request.parameters.scheme,
                                        request.parameters.port, "/", target_host=request.target_host).rstrip("/")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        pass

    def do_CONNECT(self):
        self._reject()

    def do_POST(self):
        self._reject()

    do_PUT = do_POST  # noqa: N815
    do_DELETE = do_POST  # noqa: N815
    do_PATCH = do_POST  # noqa: N815
    do_OPTIONS = do_POST  # noqa: N815

    def do_HEAD(self):
        self._fetch()

    def do_GET(self):
        self._fetch()

    def _reject(self):
        self.server.failed = True
        self.send_error(403)

    def _fetch(self):
        bridge = self.server
        request, params = bridge.request, bridge.request.parameters
        try:
            parts = urlsplit(self.path)
            local = urlsplit(bridge.origin)
            # Katana v1.1.0 detects Burp proxies with this fixed probe. Answer
            # locally; it is never resolved or forwarded to any target.
            if request.capability == Capability.WEB_CRAWL and self.command == "GET" and self.path == "http://burpsuite/":
                self.send_error(403)
                return
            # Go's HTTP proxy serialization uses the overridden Host as the
            # absolute URI authority for FFUF. Map only packaged candidates
            # back onto the same pin; never resolve this authority.
            vhost_proxy = (request.capability == Capability.VHOST_DISCOVERY and parts.scheme == "http"
                           and parts.hostname in bridge.hosts and parts.port in {None, 80})
            if parts.scheme and (parts.scheme != "http" or parts.netloc != local.netloc) and not vhost_proxy:
                return self._reject()
            path = parts.path or "/"
            try:
                validate_path(path)
            except ValueError:
                return self._reject()
            if not path_allowed(path, bridge.task.scope.allowed_paths) or self.command not in bridge.task.scope.allowed_methods:
                return self._reject()
            if self.headers.get("Content-Length", "0") != "0" or self.headers.get("Transfer-Encoding"):
                return self._reject()
            if request.capability == Capability.VHOST_DISCOVERY and (self.command != "HEAD" or path != "/"):
                return self._reject()
            if request.capability == Capability.TECHNOLOGY_SCAN and (self.command != "GET" or path != "/"):
                return self._reject()
            if request.capability == Capability.PARAMETER_DISCOVERY and (self.command != "GET" or path != params.path):
                return self._reject()
            host = request.target_host or request.target_ip
            if request.capability == Capability.VHOST_DISCOVERY:
                host = self.headers.get("Host", "").split(":", 1)[0]
                if host not in bridge.hosts:
                    return self._reject()
                if vhost_proxy and host != parts.hostname:
                    return self._reject()
            query = ""
            if request.capability == Capability.PARAMETER_DISCOVERY:
                fields = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=128)
                permitted = set(load_wordlist(params.wordlist_id).entries)
                fields = [(key, value) for key, value in fields
                          if key in permitted or re.fullmatch(r"z[A-Za-z0-9]{5}", key)]
                if len(fields) > 16 or any(len(value) > 64 for key, value in fields):
                    return self._reject()
                # Arjun uses generated z-prefixed controls for response stability.
                query = urlencode(fields)
            with bridge.lock:
                if bridge.count >= params.max_requests or time.monotonic() >= bridge.deadline:
                    return self._reject()
                bridge.count += 1
                delay = max(0, bridge.next_request - time.monotonic())
                bridge.next_request = max(time.monotonic(), bridge.next_request) + .5
            if delay:
                time.sleep(delay)
            if time.monotonic() >= bridge.deadline:
                return self._reject()
            display = request_url(request.target_ip, params.scheme, params.port, path, query,
                                  target_host=host)
            target = request_url(request.target_ip, params.scheme, params.port, path, query)
            with httpx.Client(transport=bridge.transport, follow_redirects=False, trust_env=False,
                              verify=ssl.create_default_context() if request.target_host else True,
                              timeout=min(3, max(.1, bridge.deadline - time.monotonic()))) as client:
                with client.stream(self.command, target, headers={"Host": urlsplit(display).netloc,
                    "Accept-Encoding": "identity"}, extensions={"sni_hostname": request.target_host or host}) as response:
                    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                        return self._reject()
                    body = bytearray()
                    if self.command == "GET":
                        for chunk in response.iter_raw():
                            if len(body) + len(chunk) > params.max_body_bytes or time.monotonic() >= bridge.deadline:
                                return self._reject()
                            body.extend(chunk)
                    content_type = response.headers.get("content-type", "")
                    if "html" in content_type or "javascript" in content_type:
                        body = body.replace(bridge.target_origin.encode(), bridge.origin.encode())
                        original = urlsplit(bridge.target_origin)
                        if original.port in {80, 443}:
                            body = body.replace(f"{original.scheme}://{original.hostname}".encode(), bridge.origin.encode())
                    if len(body) > params.max_body_bytes:
                        return self._reject()
                    self.send_response(response.status_code)
                    # Redirects and credentials cannot cross from upstream into the CLI.
                    for key in ("Content-Type", "Server", "X-Powered-By"):
                        if key.lower() in response.headers:
                            self.send_header(key, response.headers[key][:512])
                    length = response.headers.get("content-length", "0") if self.command == "HEAD" else str(len(body))
                    self.send_header("Content-Length", length if length.isdigit() else "0")
                    self.end_headers()
                    if self.command == "GET":
                        self.wfile.write(body)
        except (ValueError, OSError, httpx.HTTPError):
            bridge.failed = True
            try:
                self.send_error(502)
            except OSError:
                pass


@contextmanager
def web_tool_bridge(request, task, **kwargs):
    bridge = WebToolBridge(request, task, **kwargs)
    worker = threading.Thread(target=bridge.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
    worker.start()
    try:
        yield bridge
    finally:
        bridge.deadline = time.monotonic()
        bridge.shutdown()
        bridge.server_close()
        worker.join(timeout=1)
