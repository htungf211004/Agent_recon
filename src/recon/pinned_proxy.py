"""Loopback proxy that binds a hostname-only tool to one authorized transport IP."""

from __future__ import annotations

import select
import socket
import socketserver
import threading
from contextlib import contextmanager
from urllib.parse import urlsplit

MAX_HEAD = 8192
MAX_CONNECTIONS = 8
MAX_TRANSFER = 2 * 1024 * 1024


class _PinnedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, host: str, address: str, port: int):
        self.authorized_host = host
        self.pinned_address = address
        self.authorized_port = port
        self.connection_count = 0
        self.count_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _PinnedHandler)


class _PinnedHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        with server.count_lock:
            server.connection_count += 1
            if server.connection_count > MAX_CONNECTIONS:
                return
        self.request.settimeout(5)
        head = bytearray()
        try:
            while not head.endswith(b"\r\n\r\n") and len(head) < MAX_HEAD:
                part = self.request.recv(1)
                if not part:
                    return
                head.extend(part)
            if not head.endswith(b"\r\n\r\n"):
                return
            lines = head.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                return
            headers = {}
            for line in lines[1:-2]:
                name, separator, value = line.partition(":")
                if not separator or name.lower() in headers:
                    return
                headers[name.lower()] = value.strip()
            if headers.get("content-length", "0") != "0" or "transfer-encoding" in headers:
                return
            if method == "CONNECT":
                authority = urlsplit("//" + target)
                if authority.hostname != server.authorized_host or authority.port != server.authorized_port:
                    return
                with socket.create_connection((server.pinned_address, server.authorized_port), timeout=5) as upstream:
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    self._tunnel(upstream)
                return
            if method not in {"GET", "HEAD"}:
                return
            url = urlsplit(target)
            if (url.scheme != "http" or url.hostname != server.authorized_host
                    or url.port != server.authorized_port or url.username or url.password
                    or url.fragment or headers.get("host", "").lower()
                    not in {server.authorized_host, f"{server.authorized_host}:{server.authorized_port}"}):
                return
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            forwarded = [f"{method} {path} {version}",
                         f"Host: {server.authorized_host}:{server.authorized_port}"]
            for name, value in headers.items():
                if name not in {"host", "connection", "proxy-connection", "proxy-authorization"}:
                    forwarded.append(f"{name}: {value}")
            forwarded.append("Connection: close")
            with socket.create_connection((server.pinned_address, server.authorized_port), timeout=5) as upstream:
                upstream.settimeout(5)
                upstream.sendall(("\r\n".join(forwarded) + "\r\n\r\n").encode("iso-8859-1"))
                remaining = MAX_TRANSFER
                while remaining > 0:
                    chunk = upstream.recv(min(16384, remaining))
                    if not chunk:
                        break
                    self.request.sendall(chunk)
                    remaining -= len(chunk)
        except (OSError, UnicodeError, ValueError):
            return

    def _tunnel(self, upstream):
        sockets = (self.request, upstream)
        remaining = MAX_TRANSFER
        while remaining > 0:
            readable, _, _ = select.select(sockets, (), (), 5)
            if not readable:
                return
            for source in readable:
                data = source.recv(min(16384, remaining))
                if not data:
                    return
                (upstream if source is self.request else self.request).sendall(data)
                remaining -= len(data)


@contextmanager
def pinned_proxy(host: str, address: str, port: int):
    """Expose only the exact host:port and forward to its persisted address."""
    server = _PinnedServer(host, address, port)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
