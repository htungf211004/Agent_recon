"""Fixed, bounded implementations of the three Day-1 Recon capabilities."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from shutil import which
from urllib.parse import urlsplit, urlunsplit

import httpx

from src.recon.gateway import AdapterOutput
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    HttpProbeParams,
    NmapScanParams,
    TechnologyObservation,
    WhatWebParams,
)
from src.recon.parsers import parse_nmap, parse_whatweb
from src.recon.urls import request_url
from src.recon.web_models import HttpResponseMetadata

MAX_OUTPUT_BYTES = 262_144


def bounded_dns_answers(host: str, port: int, *, limit: int = 8, timeout: float = 8) -> tuple[str, ...]:
    """Trusted bounded resolver used by admission and the Gateway DNS adapter."""
    script = ("import json,socket,sys; print(json.dumps(sorted({a[4][0] for a in "
              "socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))")
    try:
        result = subprocess.run([sys.executable, "-c", script, host, str(port)], capture_output=True,
                                timeout=timeout, check=True, shell=False,
                                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
        addresses = sorted({str(ipaddress.ip_address(item)) for item in json.loads(result.stdout)},
                           key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
        addresses = tuple(item for item in addresses if not (ipaddress.ip_address(item).is_unspecified
                                                              or ipaddress.ip_address(item).is_multicast))
        if not addresses or len(addresses) > limit:
            raise ValueError("DNS answer count exceeds policy")
        return addresses
    except (OSError, subprocess.SubprocessError, TypeError, IndexError, ValueError):
        raise ValueError("bounded DNS resolution failed") from None


class HttpFetchAdapter:
    """Read a bounded response from the literal IP authorized by the gateway."""

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self.transport = transport

    def execute(self, request: CapabilityRequest) -> AdapterOutput:
        params = request.parameters
        if not isinstance(params, HttpFetchParams):
            raise TypeError("HTTP fetch parameters required")
        url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query, target_host=request.target_host)
        transport_url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query)
        transport_options = ({"headers": {"Host": urlsplit(url).netloc},
                              "extensions": {"sni_hostname": request.target_host}} if request.target_host else {})
        deadline = time.monotonic() + params.timeout_seconds
        body = bytearray()
        truncated = False
        message = ""
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False,
                              verify=ssl.create_default_context() if request.target_host else True,
                              timeout=params.timeout_seconds, headers={"Accept-Encoding": "identity"}) as client:
                with client.stream(params.method, transport_url, **transport_options) as response:
                    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                        truncated = True
                        message = "encoded response body not supported"
                    elif params.method == "GET":
                        for chunk in response.iter_raw():
                            if time.monotonic() > deadline:
                                raise httpx.ReadTimeout("total HTTP fetch deadline exceeded")
                            remaining = params.max_body_bytes - len(body)
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                message = "HTTP body size limit reached"
                                break
                    metadata = HttpResponseMetadata(
                        status_code=response.status_code,
                        content_type=response.headers.get("content-type", "")[:512],
                        body_size=len(body), body_sha256=hashlib.sha256(body).hexdigest(), truncated=truncated,
                    )
                    envelope = {
                        "url": url, "method": params.method, "response": metadata.model_dump(),
                        "body_base64": base64.b64encode(body).decode("ascii"),
                        "location": response.headers.get("location", "")[:2048],
                        "source_map": (response.headers.get("x-sourcemap") or response.headers.get("sourcemap") or "")[:2048],
                        **({"pinned_ip": request.target_ip, "authority": urlsplit(url).netloc} if request.target_host else {}),
                    }
                    return AdapterOutput(
                        status="error" if truncated else "success",
                        message=message or f"HTTP {response.status_code}",
                        raw_output=json.dumps(envelope, separators=(",", ":")).encode(),
                        http_response=metadata,
                    )
        except httpx.HTTPError as exc:
            return AdapterOutput(status="error", timed_out=isinstance(exc, httpx.TimeoutException), message=f"HTTP fetch failed: {type(exc).__name__}")


def _url(target_ip: str, scheme: str, port: int) -> str:
    host = f"[{target_ip}]" if ":" in target_ip else target_ip
    return urlunsplit((scheme, f"{host}:{port}", "/", "", ""))


class HttpProbeAdapter:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self.transport = transport

    def execute(self, request: CapabilityRequest) -> AdapterOutput:
        params = request.parameters
        if not isinstance(params, HttpProbeParams):
            raise TypeError("HTTP probe parameters required")
        url = _url(request.target_ip, params.scheme, params.port)
        origin = request_url(request.target_ip, params.scheme, params.port, "/", target_host=request.target_host)
        options = ({"headers": {"Host": urlsplit(origin).netloc},
                    "extensions": {"sni_hostname": request.target_host}} if request.target_host else {})
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False, timeout=5.0,
                              verify=ssl.create_default_context() if request.target_host else True) as client:
                response = client.head(url, **options)
        except httpx.HTTPError as exc:
            return AdapterOutput(status="error", timed_out=isinstance(exc, httpx.TimeoutException), message=f"HTTP probe failed: {type(exc).__name__}")
        lines = [f"HTTP {response.status_code}"]
        for header in ("server", "content-type", "x-powered-by", "location"):
            if header in response.headers:
                lines.append(f"{header}: {response.headers[header][:500]}")
        raw = "\n".join(lines).encode("utf-8")[:MAX_OUTPUT_BYTES]
        technologies = []
        for header in ("server", "x-powered-by"):
            value = response.headers.get(header, "").strip()
            if value:
                name, _, version = value.partition("/")
                technologies.append(TechnologyObservation(
                    target_ip=request.target_ip, name=name[:100], version=version[:100],
                    source=Capability.HTTP_PROBE,
                ))
        return AdapterOutput(
            status="success", raw_output=raw,
            message=f"HTTP {response.status_code}",
            attack_surface=(AttackSurfaceEntry(
                target_ip=request.target_ip, port=params.port, service=params.scheme,
            ),),
            technologies=tuple(technologies),
        )


def _run_fixed(command: list[str], timeout: int, *, env=None, cwd=None) -> AdapterOutput:
    # Send process output to a file so an unbounded tool response cannot fill RAM.
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        try:
            completed = subprocess.run(
                command, stdout=output_file, stderr=subprocess.STDOUT,
                timeout=timeout, check=False, shell=False,
                env=env, cwd=cwd, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            output_file.seek(0)
            return AdapterOutput(
                status="error", timed_out=True, raw_output=output_file.read(MAX_OUTPUT_BYTES),
                message=f"tool timed out after {timeout}s",
            )
        except FileNotFoundError:
            return AdapterOutput(status="error", message=f"tool unavailable: {command[0]}")
        output_file.seek(0)
        raw = output_file.read(MAX_OUTPUT_BYTES)
        truncated = bool(output_file.read(1))
    return AdapterOutput(
        status="success" if completed.returncode == 0 else "error",
        raw_output=raw,
        message=(f"tool exit code {completed.returncode}" if completed.returncode else "") +
        ("; output truncated" if truncated else ""),
    )


class NmapAdapter:
    def execute(self, request: CapabilityRequest) -> AdapterOutput:
        params = request.parameters
        if not isinstance(params, NmapScanParams):
            raise TypeError("Nmap parameters required")
        # Every argument is constructed here from validated typed values.
        command = ["nmap", "-sT", "-sV", "-Pn", "-n", "--max-retries", "1", "-p", ",".join(map(str, params.ports)), request.target_ip]
        output = _run_fixed(command, timeout=60)
        entries = parse_nmap(output.raw_output.decode("utf-8", errors="replace"), request.target_ip)
        return AdapterOutput(
            status=output.status, timed_out=output.timed_out, raw_output=output.raw_output, message=output.message,
            attack_surface=entries,
        )


class WhatWebAdapter:
    def execute(self, request: CapabilityRequest) -> AdapterOutput:
        params = request.parameters
        if not isinstance(params, WhatWebParams):
            raise TypeError("WhatWeb parameters required")
        command = ["whatweb", "-a", "1", "--follow-redirect=never"]
        if request.target_host:
            from src.recon.pinned_proxy import pinned_proxy

            # WhatWeb resolves before consulting its proxy. The process-local
            # resolver shim permits only the persisted binding. For HTTP, the
            # loopback proxy enforces the same binding on each request.
            env = dict(os.environ)
            env.update(RECON_PIN_HOST=request.target_host, RECON_PIN_IP=request.target_ip,
                       RUBYOPT="-r" + str(Path(__file__).with_name("whatweb_pin.rb")))
            url = request_url(request.target_ip, params.scheme, params.port, "/",
                              target_host=request.target_host)
            if params.scheme == "http":
                with pinned_proxy(request.target_host, request.target_ip, params.port) as proxy:
                    output = _run_fixed([*command, "--proxy", proxy.removeprefix("http://"), url],
                                        timeout=20, env=env)
            else:
                # WhatWeb 0.5.5 starts TLS before CONNECT when a proxy is set;
                # use its direct TLS path with pinned DNS for correct SNI.
                command.append(url)
                output = _run_fixed(command, timeout=20, env=env)
        else:
            command.append(_url(request.target_ip, params.scheme, params.port))
            output = _run_fixed(command, timeout=20)
        if b"ERROR Opening:" in output.raw_output:
            return AdapterOutput(status="error", timed_out=output.timed_out,
                                 raw_output=output.raw_output, message="WhatWeb could not open target")
        technologies = parse_whatweb(output.raw_output.decode("utf-8", errors="replace"), request.target_ip)
        return AdapterOutput(
            status=output.status, timed_out=output.timed_out, raw_output=output.raw_output, message=output.message,
            technologies=technologies,
        )


class FfufAdapter:
    """HEAD-only small path discovery; no bodies, redirects, calibration or recursion."""

    def execute(self, request):
        from src.recon.content_discovery import parse_ffuf
        from src.recon.models import ContentDiscoveryParams
        from src.recon.wordlists import load_wordlist

        params = request.parameters
        if not isinstance(params, ContentDiscoveryParams):
            raise TypeError("content discovery parameters required")
        binary = which("ffuf")
        if not binary:
            return AdapterOutput(status="error", message="ffuf unavailable")
        wordlist = load_wordlist(params.wordlist_id)
        with tempfile.TemporaryDirectory(prefix="recon-ffuf-") as directory:
            # No inherited proxy, credentials, FFUF config, or history; fixed literal-IP URL.
            env = {key: value for key, value in os.environ.items() if key in {"PATH", "SYSTEMROOT", "WINDIR"}}
            env.update(HOME=directory, USERPROFILE=directory, XDG_CONFIG_HOME=directory,
                       XDG_DATA_HOME=directory, XDG_CACHE_HOME=directory)
            output_path = Path(directory) / "results.json"
            command = [binary, "-w", str(wordlist.path.resolve()), "-u",
                       request_url(request.target_ip, params.scheme, params.port, params.path_prefix + "FUZZ"),
                       "-X", "HEAD", "-t", "1", "-p", "0.5", "-timeout", "2", "-maxtime", "15",
                       "-ignore-body", "-H", "Connection: close",
                       "-r=false", "-recursion=false", "-ac=false", "-s", "-mc", "all", "-fc", "404",
                       "-of", "json", "-o", str(output_path)]
            output = _run_fixed(command, timeout=20, env=env, cwd=directory)
            if output.status != "success":
                return AdapterOutput(status="error", timed_out=output.timed_out, message="content discovery failed")
            try:
                with output_path.open("rb") as stream:
                    raw = stream.read(MAX_OUTPUT_BYTES + 1)
                candidates = parse_ffuf(raw, request)
            except (OSError, ValueError, TypeError, KeyError):
                return AdapterOutput(status="error", message="invalid or oversized ffuf result")
            # Persist only typed bounded facts, not FFUF command/config dumps.
            envelope = {"wordlist_id": wordlist.id, "wordlist_sha256": wordlist.sha256,
                        "method": "HEAD", "candidates": candidates}
            return AdapterOutput(status="success", raw_output=json.dumps(envelope, separators=(",", ":")).encode())
