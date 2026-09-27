"""Fixed, bounded implementations of the three Day-1 Recon capabilities."""

from __future__ import annotations

import subprocess
import tempfile
from urllib.parse import urlunsplit

import httpx

from src.recon.gateway import AdapterOutput
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityRequest,
    HttpProbeParams,
    NmapScanParams,
    TechnologyObservation,
    WhatWebParams,
)
from src.recon.parsers import parse_nmap, parse_whatweb

MAX_OUTPUT_BYTES = 262_144


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
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False, timeout=5.0) as client:
                response = client.head(url)
        except httpx.HTTPError as exc:
            return AdapterOutput(status="error", message=f"HTTP probe failed: {type(exc).__name__}")
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


def _run_fixed(command: list[str], timeout: int) -> AdapterOutput:
    # Send process output to a file so an unbounded tool response cannot fill RAM.
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        try:
            completed = subprocess.run(
                command, stdout=output_file, stderr=subprocess.STDOUT,
                timeout=timeout, check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            output_file.seek(0)
            return AdapterOutput(
                status="error", raw_output=output_file.read(MAX_OUTPUT_BYTES),
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
            status=output.status, raw_output=output.raw_output, message=output.message,
            attack_surface=entries,
        )


class WhatWebAdapter:
    def execute(self, request: CapabilityRequest) -> AdapterOutput:
        params = request.parameters
        if not isinstance(params, WhatWebParams):
            raise TypeError("WhatWeb parameters required")
        command = ["whatweb", "-a", "1", "--no-redirect", _url(request.target_ip, params.scheme, params.port)]
        output = _run_fixed(command, timeout=20)
        technologies = parse_whatweb(output.raw_output.decode("utf-8", errors="replace"), request.target_ip)
        return AdapterOutput(
            status=output.status, raw_output=output.raw_output, message=output.message,
            technologies=technologies,
        )
