"""Fixed passive CLI profiles. Only normalized references leave this adapter."""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from src.recon.adapters import _run_fixed
from src.recon.gateway import AdapterOutput
from src.recon.models import Capability, LocalOsintCapabilityRequest, ReconObservation
from src.recon.urls import canonical_host


class LocalOsintAdapter:
    def __init__(self, tool: str):
        if tool not in {"subfinder", "amass", "gau"}:
            raise ValueError("unsupported local OSINT tool")
        self.tool = tool

    def execute(self, request: LocalOsintCapabilityRequest) -> AdapterOutput:
        if request.tool != self.tool:
            raise ValueError("local OSINT tool mismatch")
        infrastructure = request.capability == Capability.PASSIVE_INFRA_ENUM
        with tempfile.TemporaryDirectory(prefix="recon-osint-") as directory:
            output_path = Path(directory) / ("amass.json" if infrastructure else "amass.txt")
            command = {
                "subfinder": ["subfinder", "-d", request.root_domain, "-silent"],
                "amass": ["amass", "enum", "-passive", "-d", request.root_domain,
                          "-dir", directory, "-json" if infrastructure else "-o", str(output_path)],
                "gau": ["gau", "--subs", "--providers", "wayback,commoncrawl,otx,urlscan",
                        "--threads", "2", "--timeout", "5", "--retries", "0", request.root_domain],
            }[self.tool]
            env = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "SYSTEMROOT", "WINDIR"}}
            env.update(HOME=directory, USERPROFILE=directory, XDG_CONFIG_HOME=directory,
                       XDG_DATA_HOME=directory, XDG_CACHE_HOME=directory)
            process = _run_fixed(command, timeout=int(request.parameters.timeout_seconds), env=env, cwd=directory)
            if process.status != "success" or "output truncated" in process.message:
                return AdapterOutput(status="error", timed_out=process.timed_out,
                                     message="passive tool failed or exceeded output limit")
            if self.tool == "amass" and not output_path.is_file():
                return AdapterOutput(status="error", message="passive tool produced no result file")
            if self.tool == "amass" and output_path.is_file():
                with output_path.open("rb") as stream:
                    raw = stream.read(262145)
            else:
                raw = process.raw_output
        if len(raw) > 262144:
            return AdapterOutput(status="error", message="passive tool exceeded output limit")
        observations: list[ReconObservation] = []
        seen: set[str] = set()
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            if infrastructure:
                try:
                    row = json.loads(line)
                    name = self._normalized(row.get("name", ""), request.root_domain)
                    if name is None:
                        continue
                    values = [("HOST", name)]
                    addresses = row.get("addresses") or []
                    if not isinstance(addresses, list):
                        raise ValueError("invalid address collection")
                    for address in addresses[:32]:
                        try:
                            ip = ipaddress.ip_address(address.get("ip", ""))
                            if not ip.is_unspecified and not ip.is_multicast:
                                values.append(("IP", str(ip)))
                            asn = address.get("asn")
                            if type(asn) is int and 0 < asn <= 4294967295:
                                values.append(("METADATA", f"asn:{asn}"))
                        except (ValueError, TypeError):
                            continue
                except (ValueError, TypeError, AttributeError):
                    return AdapterOutput(status="error", message="invalid passive infrastructure output")
                for kind, value in values:
                    key = kind + ":" + value
                    if key not in seen:
                        seen.add(key)
                        if len(observations) < request.parameters.max_results:
                            observations.append(ReconObservation(kind=kind, value=value,
                                source=request.capability, provider=self.tool))
                continue
            value = self._normalized(line.strip(), request.root_domain)
            if value is None or value in seen:
                continue
            seen.add(value)
            if len(observations) >= request.parameters.max_results:
                break
            observations.append(ReconObservation(
                kind="URL" if self.tool == "gau" else "HOST", value=value,
                source=request.capability, provider=self.tool,
            ))
        normalized = json.dumps({"tool": self.tool, "root_domain": request.root_domain,
                                 "observations": [item.model_dump(mode="json") for item in observations]},
                                sort_keys=True, separators=(",", ":")).encode()
        metadata_missing = infrastructure and not any(row.kind in {"IP", "METADATA"} for row in observations)
        return AdapterOutput(status="success", raw_output=normalized,
                             observations=tuple(observations),
                             message=("passive_infra:metadata_unavailable" if metadata_missing else
                                      "result limit reached" if len(seen) > len(observations) else ""))

    def _normalized(self, value: str, root_domain: str) -> str | None:
        if len(value) > 2048 or any(ord(char) < 32 for char in value):
            return None
        if self.tool == "gau":
            try:
                parts = urlsplit(value)
                if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
                    return None
                _port = parts.port  # Reject malformed numeric ports before persisting a reference.
                host = canonical_host(parts.hostname)
            except ValueError:
                return None
            if host != root_domain and not host.endswith("." + root_domain):
                return None
            return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path or "/", "", ""))
        try:
            host = canonical_host(value.rstrip("."))
        except ValueError:
            return None
        return host if host == root_domain or host.endswith("." + root_domain) else None


class LocalOsintRouter:
    def __init__(self, tools: tuple[str, ...]):
        self.adapters = {tool: LocalOsintAdapter(tool) for tool in tools}

    def availability(self, tool: str | None = None) -> str:
        from shutil import which

        if tool is None:
            return "AVAILABLE" if any(which(name) for name in self.adapters) else "MISSING_BINARY"
        return "AVAILABLE" if tool in self.adapters and which(tool) else "MISSING_BINARY"

    def execute(self, request: LocalOsintCapabilityRequest) -> AdapterOutput:
        return self.adapters[request.tool].execute(request)
