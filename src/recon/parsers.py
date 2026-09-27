"""Deterministic observations from Nmap and WhatWeb output."""

from __future__ import annotations

import re

from src.recon.models import AttackSurfaceEntry, Capability, TechnologyObservation

# Adapted from pentest_ai_v2/core/analyzer.py::parse_nmap_output.
_NMAP_PORT = re.compile(r"^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", re.MULTILINE)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_WHATWEB_PLUGIN = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*)\[([^\]]*)\]")


def parse_nmap(raw: str, target_ip: str) -> tuple[AttackSurfaceEntry, ...]:
    entries = []
    for match in _NMAP_PORT.finditer(raw):
        port, protocol, service, version = match.groups()
        if not 1 <= int(port) <= 65535:
            continue
        entries.append(AttackSurfaceEntry(
            target_ip=target_ip, port=int(port), protocol=protocol,
            service=service, version=(version or "").strip(),
        ))
    return tuple(entries)


def parse_whatweb(raw: str, target_ip: str) -> tuple[TechnologyObservation, ...]:
    clean = _ANSI.sub("", raw)
    summary = next((line.partition(":")[2] for line in clean.splitlines() if line.strip().startswith("Summary")), "")
    if not summary:
        summary = next((line for line in clean.splitlines() if "[200" in line or "[301" in line), "")
    observations = []
    seen = set()
    for name, details in _WHATWEB_PLUGIN.findall(summary):
        versions = [part.strip() for part in details.split(",") if re.fullmatch(r"\d[\w.+-]*", part.strip())]
        version = max(versions, key=len, default="")
        key = (name.lower(), version)
        if key not in seen:
            seen.add(key)
            observations.append(TechnologyObservation(
                target_ip=target_ip, name=name, version=version, source=Capability.WHATWEB,
            ))
    return tuple(observations)
