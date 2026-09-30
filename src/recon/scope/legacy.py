"""Compatibility admission for explicit URL and IP/port missions."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from src.recon.adapters import bounded_dns_answers
from src.recon.execution import ExecutionBudget
from src.recon.models import Capability, ReconTask, Scope, WebOrigin
from src.recon.planner import scheme_for_port
from src.recon.urls import canonical_host, canonical_url, path_allowed, validate_path
from src.recon.web_models import DiscoveryLimits


def resolve_pin(host: str, port: int) -> str:
    """Operator admission only: bound OS DNS lifetime and freeze one IP."""
    host = canonical_host(host)
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        return bounded_dns_answers(host, port, limit=8)[0]
    except ValueError:
        raise ValueError("DNS resolution failed or timed out; check hostname/network") from None


def scoped_task(url: str, task_id: str, *, path_prefix: str | None = None, browser: bool = False,
                ports: tuple[int, ...] | None = None, content_discovery: bool = False, full_profile: bool = False,
                pinned_ip: str | None = None, resolver: Callable[[str, int], str] = resolve_pin) -> ReconTask:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id):
        raise ValueError("task-id must contain 1-64 letters, digits, hyphens or underscores")
    target = urlsplit(canonical_url(url))
    try:
        target_ip = str(ipaddress.ip_address(target.hostname))
        domain = False
    except ValueError:
        domain = True
        target_ip = None
    bound = domain or target.scheme != scheme_for_port(target.port)
    if bound and (full_profile or content_discovery):
        raise ValueError("hostname/explicit-scheme URLs support HTTP and Browser; use an IP mission for Nmap/WhatWeb/FFUF")
    if pinned_ip and not domain and pinned_ip != target_ip:
        raise ValueError("literal IP must match the supplied pin")
    prefix = validate_path(path_prefix if path_prefix is not None else target.path)
    if not path_allowed(target.path, (prefix,)):
        raise ValueError("target URL is outside the supplied path prefix")
    capabilities = (Capability.HTTP_FETCH,)
    if full_profile:
        capabilities = (Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB, Capability.HTTP_FETCH)
    if browser:
        capabilities += (Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST)
    if content_discovery:
        capabilities += (Capability.CONTENT_DISCOVERY,)
    if ports is not None and target.port not in ports:
        raise ValueError("URL port must be explicitly authorized")
    target_ip = target_ip or pinned_ip or resolver(target.hostname, target.port)
    origin = WebOrigin(host=target.hostname, scheme=target.scheme, port=target.port, pinned_ip=target_ip) if bound else None
    seed = target.path + ("?" + target.query if target.query else "")
    return ReconTask(
        id=task_id, run_id=task_id,
        scope=Scope(allowed_ips=(target_ip,), allowed_ports=tuple(sorted(set(ports))) if ports else (target.port,),
                    allowed_paths=(prefix,), allowed_methods=("GET", "HEAD"), capabilities=capabilities, web_origin=origin),
        discovery_seeds=() if full_profile and target.path == "/" else (seed,),
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        discovery_limits=DiscoveryLimits(max_rounds=2, max_requests=24, max_sources=16, max_endpoints=64, max_depth=2),
        execution_budget=ExecutionBudget(max_requests=64 if full_profile else 40, max_body_bytes=65536,
                                         max_timeout_seconds=60 if full_profile else 30),
    )
