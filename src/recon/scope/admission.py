"""Canonical root target admission and bounded DNS observation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from src.recon.adapters import bounded_dns_answers
from src.recon.execution import ExecutionBudget
from src.recon.models import Capability, ReconTask, Scope, WebOrigin
from src.recon.profile import ROOT_SEEDS
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget, DnsObservation
from src.recon.urls import canonical_host
from src.recon.web_models import DiscoveryLimits


def parse_target(value: str) -> AuthorizedTarget:
    if not value or value.strip() != value or any(char in value for char in "/\\@?#%"):
        raise ValueError("--target requires a bare domain or literal IP")
    try:
        return AuthorizedTarget(kind="IP", value=str(ipaddress.ip_address(value)))
    except ValueError:
        pass
    if ":" in value or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
        raise ValueError("invalid or ambiguous target")
    return AuthorizedTarget(kind="DOMAIN", value=canonical_host(value), include_subdomains=True)


def resolve_addresses(host: str, port: int, *, limit: int = 8) -> tuple[str, ...]:
    """Resolve once during admission with a hard timeout; execution uses persisted pins."""
    return bounded_dns_answers(host, port, limit=limit)


def admit_target(value: str, task_id: str, *, resolver: Callable[[str, int], tuple[str, ...]] = resolve_addresses,
                 pinned_addresses: tuple[str, ...] | None = None) -> tuple[ReconTask, AuthorizationBoundary]:
    root = parse_target(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id):
        raise ValueError("invalid task-id")
    if root.kind == "DOMAIN":
        scheme, ports = "https", (80, 443, 8080, 8443)
        addresses = pinned_addresses or resolver(root.value, 443)
        observation = DnsObservation(host=root.value, addresses=addresses)
        pin = observation.addresses[0]
        origin = WebOrigin(host=root.value, scheme=scheme, port=443, pinned_ip=pin)
        capabilities = (Capability.DNS_RESOLVE, Capability.HTTP_PROBE, Capability.WHATWEB, Capability.HTTP_FETCH,
                        Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                        Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST,
                        Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY,
                        Capability.GRAPHQL_DISCOVERY,
                        Capability.WHOIS_RDAP_LOOKUP,
                        Capability.EXTERNAL_ASSET_SEARCH, Capability.PUBLIC_CODE_SEARCH,
                        Capability.SEARCH_ENGINE_OSINT)
    else:
        ports = (80, 443, 8080, 8443)
        pin = root.value
        origin = None
        observation = None
        capabilities = (Capability.DNS_RESOLVE, Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB,
                        Capability.HTTP_FETCH, Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                        Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST)
        capabilities += (Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY)
    boundary = AuthorizationBoundary(task_id=task_id, root=root,
                                     dns_observations=(observation,) if observation else ())
    task = ReconTask(
        id=task_id, run_id=task_id,
        scope=Scope(allowed_ips=(pin,), allowed_ports=ports, capabilities=capabilities,
                    allowed_paths=("/",), web_origin=origin, multi_origin=root.kind == "DOMAIN"),
        discovery_seeds=ROOT_SEEDS,
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        discovery_limits=DiscoveryLimits(max_rounds=6, max_requests=64, max_sources=256, max_endpoints=512, max_depth=2),
        execution_budget=ExecutionBudget(max_requests=128, max_body_bytes=65536, max_timeout_seconds=60),
    )
    return task, boundary
