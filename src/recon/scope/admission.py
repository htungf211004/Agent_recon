"""Canonical root target admission and bounded DNS observation."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from src.recon.adapters import bounded_dns_answers
from src.recon.execution import ExecutionBudget
from src.recon.models import Capability, ReconTask, Scope, WebOrigin
from src.recon.profile import ROOT_SEEDS
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget, DnsObservation
from src.recon.urls import canonical_host, validate_path
from src.recon.web_models import DiscoveryLimits


@dataclass(frozen=True)
class CanonicalRoot:
    root: AuthorizedTarget
    scheme: str | None = None
    port: int | None = None
    path: str = "/"
    explicit_origin: bool = False


def normalize_target_input(value: str) -> CanonicalRoot:
    """Normalize domain, IP, URL and host:port into one immutable root authority."""
    if not value or value.strip() != value or any(ord(char) <= 32 for char in value):
        raise ValueError("invalid target")
    try:
        return CanonicalRoot(parse_target(value))
    except ValueError:
        pass
    try:
        parts = urlsplit(value if "://" in value else "//" + value)
        if (parts.scheme not in {"", "http", "https"} or parts.username or parts.password
                or parts.query or parts.fragment or not parts.hostname or parts.port is not None and
                not 1 <= parts.port <= 65535):
            raise ValueError("invalid target URL")
        if "://" in value and not value.startswith(("http://", "https://")):
            raise ValueError("invalid target URL")
        path = validate_path(parts.path or "/")
        root = parse_target(parts.hostname)
        scheme = parts.scheme or ("https" if parts.port in {443, 8443, 9443} else "http")
        port = parts.port or (443 if scheme == "https" else 80)
        default_domain = (root.kind == "DOMAIN" and scheme == "https" and port == 443 and path == "/")
        return CanonicalRoot(root, None if default_domain else scheme,
                             None if default_domain else port, path, not default_domain)
    except (ValueError, TypeError) as error:
        raise ValueError("invalid target input") from error


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
    normalized = normalize_target_input(value)
    root = normalized.root
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id):
        raise ValueError("invalid task-id")
    if root.kind == "DOMAIN":
        scheme, ports = normalized.scheme or "https", (normalized.port,) if normalized.port else (80, 443, 8080, 8443)
        addresses = pinned_addresses or resolver(root.value, normalized.port or 443)
        observation = DnsObservation(host=root.value, addresses=addresses)
        pin = observation.addresses[0]
        origin = WebOrigin(host=root.value, scheme=scheme, port=normalized.port or 443, pinned_ip=pin)
        capabilities = (Capability.DNS_RESOLVE, Capability.HTTP_PROBE, Capability.WHATWEB, Capability.HTTP_FETCH,
                        Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                        Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST,
                        Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY,
                        Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION,
                        Capability.PARAMETER_DISCOVERY,
                        Capability.WHOIS_RDAP_LOOKUP,
                        Capability.EXTERNAL_ASSET_SEARCH, Capability.PUBLIC_CODE_SEARCH,
                        Capability.SEARCH_ENGINE_OSINT)
        capabilities += (Capability.PASSIVE_SUBDOMAIN_ENUM, Capability.PASSIVE_INFRA_ENUM,
                         Capability.HISTORICAL_URL_DISCOVERY, Capability.WEB_CRAWL,
                         Capability.VHOST_DISCOVERY, Capability.TECHNOLOGY_SCAN)
    else:
        ports = (normalized.port,) if normalized.port else (80, 443, 8080, 8443)
        pin = root.value
        origin = (WebOrigin(host=root.value, scheme=normalized.scheme, port=normalized.port,
                           pinned_ip=pin) if normalized.explicit_origin else None)
        observation = None
        capabilities = (Capability.DNS_RESOLVE, Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB,
                        Capability.HTTP_FETCH, Capability.CONTENT_DISCOVERY, Capability.EXPOSURE_DISCOVERY,
                        Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST)
        capabilities += (Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY,
                         Capability.WEB_CRAWL, Capability.TECHNOLOGY_SCAN,
                         Capability.PARAMETER_DISCOVERY, Capability.GRAPHQL_DISCOVERY,
                         Capability.GRAPHQL_INTROSPECTION)
    boundary = AuthorizationBoundary(task_id=task_id, root=root,
                                     dns_observations=(observation,) if observation else ())
    task = ReconTask(
        id=task_id, run_id=task_id,
        scope=Scope(allowed_ips=(pin,), allowed_ports=ports, capabilities=capabilities,
                    allowed_paths=(normalized.path,), web_origin=origin,
                    multi_origin=root.kind == "DOMAIN" and not normalized.explicit_origin),
        discovery_seeds=ROOT_SEEDS if normalized.path == "/" else (normalized.path,),
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
        discovery_limits=DiscoveryLimits(max_rounds=6, max_requests=64, max_sources=256, max_endpoints=512, max_depth=2),
        execution_budget=ExecutionBudget(max_requests=128, max_body_bytes=65536, max_timeout_seconds=60),
    )
    return task, boundary
