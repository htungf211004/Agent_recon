"""Composition root for the Day-1 Recon execution path."""

from __future__ import annotations

from pathlib import Path
from shutil import which

from src.recon.adapters import FfufAdapter, HttpFetchAdapter, HttpProbeAdapter, NmapAdapter, WhatWebAdapter
from src.recon.agent import ReconAgent
from src.recon.browser_runtime import chromium_available
from src.recon.dns_adapter import DnsResolveAdapter
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.graphql_recon import GraphqlDiscoveryAdapter, GraphqlIntrospectionAdapter
from src.recon.models import Capability
from src.recon.offline_analysis import OfflineEvidenceAdapter
from src.recon.pinned_content import ContentDiscoveryAdapter
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.provider_search import ProviderRouter, RdapAdapter
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def create_recon_service(database_path: Path | str, evidence_dir: Path | str) -> tuple[ReconRepository, ReconService]:
    """Build the trusted task store and the only production dispatch path."""
    repository = ReconRepository(database_path)
    registry = CapabilityRegistry()
    registry.register(Capability.DNS_RESOLVE, DnsResolveAdapter())
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter())
    if which("nmap"):
        registry.register(Capability.NMAP_SCAN, NmapAdapter())
    if which("whatweb"):
        registry.register(Capability.WHATWEB, WhatWebAdapter())
    content = ContentDiscoveryAdapter(FfufAdapter(), ip_available=bool(which("ffuf")))
    registry.register(Capability.CONTENT_DISCOVERY, content)
    registry.register(Capability.EXPOSURE_DISCOVERY, content)
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter())
    registry.register(Capability.GRAPHQL_DISCOVERY, GraphqlDiscoveryAdapter())
    registry.register(Capability.GRAPHQL_INTROSPECTION, GraphqlIntrospectionAdapter())
    gateway = ToolExecutionGateway(
        policy=PolicyService(repository),
        registry=registry,
        evidence=EvidenceStore(evidence_dir, repository),
        results=repository,
    )
    offline = OfflineEvidenceAdapter(gateway.evidence)
    registry.register(Capability.SOURCEMAP_ANALYZE, offline)
    registry.register(Capability.WSDL_DISCOVERY, offline)
    registry.register(Capability.EXTERNAL_ASSET_SEARCH, ProviderRouter(("shodan", "censys", "fofa")))
    registry.register(Capability.PUBLIC_CODE_SEARCH, ProviderRouter(("github", "gitlab")))
    registry.register(Capability.SEARCH_ENGINE_OSINT, ProviderRouter(("brave",)))
    registry.register(Capability.WHOIS_RDAP_LOOKUP, RdapAdapter())
    for capability in Capability:
        if registry.get(capability) is None:
            registry.mark_unavailable(capability, "MISSING_BINARY")
    if chromium_available():
        from src.recon.browser import BrowserExploreAdapter

        registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway))
    return repository, ReconService(repository, gateway)


def create_recon_agent(database_path: Path | str, evidence_dir: Path | str) -> tuple[ReconRepository, ReconAgent]:
    repository, service = create_recon_service(database_path, evidence_dir)
    return repository, ReconAgent(repository, ReconPlanner(), service)
