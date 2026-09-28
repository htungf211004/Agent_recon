"""Composition root for the Day-1 Recon execution path."""

from __future__ import annotations

from pathlib import Path
from shutil import which

from src.recon.adapters import HttpFetchAdapter, HttpProbeAdapter, NmapAdapter, WhatWebAdapter
from src.recon.agent import ReconAgent
from src.recon.browser_runtime import chromium_available
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def create_recon_service(database_path: Path | str, evidence_dir: Path | str) -> tuple[ReconRepository, ReconService]:
    """Build the trusted task store and the only production dispatch path."""
    repository = ReconRepository(database_path)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter())
    if which("nmap"):
        registry.register(Capability.NMAP_SCAN, NmapAdapter())
    if which("whatweb"):
        registry.register(Capability.WHATWEB, WhatWebAdapter())
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter())
    gateway = ToolExecutionGateway(
        policy=PolicyService(repository),
        registry=registry,
        evidence=EvidenceStore(evidence_dir, repository),
        results=repository,
    )
    if chromium_available():
        from src.recon.browser import BrowserExploreAdapter

        registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway))
    return repository, ReconService(repository, gateway)


def create_recon_agent(database_path: Path | str, evidence_dir: Path | str) -> tuple[ReconRepository, ReconAgent]:
    repository, service = create_recon_service(database_path, evidence_dir)
    return repository, ReconAgent(repository, ReconPlanner(), service)
