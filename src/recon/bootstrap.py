"""Composition root for the Day-1 Recon execution path."""

from __future__ import annotations

from pathlib import Path

from src.recon.adapters import HttpProbeAdapter, NmapAdapter, WhatWebAdapter
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def create_recon_service(database_path: Path | str, evidence_dir: Path | str) -> tuple[ReconRepository, ReconService]:
    """Build the trusted task store and the only production dispatch path."""
    repository = ReconRepository(database_path)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter())
    registry.register(Capability.NMAP_SCAN, NmapAdapter())
    registry.register(Capability.WHATWEB, WhatWebAdapter())
    gateway = ToolExecutionGateway(
        policy=PolicyService(repository),
        registry=registry,
        evidence=EvidenceStore(evidence_dir, repository),
        results=repository,
    )
    return repository, ReconService(repository, gateway)
