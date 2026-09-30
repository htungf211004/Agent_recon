"""Pure scope classification. No DNS or network operation occurs here."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from src.contracts.recon_assets import AssetScopeStatus
from src.recon.scope.models import AuthorizationBoundary, DnsObservation
from src.recon.urls import canonical_host, canonical_url


class ScopeDeriver:
    def __init__(self, boundary: AuthorizationBoundary, observations: tuple[DnsObservation, ...] = ()):
        self.boundary = boundary
        self.observations = (*boundary.dns_observations, *observations)

    def classify_host(self, host: str) -> AssetScopeStatus:
        host = canonical_host(host)
        root = self.boundary.root
        if root.kind == "DOMAIN":
            if host == root.value or (root.include_subdomains and host.endswith("." + root.value)
                                      and host.count(".") - root.value.count(".") <= self.boundary.max_host_depth):
                return AssetScopeStatus.IN_SCOPE
            return AssetScopeStatus.OUT_OF_SCOPE
        if host == root.value:
            return AssetScopeStatus.IN_SCOPE
        try:
            ipaddress.ip_address(host)
        except ValueError:
            verified = tuple(observation for observation in self.observations
                             if observation.host == host and observation.evidence_ref)
            if any(root.value in observation.addresses for observation in verified):
                return AssetScopeStatus.IN_SCOPE
            return AssetScopeStatus.OUT_OF_SCOPE if verified else AssetScopeStatus.MANUAL_REVIEW
        return AssetScopeStatus.OUT_OF_SCOPE

    def classify_url(self, url: str) -> AssetScopeStatus:
        return self.classify_host(urlsplit(canonical_url(url)).hostname)
