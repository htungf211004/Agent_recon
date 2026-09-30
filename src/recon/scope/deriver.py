"""Pure scope classification. No DNS or network operation occurs here."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from src.contracts.recon_assets import AssetScopeStatus
from src.recon.scope.models import AuthorizationBoundary
from src.recon.urls import canonical_host, canonical_url


class ScopeDeriver:
    def __init__(self, boundary: AuthorizationBoundary):
        self.boundary = boundary

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
            if any(observation.host == host and root.value in observation.addresses
                   and observation.evidence_ref for observation in self.boundary.dns_observations):
                return AssetScopeStatus.IN_SCOPE
            return AssetScopeStatus.MANUAL_REVIEW
        return AssetScopeStatus.OUT_OF_SCOPE

    def classify_url(self, url: str) -> AssetScopeStatus:
        return self.classify_host(urlsplit(canonical_url(url)).hostname)
