"""Deterministic optional provider phase and evidence-based candidate projection."""

import hashlib

from src.contracts.recon_assets import AssetRelation, AssetType
from src.recon.asset_extraction import record_candidate
from src.recon.models import (
    Capability,
    LocalOsintCapabilityRequest,
    LocalOsintParams,
    ProviderCapabilityRequest,
    ProviderParams,
)

PROFILES = (
    (Capability.WHOIS_RDAP_LOOKUP, "rdap", "root_domain"),
    (Capability.EXTERNAL_ASSET_SEARCH, "shodan", "root_domain"),
    (Capability.EXTERNAL_ASSET_SEARCH, "censys", "root_domain"),
    (Capability.EXTERNAL_ASSET_SEARCH, "fofa", "root_domain"),
    (Capability.PUBLIC_CODE_SEARCH, "github", "public_code"),
    (Capability.PUBLIC_CODE_SEARCH, "gitlab", "public_code"),
    *((Capability.SEARCH_ENGINE_OSINT, "brave", profile) for profile in
      ("PUBLIC_DOCUMENTS", "ADMIN_LOGIN", "DIRECTORY_INDEX", "CONFIG_FILES", "BACKUP_FILES")),
)


class ExternalOsintExecutor:
    def __init__(self, repository, gateway):
        self.repository, self.gateway = repository, gateway

    def run(self, task):
        boundary = self.repository.get_authorization(task.id)
        if boundary is None or boundary.root.kind != "DOMAIN":
            return
        for tool, capability in (("subfinder", Capability.PASSIVE_SUBDOMAIN_ENUM),
                                 ("amass", Capability.PASSIVE_INFRA_ENUM),
                                 ("gau", Capability.HISTORICAL_URL_DISCOVERY)):
            if capability not in task.scope.capabilities:
                continue
            if self.gateway.registry.availability(capability, tool) != "AVAILABLE":
                continue
            limit = (task.execution_budget.max_historical_urls if tool == "gau" else
                     task.execution_budget.max_subdomains // 2)
            if limit == 0:
                continue
            identity = hashlib.sha256(f"{task.id}\0{capability.value}\0{tool}".encode()).hexdigest()[:24]
            request = LocalOsintCapabilityRequest(id=f"osint-{identity}", task_id=task.id,
                root_domain=boundary.root.value, capability=capability, tool=tool,
                parameters=LocalOsintParams(max_results=min(limit, 512), timeout_seconds=20))
            result = self.gateway.execute(request)
            if result.status == "success" and result.evidence_id:
                try:
                    if self.gateway.evidence.read(result.evidence_id) is not None:
                        self._project(task, boundary, result)
                except (ValueError, OSError):
                    self.repository.add_limitation(task.id, f"osint:{tool}:evidence_unavailable")
            elif result.status != "success":
                self.repository.add_limitation(task.id, f"osint:{tool}:failed")
        if task.execution_budget.max_external_results == 0:
            self.repository.add_limitation(task.id, "osint:result_budget_zero")
            return
        for capability, provider, profile in PROFILES:
            if capability not in task.scope.capabilities:
                continue
            if self.gateway.registry.availability(capability, provider) != "AVAILABLE":
                continue
            if provider == "rdap" and boundary.root.value.rsplit(".", 1)[-1] not in {"com", "net"}:
                continue
            identity = hashlib.sha256(f"{task.id}\0{capability.value}\0{provider}\0{profile}".encode()).hexdigest()[:24]
            request = ProviderCapabilityRequest(id=f"osint-{identity}", task_id=task.id,
                root_domain=boundary.root.value, capability=capability, provider=provider,
                parameters=ProviderParams(profile=profile,
                    max_results=min(25, task.execution_budget.max_external_results)))
            result = self.gateway.execute(request)
            if result.status != "success" or not result.evidence_id:
                self.repository.add_limitation(task.id, f"osint:{provider}:failed")
                continue
            if result.message == "result limit reached":
                self.repository.add_limitation(task.id, f"osint:{provider}:result_limit")
            try:
                if self.gateway.evidence.read(result.evidence_id) is None:
                    continue
            except (ValueError, OSError):
                continue
            self._project(task, boundary, result)

    def _project(self, task, boundary, result):
        base = f"https://{boundary.root.value}/"
        for observation in result.observations:
            if observation.kind == "HOST":
                hosts = {asset.canonical_value for asset in self.repository.list_assets(task.id)
                         if asset.asset_type == AssetType.HOST}
                if len(hosts) >= task.execution_budget.max_subdomains:
                    self.repository.add_limitation(task.id, "osint:subdomain_limit")
                    break
                record_candidate(self.repository, task, boundary, base, result.evidence_id,
                                 f"https://{observation.value}/", AssetRelation.OTHER_REFERENCE)
            elif observation.kind == "URL":
                record_candidate(self.repository, task, boundary, base, result.evidence_id,
                                 observation.value, AssetRelation.OTHER_REFERENCE)
            elif observation.kind == "IP":
                from src.contracts.recon_assets import AssetScopeStatus, AssetVerificationStatus, DiscoveredAsset

                if len(self.repository.list_assets(task.id)) >= boundary.max_discovered_assets:
                    self.repository.add_limitation(task.id, "assets:max_discovered_assets")
                    continue
                self.repository.upsert_asset(DiscoveredAsset(
                    run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
                    asset_type=AssetType.IP, canonical_value=observation.value,
                    relation=AssetRelation.OTHER_REFERENCE, discovered_from=base,
                    discovery_evidence_refs=(result.evidence_id,),
                    scope_status=AssetScopeStatus.MANUAL_REVIEW,
                    verification_status=AssetVerificationStatus.MANUAL_REVIEW))
            elif observation.kind in {"CODE_REFERENCE", "SEARCH_REFERENCE"} and observation.value.startswith("https://"):
                record_candidate(self.repository, task, boundary, base, result.evidence_id,
                                 observation.value, AssetRelation.OTHER_REFERENCE)
