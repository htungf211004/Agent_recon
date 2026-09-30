"""Deterministic read-only verification through Policy and ToolExecutionGateway."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.models import Capability, DnsResolveParams, HttpFetchParams, ReconPlan
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.scope.models import DerivedBinding, DnsObservation
from src.recon.urls import request_url


class AssetVerifier:
    def __init__(self, repository, service):
        self.repository, self.service = repository, service

    def verify(self, task):
        boundary = self.repository.get_authorization(task.id)
        if boundary is None:
            return
        origin = task.scope.web_origin
        port = origin.port if origin else task.scope.allowed_ports[0]
        root_url = request_url(task.scope.allowed_ips[0], origin.scheme if origin else scheme_for_port(port),
                               port, "/", target_host=origin.host if origin else None)
        self.repository.upsert_asset(DiscoveredAsset(
            run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
            asset_type=AssetType.PATH, canonical_value=root_url.rstrip("/") + "/backup.zip",
            relation=AssetRelation.ROOT, discovered_from="default-profile",
            scope_status=AssetScopeStatus.IN_SCOPE, verification_status=AssetVerificationStatus.CLASSIFIED,
        ))
        attempted = 0
        for asset in self.repository.pending_verification_assets(task.id):
            if attempted >= boundary.max_verification_requests:
                self.repository.add_limitation(task.id, "assets:max_verification_requests")
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            if len(self.repository.list_assets(task.id, status=AssetVerificationStatus.VERIFIED)) >= boundary.max_verified_assets:
                self.repository.add_limitation(task.id, "assets:max_verified_assets")
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            if asset.asset_type in {"HOST", "IP"} and asset.relation == "ROOT":
                evidence = next((result.evidence_id for result in self.repository.list_tool_results(task.id)
                                 if result.status == "success" and result.evidence_id
                                 and result.target_ip in task.scope.allowed_ips), None)
                if evidence:
                    try:
                        self.service.gateway.evidence.read(evidence)
                        self.repository.upsert_asset(asset.model_copy(update={
                            "verification_status": AssetVerificationStatus.VERIFIED,
                            "verification_evidence_refs": (evidence,),
                        }))
                        continue
                    except (ValueError, OSError):
                        pass
            if asset.asset_type not in {"PATH", "API", "DOCUMENT", "HOST"}:
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            url = urlsplit(asset.canonical_value if asset.asset_type != "HOST" else
                           f"https://{asset.canonical_value}:443/")
            origin = task.scope.web_origin
            target_ip = (origin.pinned_ip if origin and (url.hostname, url.scheme, url.port) ==
                         (origin.host, origin.scheme, origin.port) else
                         url.hostname if origin is None and url.hostname in task.scope.allowed_ips else None)
            if target_ip is None and boundary.root.kind == "DOMAIN" and url.port in task.scope.allowed_ports:
                binding = self.repository.get_binding(task.id, url.hostname, url.scheme, url.port)
                if binding is None:
                    binding = self._derive_host(task, boundary, url.hostname, url.scheme, url.port)
                    if binding:
                        task = self.repository.get_task(task.id)
                target_ip = binding.address if binding else None
            if target_ip is None or url.port not in task.scope.allowed_ports:
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            prior = next((observation for observation in self.repository.list_observations(task.id)
                          if observation.url == asset.canonical_value and observation.evidence_verified
                          and observation.evidence_id), None)
            if prior:
                try:
                    self.service.gateway.evidence.read(prior.evidence_id)
                    self.repository.upsert_asset(asset.model_copy(update={
                        "verification_status": (AssetVerificationStatus.VERIFIED if prior.response
                                                and prior.response.status_code < 400 else
                                                AssetVerificationStatus.UNREACHABLE),
                        "verification_evidence_refs": (prior.evidence_id,),
                    }))
                    continue
                except (ValueError, OSError):
                    pass
            method = "HEAD" if url.path.lower().endswith((".zip", ".tar", ".gz", ".sql", ".bak", ".map")) else "GET"
            action = ReconPlanner._action(task, target_ip, Capability.HTTP_FETCH, HttpFetchParams(
                port=url.port, scheme=url.scheme, path=url.path, method=method,
                timeout_seconds=min(5, task.execution_budget.max_timeout_seconds),
                max_body_bytes=min(16384, task.execution_budget.max_body_bytes)),
                target_host=url.hostname if task.scope.web_origin and url.hostname != task.scope.web_origin.host else None)
            attempted += 1
            request = action.request
            if not self.service.gateway.policy.decide(request).allowed:
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            try:
                self.service.run(ReconPlan(task_id=task.id, actions=(action,)))
            except RuntimeError:
                return  # In-flight claim is not safe to replay with a new identity.
            result = self.repository.get_tool_result(request.id)
            evidence = result.evidence_id if result else None
            verified_evidence = False
            if evidence:
                try:
                    self.service.gateway.evidence.read(evidence)
                    verified_evidence = True
                except (ValueError, OSError):
                    pass
            status = (AssetVerificationStatus.VERIFIED if result and result.status == "success"
                      and result.http_response and result.http_response.status_code < 400 and verified_evidence
                      else AssetVerificationStatus.BLOCKED if result and result.status == "denied"
                      else AssetVerificationStatus.UNREACHABLE)
            self.repository.upsert_asset(asset.model_copy(update={
                "verification_status": status,
                "verification_evidence_refs": (evidence,) if verified_evidence else (),
            }))

    def _derive_host(self, task, boundary, host, scheme, port):
        if Capability.DNS_RESOLVE not in task.scope.capabilities or self.service.gateway.registry.get(Capability.DNS_RESOLVE) is None:
            return None
        action = ReconPlanner._action(task, task.scope.allowed_ips[0], Capability.DNS_RESOLVE,
                                      DnsResolveParams(host=host, max_answers=boundary.max_dns_addresses_per_host),
                                      target_host=host)
        if not self.service.gateway.policy.decide(action.request).allowed:
            return None
        try:
            self.service.run(ReconPlan(task_id=task.id, actions=(action,)))
        except RuntimeError:
            return None
        result = self.repository.get_tool_result(action.request.id)
        if not result or result.status != "success" or not result.evidence_id:
            return None
        try:
            data = json.loads(self.service.gateway.evidence.read(result.evidence_id))
            if data["host"] != host:
                return None
            observation = DnsObservation(host=host, addresses=tuple(data["addresses"]),
                                         evidence_ref=result.evidence_id)
            self.repository.save_dns_observation(task.id, observation)
            binding = DerivedBinding(task_id=task.id, host=host, address=observation.addresses[0],
                                     scheme=scheme, port=port, dns_evidence_ref=result.evidence_id)
            self.repository.save_binding(binding)
            return binding
        except (ValueError, OSError, TypeError, KeyError):
            return None
