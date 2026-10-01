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
from src.recon.models import (
    Capability,
    DnsResolveParams,
    HttpFetchParams,
    ReconPlan,
)
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.profile import BACKUP_PROBE
from src.recon.scope.deriver import ScopeDeriver
from src.recon.scope.models import DerivedBinding, DnsObservation
from src.recon.urls import request_url


class AssetVerifier:
    def __init__(self, repository, service):
        self.repository, self.service = repository, service

    def verify(self, task):
        boundary = self.repository.get_authorization(task.id)
        if boundary is None:
            return
        if boundary.root.kind == "IP":
            for asset in self.repository.list_assets(task.id):
                if asset.asset_type == "HOST" and asset.scope_status == AssetScopeStatus.MANUAL_REVIEW:
                    self._derive_host(task, boundary, asset.canonical_value, "https", 443)
                    task = self.repository.get_task(task.id)
            deriver = ScopeDeriver(boundary, self.repository.list_dns_observations(task.id))
            for asset in self.repository.list_assets(task.id):
                if asset.scope_status != AssetScopeStatus.MANUAL_REVIEW:
                    continue
                host = asset.canonical_value if asset.asset_type == "HOST" else urlsplit(asset.canonical_value).hostname
                scope = deriver.classify_host(host)
                if scope == AssetScopeStatus.MANUAL_REVIEW:
                    continue
                status = (AssetVerificationStatus.CLASSIFIED if scope == AssetScopeStatus.IN_SCOPE
                          else AssetVerificationStatus.BLOCKED)
                self.repository.upsert_asset(asset.model_copy(update={"scope_status": scope,
                                                                "verification_status": status}))
        for asset in self.repository.list_assets(task.id):
            if asset.asset_type == "HOST" and asset.scope_status == AssetScopeStatus.IN_SCOPE and asset.relation != "ROOT":
                source = next((item for item in self.repository.list_assets(task.id)
                               if item.canonical_value.startswith(("http://" + asset.canonical_value + ":",
                                                                   "https://" + asset.canonical_value + ":"))), None)
                if source:
                    parts = urlsplit(source.canonical_value)
                    if not self.repository.get_binding(task.id, parts.hostname, parts.scheme, parts.port):
                        self._derive_host(task, boundary, parts.hostname, parts.scheme, parts.port)
                        task = self.repository.get_task(task.id)
        task = self.repository.get_task(task.id)
        origin = task.scope.web_origin
        port = origin.port if origin else task.scope.allowed_ports[0]
        root_url = request_url(task.scope.allowed_ips[0], origin.scheme if origin else scheme_for_port(port),
                               port, "/", target_host=origin.host if origin else None)
        verified_roots = []
        for run in self.repository.list_tool_runs(task.id):
            if not run.request_payload:
                continue
            from src.recon.models import parse_target_request

            request = parse_target_request(run.request_payload)
            if request is None:
                continue
            if request.capability != Capability.HTTP_PROBE:
                continue
            result = self.repository.get_tool_result(request.id)
            if not result or result.status != "success" or not result.attack_surface or not result.evidence_id:
                continue
            try:
                self.service.gateway.evidence.read(result.evidence_id)
            except (ValueError, OSError):
                continue
            params = request.parameters
            verified_roots.append(request_url(request.target_ip, params.scheme, params.port, "/",
                                              target_host=request.target_host))
        for base in sorted(set(verified_roots)) or [root_url]:
            self.repository.upsert_asset(DiscoveredAsset(
                run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
                asset_type=AssetType.PATH, canonical_value=base.rstrip("/") + BACKUP_PROBE,
                relation=AssetRelation.ROOT, discovered_from="default-profile",
                scope_status=AssetScopeStatus.IN_SCOPE, verification_status=AssetVerificationStatus.CLASSIFIED,
            ))
        for script in (item for item in self.repository.list_assets(task.id)
                       if item.scope_status == AssetScopeStatus.IN_SCOPE
                       and urlsplit(item.canonical_value).path.lower().endswith(".js")):
            if len(self.repository.list_assets(task.id)) >= boundary.max_discovered_assets:
                break
            self.repository.upsert_asset(DiscoveredAsset(
                run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
                asset_type=AssetType.PATH, canonical_value=script.canonical_value + ".map",
                relation=AssetRelation.JS_REFERENCE, discovered_from="default-profile",
                discovery_evidence_refs=script.discovery_evidence_refs,
                scope_status=AssetScopeStatus.IN_SCOPE,
                verification_status=AssetVerificationStatus.CLASSIFIED,
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
            if asset.asset_type == "HOST":
                observation = next((item for item in self.repository.list_dns_observations(task.id)
                                    if item.host == asset.canonical_value and item.evidence_ref), None)
                if observation:
                    self.repository.upsert_asset(asset.model_copy(update={
                        "verification_status": AssetVerificationStatus.VERIFIED,
                        "verification_evidence_refs": (observation.evidence_ref,),
                    }))
                    continue
            if asset.asset_type not in {"PATH", "API", "DOCUMENT", "HOST"}:
                self.repository.upsert_asset(asset.model_copy(update={"verification_status": AssetVerificationStatus.BLOCKED}))
                continue
            url = urlsplit(asset.canonical_value if asset.asset_type != "HOST" else
                           f"https://{asset.canonical_value}:443/")
            origin = task.scope.web_origin
            target_ip = (origin.pinned_ip if origin and url.hostname == origin.host and
                         ((url.scheme, url.port) == (origin.scheme, origin.port) or
                          task.scope.multi_origin and url.port in task.scope.allowed_ports and
                          url.scheme == scheme_for_port(url.port)) else
                         url.hostname if origin is None and url.hostname in task.scope.allowed_ips else None)
            if target_ip is None and url.port in task.scope.allowed_ports:
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
                target_host=url.hostname if url.hostname != target_ip else None)
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
        prior = next((item for item in self.repository.list_dns_observations(task.id)
                      if item.host == host and item.evidence_ref), None)
        if prior:
            if boundary.root.kind == "IP" and boundary.root.value not in prior.addresses:
                return None
            address = boundary.root.value if boundary.root.kind == "IP" else prior.addresses[0]
            binding = DerivedBinding(task_id=task.id, host=host, address=address,
                                     scheme=scheme, port=port, dns_evidence_ref=prior.evidence_ref)
            try:
                self.repository.save_binding(binding)
                return binding
            except ValueError:
                return None
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
            raw = self.service.gateway.evidence.read(result.evidence_id)
            data = json.loads(raw)
            if data["host"] != host:
                return None
            observation = DnsObservation(host=host, addresses=tuple(data["addresses"]),
                                         evidence_ref=result.evidence_id)
            self.repository.save_dns_observation(task.id, observation, raw)
            if boundary.root.kind == "IP" and boundary.root.value not in observation.addresses:
                return None
            address = boundary.root.value if boundary.root.kind == "IP" else observation.addresses[0]
            binding = DerivedBinding(task_id=task.id, host=host, address=address,
                                     scheme=scheme, port=port, dns_evidence_ref=result.evidence_id)
            self.repository.save_binding(binding)
            return binding
        except (ValueError, OSError, TypeError, KeyError):
            return None
