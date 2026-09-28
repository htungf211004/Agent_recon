"""Convert verified Recon records into the versioned product Attack Surface DTO."""

import base64
import hashlib
import json
from datetime import UTC, datetime
from urllib.parse import urlsplit

from src.contracts.attack_surface import AttackSurfaceEntry, AttackSurfaceInventory, Observation, Provenance
from src.recon.endpoints import fuzz_ready, has_unresolved_required_input, is_testable
from src.recon.models import Capability
from src.recon.urls import path_allowed
from src.recon.web_models import EndpointLifecycle, stable_id


def build_inventory(task, repository, evidence):
    observations = repository.list_observations(task.id)
    verified = {}

    def read_proof(request_id, evidence_id):
        key = (request_id, evidence_id)
        if key not in verified:
            result = repository.get_tool_result(request_id)
            artifact = repository.get_evidence(evidence_id)
            try:
                valid = (result and result.task_id == task.id and result.evidence_id == evidence_id and artifact
                         and artifact.task_id == task.id and artifact.request_id == request_id
                         and artifact.run_id == task.run_id and artifact.tool_run_id == request_id)
                verified[key] = evidence.read(evidence_id) if valid else None
            except (ValueError, OSError):
                verified[key] = None
        return verified[key]

    entries = []
    for route in repository.list_endpoints(task.id):
        origin = urlsplit(route.url)
        in_scope = bool(
            task.expires_at.tzinfo and task.expires_at > datetime.now(UTC)
            and Capability.HTTP_FETCH in task.scope.capabilities
            and origin.hostname in task.scope.allowed_ips and origin.port in task.scope.allowed_ports
            and route.method in task.scope.allowed_methods and path_allowed(origin.path, task.scope.allowed_paths)
        )
        dtos = []
        provenance = []
        valid_observations = set()
        for observation in (item for item in observations if item.endpoint_id == route.id):
            proofs = []
            for item in observation.provenance:
                if item.request_id and item.evidence_id and read_proof(item.request_id, item.evidence_id) is not None:
                    proofs.append(Provenance(source_ref=item.source_id, observation_ref=observation.id,
                                             request_ref=item.request_id, evidence_ref=item.evidence_id,
                                             kind=item.kind.value, relation=item.relation))
            raw = read_proof(observation.request_id, observation.evidence_id) if observation.request_id and observation.evidence_id else None
            if raw is not None:
                try:
                    envelope = json.loads(raw)
                    body = base64.b64decode(envelope["body_base64"], validate=True)
                    response = observation.response
                    tool_result = repository.get_tool_result(observation.request_id)
                    if (response and envelope["url"] == observation.url and envelope["method"] == observation.method
                            and envelope["response"] == response.model_dump() and tool_result.http_response == response
                            and len(body) == response.body_size and hashlib.sha256(body).hexdigest() == response.body_sha256):
                        valid_observations.add(observation.id)
                        proofs.append(Provenance(source_ref=observation.id, observation_ref=observation.id,
                                                 request_ref=observation.request_id, evidence_ref=observation.evidence_id,
                                                 kind="http_response", relation="response"))
                except (ValueError, KeyError, TypeError):
                    pass
            if observation.evidence_verified != (observation.id in valid_observations):
                repository.save_observation(observation.model_copy(update={
                    "evidence_verified": observation.id in valid_observations,
                }))
            if proofs:
                unique = {item.model_dump_json(): item for item in proofs}
                proofs = tuple(unique[key] for key in sorted(unique))
                dtos.append(Observation(id=observation.id, concrete_url=observation.url,
                                        request_ref=observation.request_id if observation.id in valid_observations else None,
                                        response_status=observation.response.status_code if observation.id in valid_observations else None,
                                        evidence_refs=tuple(sorted({p.evidence_ref for p in proofs})), provenance=proofs))
                provenance.extend(proofs)
        baseline = repository.get_baseline(route.baseline_id) if route.baseline_id else None
        baseline_observation = next((o for o in observations if baseline and o.id == baseline.observation_id), None)
        decision = repository.get_policy_decision(baseline.request_id) if baseline else None
        baseline_result = repository.get_tool_result(baseline.request_id) if baseline else None
        baseline_valid = bool(
            baseline and baseline_observation and baseline.observation_id in valid_observations
            and baseline.endpoint_id == route.id and baseline.request_id == baseline_observation.request_id
            and baseline.evidence_id == baseline_observation.evidence_id and baseline.response == baseline_observation.response
            and decision and decision.allowed
            and baseline_result and baseline_result.status == "success"
        )
        status = EndpointLifecycle.OBSERVED if valid_observations else EndpointLifecycle.DISCOVERED
        route = route.model_copy(update={"in_scope": in_scope, "baseline_verified": baseline_valid,
                                         "baseline_url": baseline.url if baseline else None, "lifecycle": status})
        if baseline_valid:
            route = route.model_copy(update={"lifecycle": EndpointLifecycle.FUZZ_READY if fuzz_ready(route) else EndpointLifecycle.BASELINED})
        repository.replace_endpoint(route)
        if not provenance:
            continue
        refs = tuple(sorted({p.evidence_ref for p in provenance}))
        entries.append(AttackSurfaceEntry(
            id=route.id, run_id=task.run_id, target_id=stable_id(task.run_id, origin.scheme, origin.netloc),
            scheme=origin.scheme, authority=origin.netloc, resolved_ip=origin.hostname, method=route.method,
            canonical_path=origin.path, route_template=route.route_template,
            parameters=route.parameters, observations=tuple(dtos),
            baseline_ref=route.baseline_id, baseline_observation_ref=baseline.observation_id if baseline_valid else None,
            evidence_refs=refs, provenance=tuple(provenance), status=route.lifecycle, in_scope=in_scope,
            has_verified_baseline=baseline_valid, has_valid_evidence=bool(refs),
            has_unresolved_required_input=has_unresolved_required_input(route),
            is_testable=is_testable(route),
        ))
    return AttackSurfaceInventory(run_id=task.run_id, task_id=task.id, entries=tuple(entries))
