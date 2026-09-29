"""Curated read-only taxonomy; statuses are projections, never model assertions."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from src.contracts.recon_planning import ChecklistSummary, PlanningModel
from src.recon.models import Capability, CapabilityRequest


class ReconChecklistItem(PlanningModel):
    id: str = Field(pattern=r"^RECON-[A-Z-]+$")
    phase: Literal["service_discovery", "web_service_discovery", "technology_fingerprinting", "static_discovery", "adaptive"]
    title: str
    purpose: str
    applicable_when: Literal["capability_authorized"]
    recommended_capabilities: tuple[Capability, ...]
    required_capabilities: tuple[Capability, ...]
    risk: Literal["R0", "R1"]
    safe_default: Literal[True]
    evidence_requirement: Literal["verified_terminal_evidence"]
    status_rule: Literal["capability", "source", "static"]
    source_reference: str
    notes: str
    paths: tuple[str, ...] = ()


class ReconChecklist(PlanningModel):
    version: Literal["recon-checklist-v1"]
    items: tuple[ReconChecklistItem, ...] = Field(max_length=16)


def load_checklist():
    return ReconChecklist.model_validate(yaml.safe_load(
        (Path(__file__).parent / "data" / "recon_checklist_v1.yaml").read_text(encoding="utf-8")))


def project_checklist(task, repository, service):
    available = set(service.gateway.registry.available_capabilities())
    if Capability.BROWSER_EXPLORE in available:
        available.add(Capability.BROWSER_REQUEST)  # Internal Gateway dispatch, no public adapter.
    results = repository.list_tool_results(task.id)
    requests = {run.request_id: CapabilityRequest.model_validate_json(run.request_payload)
                for run in repository.list_tool_runs(task.id) if run.request_payload}
    verified = set()
    for result in results:
        if result.status == "success" and result.evidence_id:
            try:
                service.gateway.evidence.read(result.evidence_id)
                verified.add(result.request_id)
            except (ValueError, OSError):
                pass
    statuses = []
    origins = {(requests[r.request_id].target_ip, requests[r.request_id].parameters.port,
                requests[r.request_id].parameters.scheme) for r in results
               if r.request_id in verified and r.request_id in requests
               and (r.capability == Capability.HTTP_PROBE and r.attack_surface
                    or r.capability == Capability.HTTP_FETCH and r.http_response is not None)}
    for item in load_checklist().items:
        required = set(item.required_capabilities)
        if not required <= set(task.scope.capabilities):
            status, reason = "NOT_APPLICABLE", "capability not authorized"
        elif not required <= available:
            status, reason = "UNSUPPORTED", "authorized adapter unavailable"
        else:
            selected = [r for r in results if r.capability in required]
            if item.paths:
                selected = [r for r in selected if r.request_id in requests and
                            getattr(requests[r.request_id].parameters, "path", None) in item.paths]
            if item.status_rule == "static":
                sources = repository.list_sources(task.id)
                status = "COMPLETE" if sources and all(s.status in {"PARSED", "UNAVAILABLE"} for s in sources) else "PENDING"
                reason = "static sources terminal" if status == "COMPLETE" else "static coverage remains"
            elif selected and all(r.request_id in verified for r in selected):
                if item.paths:
                    seen = {(requests[r.request_id].target_ip, requests[r.request_id].parameters.port,
                             requests[r.request_id].parameters.scheme, requests[r.request_id].parameters.path) for r in selected}
                    expected = {(*origin, path) for origin in origins for path in item.paths}
                    status = "COMPLETE" if expected and expected <= seen else "PENDING"
                else:
                    planned = {a.request.id for plan in repository.list_plans(task.id) for a in plan.actions
                               if a.request.capability in required}
                    status = "COMPLETE" if planned and planned <= verified else "PENDING"
                reason = "verified terminal evidence" if status == "COMPLETE" else "coverage gaps remain"
                if item.id == "RECON-TECH-FINGERPRINT":
                    covered = {(requests[r.request_id].target_ip, requests[r.request_id].parameters.port,
                                requests[r.request_id].parameters.scheme) for r in selected if r.request_id in requests}
                    if not origins <= covered:
                        status, reason = "PENDING", "verified origins without technology evidence"
            elif selected:
                status, reason = "BLOCKED", "attempt lacks successful verified evidence"
            else:
                status, reason = "PENDING", "no qualifying evidence"
            # Nmap can only be complete when every authorized IP/port was actually scanned.
            if item.id == "RECON-SERVICE-DISCOVERY" and status == "COMPLETE":
                covered = {(requests[r.request_id].target_ip, p) for r in selected if r.request_id in requests
                           for p in requests[r.request_id].parameters.ports}
                if not {(ip, p) for ip in task.scope.allowed_ips for p in task.scope.allowed_ports} <= covered:
                    status, reason = "PENDING", "unscanned authorized ports"
        statuses.append(ChecklistSummary(id=item.id, status=status, reason=reason))
    return tuple(statuses)
