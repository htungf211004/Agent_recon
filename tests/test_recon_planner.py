from datetime import UTC, datetime, timedelta

import pytest

from src.recon.agent import ReconAgent
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, ReconTask, Scope, WhatWebParams
from src.recon.planner import ReconPlanner, scheme_for_port
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


def task(ports=(80, 443, 8443)):
    return ReconTask(
        id="task-1",
        run_id="run-1",
        scope=Scope(
            allowed_ips=("127.0.0.2", "127.0.0.1"),
            allowed_ports=ports,
            capabilities=(Capability.NMAP_SCAN, Capability.HTTP_PROBE, Capability.WHATWEB),
        ),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )


def test_planner_creates_deterministic_bounded_actions_from_scope():
    recon_task = task()
    planner = ReconPlanner()
    first = planner.initial_plan(recon_task)
    assert first == planner.initial_plan(recon_task)
    assert len(first.actions) == 14
    assert len({action.request.id for action in first.actions}) == 14
    for target_ip in recon_task.scope.allowed_ips:
        requests = [action.request for action in first.actions if action.request.target_ip == target_ip]
        nmap = [request for request in requests if request.capability == Capability.NMAP_SCAN]
        assert len(nmap) == 1
        assert nmap[0].parameters.ports == (80, 443, 8443)
        for capability in (Capability.HTTP_PROBE, Capability.WHATWEB):
            probes = [request for request in requests if request.capability == capability]
            assert {(probe.parameters.port, probe.parameters.scheme) for probe in probes} == {
                (80, "http"), (443, "https"), (8443, "https"),
            }
    assert scheme_for_port(9443) == "https"
    assert scheme_for_port(8080) == "http"


def test_planner_limits_single_nmap_action_to_32_ports():
    plan = ReconPlanner().initial_plan(task(ports=tuple(range(1, 41))))
    for action in plan.actions:
        if action.request.capability == Capability.NMAP_SCAN:
            assert action.request.parameters.ports == tuple(range(1, 33))


def test_planner_only_uses_allowed_capabilities():
    recon_task = task().model_copy(update={
        "scope": task().scope.model_copy(update={"capabilities": (Capability.WHATWEB,)}),
    })
    plan = ReconPlanner().initial_plan(recon_task)
    assert len(plan.actions) == 6
    assert all(action.request.capability == Capability.WHATWEB for action in plan.actions)


def test_planner_never_creates_raw_commands():
    plan = ReconPlanner().initial_plan(task())
    for action in plan.actions:
        assert action.request.parameters.kind == action.request.capability.value
        assert set(action.request.parameters.model_dump()) <= {"kind", "port", "ports", "scheme"}
        assert not isinstance(action.request.parameters, str)


def test_planner_targets_only_scope_ips_and_ports():
    recon_task = task(ports=(80, 9443))
    plan = ReconPlanner().initial_plan(recon_task)
    for action in plan.actions:
        request = action.request
        assert request.target_ip in recon_task.scope.allowed_ips
        requested_ports = request.parameters.ports if hasattr(request.parameters, "ports") else (request.parameters.port,)
        assert set(requested_ports) <= set(recon_task.scope.allowed_ports)
        if isinstance(request.parameters, WhatWebParams):
            assert request.parameters.scheme == scheme_for_port(request.parameters.port)


class SpyAdapter:
    def __init__(self, repository):
        self.repository = repository
        self.calls = []

    def execute(self, request):
        decision = self.repository.get_policy_decision(request.id)
        assert decision is not None and decision.allowed is True
        self.calls.append(request.id)
        return AdapterOutput(status="success", raw_output=b"mock recon output")


def test_recon_agent_builds_and_executes_plan(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    recon_task = task(ports=(80,))
    repository.save_task(recon_task)
    registry = CapabilityRegistry()
    adapter = SpyAdapter(repository)
    for capability in Capability:
        registry.register(capability, adapter)
    gateway = ToolExecutionGateway(
        PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository,
    )
    agent = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))
    first = agent.run(recon_task.id)
    second = agent.run(recon_task.id)
    assert first == second
    assert len(first.tool_results) == 6
    assert len(adapter.calls) == 6
    assert len(first.evidence_ids) == 6
    assert all(repository.get_evidence(evidence_id) is not None for evidence_id in first.evidence_ids)
    assert repository.get_recon_result(recon_task.id) == first
    with pytest.raises(ValueError, match="unknown Recon task"):
        agent.run("missing")
