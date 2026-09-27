from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest

from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import (
    AttackSurfaceEntry,
    Capability,
    CapabilityRequest,
    NmapScanParams,
    ReconAction,
    ReconPlan,
    ReconTask,
    Scope,
)
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository


class FakeNmap:
    def __init__(self):
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return AdapterOutput(
            status="success", raw_output=b"21/tcp open ftp vsftpd 2.3.4\n",
            attack_surface=(AttackSurfaceEntry(target_ip=request.target_ip, port=21, service="ftp", version="vsftpd 2.3.4"),),
        )


def test_evidence_and_complete_mocked_recon_plan(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(21,), capabilities=(Capability.NMAP_SCAN,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    registry = CapabilityRegistry()
    registry.register(Capability.NMAP_SCAN, FakeNmap())
    gateway = ToolExecutionGateway(PolicyService(repository), registry, evidence, repository)
    request = CapabilityRequest(
        id="request-1", task_id=task.id, capability=Capability.NMAP_SCAN,
        target_ip="127.0.0.1", parameters=NmapScanParams(ports=(21,)),
    )
    plan = ReconPlan(task_id=task.id, actions=(ReconAction(id="action-1", request=request),))
    result = ReconService(repository, gateway).run(plan)
    assert result.run_id == "run-1"
    assert result.attack_surface[0].evidence_id == result.evidence_ids[0]
    assert repository.get_recon_result(task.id) == result
    assert repository.get_tool_result(request.id) == result.tool_results[0]
    assert evidence.read(result.evidence_ids[0]) == b"21/tcp open ftp vsftpd 2.3.4\n"
    artifact = repository.get_evidence(result.evidence_ids[0])
    assert artifact.size_bytes == len(b"21/tcp open ftp vsftpd 2.3.4\n")
    (tmp_path / "evidence" / artifact.relative_path).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        evidence.read(artifact.id)


def test_denial_is_persisted_without_evidence(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(21,), capabilities=(Capability.NMAP_SCAN,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    registry = CapabilityRegistry()
    adapter = FakeNmap()
    registry.register(Capability.NMAP_SCAN, adapter)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository)
    request = CapabilityRequest(
        id="outside", task_id=task.id, capability=Capability.NMAP_SCAN,
        target_ip="127.0.0.2", parameters=NmapScanParams(ports=(21,)),
    )
    result = gateway.execute(request)
    assert result.status == "denied"
    assert repository.get_tool_result("outside") == result
    assert result.evidence_id is None
    decision = repository.get_policy_decision(request.id)
    assert decision is not None
    assert decision.request_id == request.id
    assert decision.allowed is False
    assert adapter.calls == 0


def test_duplicate_request_executes_exactly_once(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(21,), capabilities=(Capability.NMAP_SCAN,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    adapter = FakeNmap()
    registry = CapabilityRegistry()
    registry.register(Capability.NMAP_SCAN, adapter)
    gateway = ToolExecutionGateway(
        PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository,
    )
    request = CapabilityRequest(
        id="request-1", task_id=task.id, capability=Capability.NMAP_SCAN,
        target_ip="127.0.0.1", parameters=NmapScanParams(ports=(21,)),
    )
    first = gateway.execute(request)
    second = gateway.execute(request)
    assert adapter.calls == 1
    assert first == second
    decision = repository.get_policy_decision(request.id)
    assert decision is not None
    assert decision.request_id == request.id
    assert decision.allowed is True
    assert decision.reason == "in scope"


def test_claimed_request_without_result_does_not_dispatch(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(21,), capabilities=(Capability.NMAP_SCAN,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    adapter = FakeNmap()
    registry = CapabilityRegistry()
    registry.register(Capability.NMAP_SCAN, adapter)
    request = CapabilityRequest(
        id="request-1", task_id=task.id, capability=Capability.NMAP_SCAN,
        target_ip="127.0.0.1", parameters=NmapScanParams(ports=(21,)),
    )
    assert repository.claim_request(request) is True
    gateway = ToolExecutionGateway(
        PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository,
    )
    result = gateway.execute(request)
    assert result.status == "error"
    assert result.message == "request already claimed or incomplete"
    assert adapter.calls == 0
    assert repository.get_policy_decision(request.id) is None


def test_concurrent_duplicate_cannot_enter_adapter_twice(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(21,), capabilities=(Capability.NMAP_SCAN,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    entered = Event()
    release = Event()

    class BlockingNmap(FakeNmap):
        def execute(self, request):
            entered.set()
            assert release.wait(5)
            return super().execute(request)

    adapter = BlockingNmap()
    registry = CapabilityRegistry()
    registry.register(Capability.NMAP_SCAN, adapter)
    gateway = ToolExecutionGateway(
        PolicyService(repository), registry, EvidenceStore(tmp_path / "evidence", repository), repository,
    )
    request = CapabilityRequest(
        id="request-1", task_id=task.id, capability=Capability.NMAP_SCAN,
        target_ip="127.0.0.1", parameters=NmapScanParams(ports=(21,)),
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(gateway.execute, request)
        assert entered.wait(5)
        pending = pool.submit(gateway.execute, request).result(timeout=5)
        assert pending.status == "error"
        assert pending.message == "request already claimed or incomplete"
        release.set()
        first = first_future.result(timeout=5)
    assert adapter.calls == 1
    assert gateway.execute(request) == first
