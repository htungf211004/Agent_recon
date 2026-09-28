from datetime import UTC, datetime, timedelta

from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, CapabilityRequest, HttpProbeParams, ReconTask, Scope
from src.recon.policy import PolicyService
from src.recon.storage import ReconRepository


class TestStore(ReconRepository):
    __test__ = False

    def save(self, request, content):
        raise AssertionError("no evidence expected")


class SpyAdapter:
    def __init__(self):
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        return AdapterOutput(status="success")


def request(target="127.0.0.1", port=80, task_id="task-1", request_id="req-1"):
    return CapabilityRequest(
        id=request_id, task_id=task_id, capability=Capability.HTTP_PROBE,
        target_ip=target, parameters=HttpProbeParams(port=port),
    )


def test_gateway_denies_unknown_task_target_port_and_unregistered_capability(tmp_path):
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(80,), capabilities=(Capability.HTTP_PROBE,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    store = TestStore(tmp_path / "recon.db")
    store.save_task(task)
    adapter = SpyAdapter()
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, adapter)
    gateway = ToolExecutionGateway(PolicyService(store), registry, store, store)
    for denied in (
        request(task_id="unknown", request_id="unknown"),
        request(target="127.0.0.2", request_id="outside"),
        request(port=443, request_id="wrong-port"),
    ):
        assert gateway.execute(denied).status == "denied"
    assert adapter.calls == 0
    assert len(store.list_tool_results(task.id)) + len(store.list_tool_results("unknown")) == 3
    assert gateway.execute(request()).status == "success"
    assert adapter.calls == 1


def test_expired_task_denied_before_dispatch(tmp_path):
    task = ReconTask(
        id="task-1", run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(80,), capabilities=(Capability.HTTP_PROBE,)),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    store = TestStore(tmp_path / "recon.db")
    store.save_task(task)
    adapter = SpyAdapter()
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, adapter)
    assert ToolExecutionGateway(PolicyService(store), registry, store, store).execute(request()).status == "denied"
    assert adapter.calls == 0
