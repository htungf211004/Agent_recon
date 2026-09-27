from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.recon.models import (
    Capability,
    CapabilityRequest,
    HttpProbeParams,
    NmapScanParams,
    ReconTask,
    Scope,
)


def test_strict_request_rejects_commands_and_mismatched_parameters():
    base = dict(id="req-1", task_id="task-1", target_ip="127.0.0.1", capability=Capability.NMAP_SCAN)
    with pytest.raises(ValidationError):
        CapabilityRequest(**base, parameters={"kind": "nmap_scan", "ports": [80], "command": "sh -c whoami"})
    with pytest.raises(ValidationError):
        CapabilityRequest(**base, parameters=HttpProbeParams(port=80))
    with pytest.raises(ValidationError):
        CapabilityRequest(**base, parameters=NmapScanParams(ports=(0,)))
    with pytest.raises(ValidationError):
        CapabilityRequest(**{**base, "target_ip": "example.com"}, parameters=NmapScanParams(ports=(80,)))


def test_task_scope_serializes_and_validates():
    task = ReconTask(
        id="task-1",
        run_id="run-1",
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(80,), capabilities=(Capability.HTTP_PROBE,)),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    assert ReconTask.model_validate_json(task.model_dump_json()) == task
    with pytest.raises(ValidationError):
        Scope(allowed_ips=("example.com",), allowed_ports=(80,), capabilities=(Capability.HTTP_PROBE,))
