from datetime import UTC, datetime, timedelta

import httpx

from src.contracts.execution import Risk
from src.recon.adapters import HttpFetchAdapter
from src.recon.agent import ReconAgent
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import (
    Capability,
    CapabilityRequest,
    HttpFetchParams,
    HttpProbeParams,
    NmapScanParams,
    ReconTask,
    Scope,
    WhatWebParams,
)
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import EndpointLifecycle, SourceStatus
from tests.test_recon_day2 import make_task, stack


def test_day02_gate_route_identity_observations_and_parameterless_readiness(tmp_path):
    calls = []
    task = make_task().model_copy(update={"discovery_seeds": ("/",)})

    def handler(request):
        calls.append(str(request.url))
        if request.url.path == "/":
            body = (
                b"<html><a href='/search?q=a'>a</a>"
                b"<a href='/search?q=b'>b</a>"
                b"<a href='/profile'>profile</a></html>"
            )
            content_type = "text/html"
        elif request.url.path == "/search":
            body = b'{"ok":true}'
            content_type = "application/json"
        elif request.url.path == "/profile":
            body = b"profile"
            content_type = "text/plain"
        else:
            return httpx.Response(404, stream=httpx.ByteStream(b"not found"))
        return httpx.Response(
            200,
            headers={"content-type": content_type},
            stream=httpx.ByteStream(body),
        )

    repository, _, _, service = stack(tmp_path, task, handler)
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)

    routes = {(entry.canonical_path, entry.method): entry for entry in result.endpoints}
    search = routes[("/search", "GET")]
    profile = routes[("/profile", "GET")]

    search_observations = [item for item in result.observations if item.endpoint_id == search.id]
    assert {item.url for item in search_observations} == {
        "http://127.0.0.1:8000/search?q=a",
        "http://127.0.0.1:8000/search?q=b",
    }
    assert len(search_observations) == 2
    assert search.lifecycle == EndpointLifecycle.FUZZ_READY
    assert profile.lifecycle == EndpointLifecycle.FUZZ_READY

    exported = {entry.canonical_path: entry for entry in result.attack_surface_inventory.entries}
    assert exported["/profile"].status == EndpointLifecycle.FUZZ_READY
    assert exported["/profile"].baseline_ref
    assert exported["/profile"].baseline_observation_ref

    # The discovery engine should never replay an identical concrete request in one run.
    assert len(calls) == len(set(calls))


def test_day02_gate_declared_template_groups_paths_without_shape_guessing(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/", "/openapi.json")})

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                stream=httpx.ByteStream(
                    b"<a href='/users/1'>u1</a><a href='/users/2'>u2</a>"
                    b"<a href='/version/v1'>v1</a><a href='/version/v2'>v2</a>"
                ),
            )
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                stream=httpx.ByteStream(
                    b'{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{"parameters":'
                    b'[{"name":"id","in":"path","required":true}]}}}}'
                ),
            )
        return httpx.Response(200, stream=httpx.ByteStream(b"observed"))

    repository, _, _, service = stack(tmp_path, task, handler)
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    routes = {entry.canonical_path: entry for entry in result.endpoints}

    users = routes["/users/{id}"]
    assert users.route_template == "/users/{id}"
    assert "/users/1" not in routes and "/users/2" not in routes
    assert {item.url for item in result.observations if item.endpoint_id == users.id} >= {
        "http://127.0.0.1:8000/users/1",
        "http://127.0.0.1:8000/users/2",
    }

    # Similar-looking literal paths must remain distinct unless a declared template proves otherwise.
    assert routes["/version/v1"].id != routes["/version/v2"].id
    assert routes["/version/v1"].route_template is None
    assert routes["/version/v2"].route_template is None


def test_day02_gate_external_redirect_is_observed_but_never_followed(tmp_path):
    calls = []
    task = make_task().model_copy(update={"discovery_seeds": ("/redirect",)})

    def handler(request):
        calls.append((request.url.host, request.url.port, request.url.path))
        if request.url.host != "127.0.0.1":
            raise AssertionError("out-of-scope redirect was dispatched")
        return httpx.Response(
            302,
            headers={"location": "http://127.0.0.2:9999/outside"},
            stream=httpx.ByteStream(b""),
        )

    repository, _, _, service = stack(tmp_path, task, handler)
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)

    redirect = next(entry for entry in result.endpoints if entry.canonical_path == "/redirect")
    source = next(item for item in repository.list_sources(task.id) if item.url.endswith("/redirect"))
    assert redirect.lifecycle == EndpointLifecycle.OBSERVED
    assert source.status == SourceStatus.UNAVAILABLE
    assert calls == [("127.0.0.1", 8000, "/redirect")]
    assert all(entry.authority != "127.0.0.2:9999" for entry in result.attack_surface_inventory.entries)


def test_day02_gate_authorization_binding_and_risk_contract(tmp_path):
    task = ReconTask(
        id="risk-task",
        run_id="risk-run",
        scope=Scope(
            allowed_ips=("127.0.0.1",),
            allowed_ports=(8000,),
            capabilities=(
                Capability.HTTP_FETCH,
                Capability.HTTP_PROBE,
                Capability.WHATWEB,
                Capability.NMAP_SCAN,
            ),
            allowed_paths=("/",),
        ),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository = ReconRepository(tmp_path / "risk.db")
    repository.save_task(task)
    policy = PolicyService(repository)

    cases = (
        (Capability.HTTP_FETCH, HttpFetchParams(port=8000, path="/x"), Risk.R0),
        (Capability.HTTP_PROBE, HttpProbeParams(port=8000), Risk.R0),
        (Capability.WHATWEB, WhatWebParams(port=8000), Risk.R0),
        (Capability.NMAP_SCAN, NmapScanParams(ports=(8000,)), Risk.R1),
    )
    for index, (capability, parameters, expected_risk) in enumerate(cases):
        request = CapabilityRequest(
            id=f"request-{index}",
            task_id=task.id,
            target_ip="127.0.0.1",
            capability=capability,
            parameters=parameters,
        )
        bound = policy.bind(request)
        decision = policy.decide(bound)
        assert bound.run_id == task.run_id
        assert bound.scope_version == task.scope_version
        assert bound.action_fingerprint and len(bound.action_fingerprint) == 64
        assert bound.action_fingerprint != bound.id
        assert decision.allowed is True
        assert decision.action_fingerprint == bound.action_fingerprint
        assert decision.policy_fingerprint == PolicyService.scope_fingerprint(task)
        assert decision.risk == expected_risk

    base = CapabilityRequest(
        id="same-action-a",
        task_id=task.id,
        target_ip="127.0.0.1",
        capability=Capability.HTTP_FETCH,
        parameters=HttpFetchParams(port=8000, path="/search", query="q=a"),
    )
    same_action = base.model_copy(update={"id": "same-action-b"})
    changed_action = base.model_copy(update={
        "id": "changed-action",
        "parameters": HttpFetchParams(port=8000, path="/search", query="q=b"),
    })
    assert policy.bind(base).action_fingerprint == policy.bind(same_action).action_fingerprint
    assert policy.bind(base).action_fingerprint != policy.bind(changed_action).action_fingerprint


def test_day02_gate_restart_replays_without_network_and_preserves_evidence(tmp_path):
    calls = []
    task = make_task().model_copy(update={"discovery_seeds": ("/profile",)})

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=httpx.ByteStream(b"profile"),
        )

    database = tmp_path / "recon.db"
    evidence_dir = tmp_path / "evidence"
    repository, _, _, service = stack(tmp_path, task, handler)
    first = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    first_call_count = len(calls)
    assert first_call_count == 1

    reopened = ReconRepository(database)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(handler)))
    evidence = EvidenceStore(evidence_dir, reopened)
    gateway = ToolExecutionGateway(PolicyService(reopened), registry, evidence, reopened)
    restarted = ReconAgent(reopened, ReconPlanner(), ReconService(reopened, gateway)).run(task.id)

    assert restarted == first
    assert len(calls) == first_call_count
    assert restarted.attack_surface_inventory.entries
    for entry in restarted.attack_surface_inventory.entries:
        for evidence_id in entry.evidence_refs:
            assert evidence.read(evidence_id)
