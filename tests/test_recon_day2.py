import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError

from src.recon.adapters import HttpFetchAdapter
from src.recon.agent import ReconAgent
from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability, CapabilityRequest, HttpFetchParams, ReconAction, ReconPlan, ReconTask, Scope
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.urls import canonical_url, normalize_candidate
from src.recon.web_models import (
    DiscoveryKind,
    DiscoveryLimits,
    EndpointLifecycle,
    EndpointParameter,
    EndpointProvenance,
    SourceStatus,
    WebEndpointEntry,
)


def make_task(**scope):
    return ReconTask(
        id="day2", run_id="run2", expires_at=datetime.now(UTC) + timedelta(minutes=5),
        scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(8000,), capabilities=(Capability.HTTP_FETCH,),
                    allowed_paths=scope.pop("allowed_paths", ("/",)), **scope),
    )


def fetch_request(identifier="fetch-1", **params):
    return CapabilityRequest(id=identifier, task_id="day2", target_ip="127.0.0.1", capability=Capability.HTTP_FETCH,
                             parameters=HttpFetchParams(port=8000, **params))


def stack(tmp_path, task, handler):
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(handler)))
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, evidence, repository)
    return repository, evidence, gateway, ReconService(repository, gateway)


def test_multiple_plans_accumulate_results_without_reexecuting_requests(tmp_path):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    repository, _, _, service = stack(tmp_path, make_task(), handler)
    first = ReconAction(id="a", request=fetch_request(path="/first"))
    second = ReconAction(id="b", request=fetch_request("fetch-2", path="/second"))
    round_one = ReconPlan(task_id="day2", actions=(first,))
    round_two = ReconPlan(task_id="day2", actions=(first, second))
    assert len(service.run(round_one).tool_results) == 1
    result = service.run(round_two)
    assert len(result.tool_results) == 2
    assert service.run(round_two) == result
    assert service.run(round_one) == result
    assert calls == ["/first", "/second"]
    reopened = ReconRepository(repository.database_path)
    assert len(reopened.list_plans("day2")) == 2
    assert reopened.get_recon_result("day2") == result
    assert reopened.claim_request(second.request) is False


@pytest.mark.parametrize("params", [
    {"method": "POST"}, {"method": "DELETE"}, {"command": "curl"}, {"body": "data"},
    {"path": "//127.0.0.2/"}, {"path": "/api/../admin"}, {"path": "/api/%2e%2e/admin"},
    {"path": "/api%2fadmin"}, {"path": "/api/%252e"}, {"path": "/api\\admin"},
    {"path": "/api/{id}"}, {"path": "/x?y=1"}, {"query": "x=%0d%0aInjected"},
    {"timeout_seconds": 11}, {"max_body_bytes": 131073},
])
def test_fetch_rejects_unsafe_or_unbounded_parameters(params):
    with pytest.raises(ValidationError):
        HttpFetchParams(port=8000, **params)


@pytest.mark.parametrize("seed", ["https://outside.test/", "/api/{id}", "/../admin", "\n/admin"])
def test_discovery_rejects_invalid_seeds_instead_of_claiming_empty_coverage(seed):
    task = make_task().model_dump()
    with pytest.raises(ValidationError):
        ReconTask.model_validate({**task, "discovery_seeds": (seed,)})


def test_fetch_scope_denies_path_prefix_collision_and_method_before_network(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    repository, _, gateway, _ = stack(tmp_path, make_task(allowed_paths=("/api",), allowed_methods=("HEAD",)), handler)
    for index, params in enumerate(({"path": "/apix", "method": "HEAD"}, {"path": "/api", "method": "GET"})):
        request = fetch_request(f"denied-{index}", **params)
        assert gateway.execute(request).status == "denied"
        assert repository.get_policy_decision(request.id).allowed is False
    assert calls == []
    assert gateway.execute(fetch_request("allowed", path="/api/items", method="HEAD")).status == "success"
    assert len(calls) == 1


def test_fetch_redirect_size_limit_and_evidence(tmp_path):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "http://127.0.0.2/escape"}, stream=httpx.ByteStream(b""))
        return httpx.Response(200, headers={"content-type": "text/plain"}, stream=httpx.ByteStream(b"x" * 10000))

    _, evidence, gateway, _ = stack(tmp_path, make_task(), handler)
    redirect = gateway.execute(fetch_request(path="/redirect"))
    assert redirect.http_response.status_code == 302
    assert len(calls) == 1
    limited = gateway.execute(fetch_request("large", path="/large", max_body_bytes=100))
    assert limited.status == "error"
    assert limited.http_response.truncated is True
    envelope = json.loads(evidence.read(limited.evidence_id))
    assert len(base64.b64decode(envelope["body_base64"])) == 100
    assert len(calls) == 2


def test_fetch_timeout_returns_error_without_baseline(tmp_path):
    def handler(request):
        raise httpx.ReadTimeout("test timeout")

    repository, _, gateway, _ = stack(tmp_path, make_task(), handler)
    result = gateway.execute(fetch_request())
    assert result.status == "error"
    assert "ReadTimeout" in result.message
    assert result.evidence_id is None
    assert repository.get_tool_result(result.request_id) == result


def test_conservative_identity_and_provenance_merge(tmp_path):
    base = "http://127.0.0.1:8000/root"
    assert normalize_candidate("/a%62?x=1&x=2#fragment", base) == "http://127.0.0.1:8000/ab?x=1&x=2"
    assert normalize_candidate("http://127.0.0.2:8000/outside", base) is None
    assert normalize_candidate("../admin", base) is None
    assert normalize_candidate("\n/admin", base) is None
    assert normalize_candidate("http://127.0.0.1:0/admin", base) is None
    assert normalize_candidate("http://user@127.0.0.1:8000/", base) is None
    assert canonical_url(base + "/") != canonical_url(base)
    repository = ReconRepository(tmp_path / "recon.db")
    first = WebEndpointEntry(task_id="day2", url=base, parameters=(EndpointParameter(name="q", location="query"),),
                             provenance=(EndpointProvenance(source_id="html", kind=DiscoveryKind.HTML, relation="link"),))
    second = first.model_copy(update={
        "parameters": (EndpointParameter(name="q", location="query", required=True),),
        "provenance": (EndpointProvenance(source_id="api", kind=DiscoveryKind.OPENAPI, relation="operation"),),
    })
    repository.save_endpoint(first)
    merged = repository.save_endpoint(second)
    assert len(merged.provenance) == 2
    assert len(merged.parameters) == 1 and merged.parameters[0].required is True
    assert repository.save_endpoint(first) == merged
    assert merged.lifecycle == EndpointLifecycle.DISCOVERED
    assert first.id != first.model_copy(update={"method": "POST"}).id
    assert first.id != first.model_copy(update={"url": base + "?q=1"}).id
    with pytest.raises(ValidationError):
        WebEndpointEntry(task_id="day2", url=base, lifecycle=EndpointLifecycle.FUZZ_READY)


@pytest.mark.parametrize("body,content_type,expected_status,lifecycle", [
    (b"{" * 10, "application/json", SourceStatus.ERROR, EndpointLifecycle.BASELINED),
    (b"x" * 131073, "application/json", SourceStatus.LIMITED, EndpointLifecycle.OBSERVED),
], ids=["malformed", "truncated"])
def test_failed_or_truncated_discovery_source_cannot_claim_complete_coverage(tmp_path, body, content_type, expected_status, lifecycle):
    task = make_task().model_copy(update={"discovery_seeds": ("/openapi.json",)})
    repository, _, _, service = stack(tmp_path, task, lambda req: httpx.Response(
        200, headers={"content-type": content_type}, stream=httpx.ByteStream(body),
    ))
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    source = repository.list_sources(task.id)[0]
    assert source.status == expected_status
    assert result.coverage.complete is False
    assert result.endpoints[0].lifecycle == lifecycle
    if expected_status == SourceStatus.LIMITED:
        assert result.endpoints[0].baseline_id is None


def test_discovery_refuses_unverified_evidence_before_baseline(tmp_path, monkeypatch):
    task = make_task().model_copy(update={"discovery_seeds": ("/",)})
    repository, evidence, _, service = stack(tmp_path, task, lambda req: httpx.Response(
        200, headers={"content-type": "text/html"}, stream=httpx.ByteStream(b"<a href='/next'>next</a>"),
    ))

    def corrupted(artifact_id):
        raise ValueError("evidence integrity check failed")

    monkeypatch.setattr(evidence, "read", corrupted)
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    assert result.coverage.complete is False
    assert repository.list_sources(task.id)[0].status == SourceStatus.ERROR
    assert len(result.endpoints) == 1
    assert result.endpoints[0].lifecycle == EndpointLifecycle.DISCOVERED
    assert result.endpoints[0].baseline_id is None


def test_new_parameter_information_can_revoke_fuzz_readiness(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/query?q=one",)})
    repository, _, _, service = stack(tmp_path, task, lambda req: httpx.Response(200, stream=httpx.ByteStream(b"ok")))
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    endpoint = result.endpoints[0]
    assert endpoint.lifecycle == EndpointLifecycle.FUZZ_READY
    update = WebEndpointEntry(task_id=task.id, url=endpoint.url, parameters=(
        EndpointParameter(name="token", location="header", required=True),
    ))
    merged = repository.save_endpoint(update)
    assert merged.lifecycle == EndpointLifecycle.BASELINED
    assert len(merged.parameters) == 2
    assert merged.baseline_id == endpoint.baseline_id


def test_fetch_total_body_deadline_is_checked_on_each_chunk(tmp_path, monkeypatch):
    from types import SimpleNamespace

    ticks = iter((0, 1, 6))
    monkeypatch.setattr("src.recon.adapters.time", SimpleNamespace(monotonic=lambda: next(ticks)))

    class SlowStream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"a"
            yield b"b"
            raise AssertionError("deadline should stop streaming")

    _, _, gateway, _ = stack(tmp_path, make_task(), lambda req: httpx.Response(200, stream=SlowStream()))
    result = gateway.execute(fetch_request())
    assert result.status == "error"
    assert "ReadTimeout" in result.message


def test_resume_parses_persisted_response_even_when_network_budget_is_used(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    task = make_task().model_copy(update={
        "discovery_seeds": ("/",), "discovery_limits": DiscoveryLimits(max_requests=1, max_rounds=1),
    })
    repository, _, _, service = stack(tmp_path, task, handler)
    agent = ReconAgent(repository, ReconPlanner(), service)
    original = agent.run(task.id)
    source = repository.list_sources(task.id)[0]
    repository.save_source(source.model_copy(update={"status": SourceStatus.PENDING}))
    assert agent.run(task.id) == original
    assert len(calls) == 1
