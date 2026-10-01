"""Browser evidence selects a concrete baseline; only HTTP_FETCH can establish it."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.recon.adapters import HttpFetchAdapter
from src.recon.baseline_promotion import BrowserBaselinePromotion
from src.recon.browser import child_request
from src.recon.browser_dom import project_browser_response
from src.recon.discovery import EndpointDiscovery
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ExternalDispatchPermit, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, Capability, CapabilityRequest, ReconTask, Scope
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import EndpointParameter, HttpResponseMetadata, WebEndpointEntry, stable_id


def setup_promotion(tmp_path, paths=(("/profile", "GET", 200),), *, fetch=True, status=200, body=b"complete", body_limit=131072):
    repository = ReconRepository(tmp_path / "promotion.db")
    capabilities = (Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST, *((Capability.HTTP_FETCH,) if fetch else ()))
    task = ReconTask(id="promotion", run_id="run", expires_at=datetime.now(UTC) + timedelta(minutes=5),
                     scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(8000,), allowed_paths=("/",), capabilities=capabilities))
    task = task.model_copy(update={"execution_budget": task.execution_budget.model_copy(update={"max_body_bytes": body_limit})})
    repository.save_task(task)
    registry = CapabilityRegistry()
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, evidence, repository)
    calls = []

    def handle(request):
        calls.append((request.method, str(request.url)))
        return httpx.Response(status, stream=httpx.ByteStream(body if request.method == "GET" else b""))

    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(handle)))

    class BrowserProofAdapter:
        def execute(self, parent):
            for path, method, browser_status in paths:
                child = child_request(parent, "http://127.0.0.1:8000" + path, method, "fetch")
                permit = gateway.begin_external_dispatch(child)
                assert isinstance(permit, ExternalDispatchPermit)
                assert gateway.authorize_external_continuation(permit)
                metadata = HttpResponseMetadata(status_code=browser_status, body_size=0,
                    body_sha256=hashlib.sha256(b"").hexdigest(), truncated=method == "GET")
                envelope = {"url": "http://127.0.0.1:8000" + path, "method": method,
                            "response": metadata.model_dump(), "body_base64": ""}
                result = gateway.finish_external_dispatch(permit, AdapterOutput(
                    status="success", raw_output=json.dumps(envelope).encode(), http_response=metadata,
                ))
                project_browser_response(repository, permit.request, result, envelope)
            return AdapterOutput(status="success", raw_output=json.dumps({
                "parent_request_id": parent.id, "stop_reason": "converged",
            }).encode())

    registry.register(Capability.BROWSER_EXPLORE, BrowserProofAdapter())
    params = BrowserExploreParams(port=8000)
    params = params.model_copy(update={"limits": params.limits.model_copy(update={"max_response_bytes": body_limit})})
    parent = CapabilityRequest(id="browser-parent", task_id=task.id, capability=Capability.BROWSER_EXPLORE,
                               target_ip="127.0.0.1", parameters=params)
    assert gateway.execute(parent).status == "success"
    service = ReconService(repository, gateway)
    planner = ReconPlanner()
    promotion = BrowserBaselinePromotion(repository, planner, service)
    return repository, service, promotion, task, calls


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_browser_only_read_promotes_to_fuzz_ready(tmp_path, method):
    repository, service, promotion, task, calls = setup_promotion(tmp_path, (("/profile", method, 200),))
    before = service.snapshot(task.id)
    old = before.observations[0]
    assert before.endpoints[0].lifecycle == "OBSERVED" and before.endpoints[0].baseline_id is None
    result = promotion.run(task)
    endpoint, observation = result.endpoints[0], result.observations[0]
    assert endpoint.lifecycle == "FUZZ_READY" and result.attack_surface_inventory.entries[0].has_verified_baseline
    assert calls == [(method, "http://127.0.0.1:8000/profile")]
    baseline = repository.get_baseline(endpoint.baseline_id)
    assert baseline.request_id == observation.request_id != old.request_id
    assert baseline.response.body_size == (len(b"complete") if method == "GET" else 0)
    assert baseline.response.truncated is False
    assert {p.relation for p in observation.provenance} == {"network_request", "baseline"}
    proof = repository.get_tool_result(baseline.request_id)
    assert proof.capability == Capability.HTTP_FETCH and proof.status == "success"
    assert repository.get_policy_decision(proof.request_id).allowed
    assert repository.get_policy_decision(proof.request_id).policy_version == "recon-3.1"
    assert repository.get_tool_run(proof.request_id).state == "SUCCEEDED"
    assert service.gateway.evidence.read(baseline.evidence_id)
    expected = "browser-baseline-" + stable_id("browser-baseline-v1", task.id, endpoint.id, old.id, old.url, method)
    assert proof.request_id == expected
    assert json.loads(repository.get_tool_run(expected).request_payload)["action_fingerprint"] != expected
    assert repository.list_sources(task.id) == ()
    assert EndpointDiscovery(repository, ReconPlanner(), service)._round_count(task.id) == 0


def test_promotion_restart_does_not_repeat_network_or_change_candidate(tmp_path):
    repository, service, promotion, task, calls = setup_promotion(tmp_path, (("/search?q=b", "GET", 200), ("/search?q=a", "GET", 200)))
    first = promotion.run(task)
    assert calls == [("GET", "http://127.0.0.1:8000/search?q=a")]
    assert first.endpoints[0].baseline_url.endswith("?q=a")
    assert len(first.observations) == 2 and len(first.endpoints) == 1
    reopened = ReconRepository(repository.database_path)
    gateway = ToolExecutionGateway(PolicyService(reopened), service.gateway.registry,
                                   EvidenceStore(service.gateway.evidence.directory, reopened), reopened)
    resumed = BrowserBaselinePromotion(reopened, ReconPlanner(), ReconService(reopened, gateway))
    assert resumed.run(reopened.get_task(task.id)).attack_surface_inventory == first.attack_surface_inventory
    assert len(calls) == 1


def test_route_template_promotes_using_concrete_observation(tmp_path):
    repository, _, promotion, task, calls = setup_promotion(tmp_path, (("/users/7", "GET", 200),))
    repository.save_endpoint(WebEndpointEntry(task_id=task.id, url="http://127.0.0.1:8000/users/{id}",
        route_template="/users/{id}", parameters=(EndpointParameter(name="id", location="path", required=True),)))
    result = promotion.run(task)
    assert len(result.endpoints) == 1
    endpoint = result.endpoints[0]
    assert endpoint.route_template == "/users/{id}" and endpoint.lifecycle == "FUZZ_READY"
    assert calls == [("GET", "http://127.0.0.1:8000/users/7")]
    assert repository.get_baseline(endpoint.baseline_id).route_template == "/users/{id}"


@pytest.mark.parametrize("url,parameters,manual", [
    ("/search", (EndpointParameter(name="q", location="query", required=True),), False),
    ("/search?q=", (EndpointParameter(name="q", location="query", required=True),), False),
    ("/form", (), True),
])
def test_unresolved_required_query_or_form_is_never_promoted(tmp_path, url, parameters, manual):
    repository, _, promotion, task, calls = setup_promotion(tmp_path, ((url, "GET", 200),))
    repository.save_endpoint(WebEndpointEntry(task_id=task.id, url="http://127.0.0.1:8000" + url,
                                             parameters=parameters, requires_manual_input=manual))
    assert promotion.run(task).endpoints[0].lifecycle == "OBSERVED"
    assert calls == []


def test_write_method_and_template_without_concrete_are_never_promoted(tmp_path):
    repository, _, promotion, task, calls = setup_promotion(tmp_path, ())
    for url, method, template in (("/write", "POST", None), ("/users/{id}", "GET", "/users/{id}")):
        repository.save_endpoint(WebEndpointEntry(task_id=task.id, url="http://127.0.0.1:8000" + url,
                                                 method=method, route_template=template))
    assert all(item.baseline_id is None for item in promotion.run(task).endpoints)
    assert calls == []


@pytest.mark.parametrize("status", [404, 500])
def test_non_2xx_browser_observation_is_never_promoted(tmp_path, status):
    _, _, promotion, task, calls = setup_promotion(tmp_path, (("/profile", "GET", status),))
    assert promotion.run(task).endpoints[0].lifecycle == "OBSERVED"
    assert calls == []


def test_http_fetch_absent_leaves_endpoint_observed(tmp_path):
    _, _, promotion, task, calls = setup_promotion(tmp_path, fetch=False)
    assert promotion.run(task).endpoints[0].lifecycle == "OBSERVED" and calls == []


@pytest.mark.parametrize("change", ["scope", "expired", "budget"])
def test_scope_expiry_or_budget_denies_promotion(tmp_path, change):
    repository, _, promotion, task, calls = setup_promotion(tmp_path)
    if change == "scope":
        task = task.model_copy(update={"scope": task.scope.model_copy(update={"allowed_paths": ("/allowed",)})})
    elif change == "expired":
        task = task.model_copy(update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)})
    else:
        task = task.model_copy(update={"execution_budget": task.execution_budget.model_copy(update={
            "max_requests": repository.budget_usage(task.id),
        })})
    with repository._connect() as connection:
        connection.execute("UPDATE recon_tasks SET payload = ? WHERE id = ?", (task.model_dump_json(), task.id))
    result = promotion.run(task)
    assert result.endpoints[0].lifecycle == "OBSERVED" and calls == []
    denied = next(item for item in result.tool_results if item.request_id.startswith("browser-baseline-"))
    assert denied.status == "denied" and not repository.get_policy_decision(denied.request_id).allowed


@pytest.mark.parametrize("status,body,limit", [(302, b"", 131072), (404, b"missing", 131072),
                                             (500, b"error", 131072), (200, b"oversized", 2)])
def test_non_2xx_or_truncated_baseline_never_promotes_or_retries(tmp_path, status, body, limit):
    _, _, promotion, task, calls = setup_promotion(tmp_path, status=status, body=body, body_limit=limit)
    result = promotion.run(task)
    assert result.endpoints[0].lifecycle == "OBSERVED" and result.endpoints[0].baseline_id is None
    assert promotion.run(task).attack_surface_inventory == result.attack_surface_inventory
    assert len(calls) == 1


def test_corrupted_baseline_evidence_revokes_fuzz_ready(tmp_path):
    repository, service, promotion, task, calls = setup_promotion(tmp_path)
    result = promotion.run(task)
    baseline = repository.get_baseline(result.endpoints[0].baseline_id)
    artifact = repository.get_evidence(baseline.evidence_id)
    (service.gateway.evidence.directory / artifact.relative_path).write_bytes(b"tampered")
    result = promotion.run(task)
    assert result.endpoints[0].lifecycle != "FUZZ_READY"
    assert not result.attack_surface_inventory.entries[0].has_verified_baseline
    assert len(calls) == 1


def test_corrupted_browser_evidence_cannot_authorize_promotion(tmp_path):
    repository, service, promotion, task, calls = setup_promotion(tmp_path)
    observation = repository.list_observations(task.id)[0]
    artifact = repository.get_evidence(observation.evidence_id)
    (service.gateway.evidence.directory / artifact.relative_path).write_bytes(b"tampered")
    assert promotion.run(task).endpoints[0].baseline_id is None and calls == []


def test_crash_after_http_result_before_projection_recovers_without_dispatch(tmp_path, monkeypatch):
    repository, service, promotion, task, calls = setup_promotion(tmp_path)
    original = promotion._promote

    def crash(*_args):
        raise RuntimeError("projection crash")

    monkeypatch.setattr(promotion, "_promote", crash)
    with pytest.raises(RuntimeError, match="projection crash"):
        promotion.run(task)
    assert len(calls) == 1 and repository.list_endpoints(task.id)[0].baseline_id is None
    monkeypatch.setattr(promotion, "_promote", original)
    assert promotion.run(task).endpoints[0].lifecycle == "FUZZ_READY"
    assert len(calls) == 1
