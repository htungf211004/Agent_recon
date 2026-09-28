"""Focused final Recon hardening: inventory, execution identity, roots and coverage."""

import json
from types import SimpleNamespace

import pytest

from src.recon.agent import ReconAgent
from src.recon.browser import BrowserExploreAdapter, child_request
from src.recon.gateway import AdapterOutput, ExternalDispatchPermit
from src.recon.models import Capability, CapabilityRequest, ReconAction, ReconPlan
from src.recon.planner import ReconPlanner
from src.recon.service import ReconService
from src.recon.storage import ReconRepository
from src.recon.urls import path_allowed
from src.recon.web_models import ReconCoverage, stable_id
from tests.test_recon_browser_boundary import FakeRequest, FakeRuntime, stack


def test_asset_evidence_retained_without_inventory_projection(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    origin = "http://127.0.0.1:8000"
    resources = {"/": "document", "/app.js": "script", "/style.css": "stylesheet", "/logo.png": "image",
                 "/font.woff2": "font", "/manifest.json": "manifest", "/profile": "xhr", "/users": "fetch"}
    requests = [FakeRequest(origin + path, resource_type=kind, navigation=kind == "document")
                for path, kind in resources.items()]
    runtime = FakeRuntime([*requests, *requests[1:]])
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    result = gateway.execute(parent)
    assert result.status == "success"
    assert len(runtime.network) == len(resources)
    children = repository.list_child_runs(parent.id)
    assert len(children) == len(resources)
    for child in children:
        assert repository.get_policy_decision(child.request_id).allowed
        proof = repository.get_tool_result(child.request_id)
        assert proof.status == "success"
        assert gateway.evidence.read(proof.evidence_id)
    snapshot = ReconService(repository, gateway).snapshot(parent.task_id)
    paths = {entry.canonical_path for entry in snapshot.attack_surface_inventory.entries}
    assert paths == {"/", "/profile", "/users"}
    assert len(snapshot.endpoints) == len(snapshot.observations) == 3
    assert gateway.execute(parent) == result
    assert len(runtime.network) == len(resources)


def test_same_page_url_different_resources_have_distinct_execution_identity(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    root, data = "http://127.0.0.1:8000/", "http://127.0.0.1:8000/data"
    runtime = FakeRuntime([FakeRequest(root, resource_type="document", navigation=True),
                           FakeRequest(data, resource_type="script"), FakeRequest(data, resource_type="fetch")])
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    assert gateway.execute(parent).status == "success"
    children = [CapabilityRequest.model_validate_json(run.request_payload) for run in repository.list_child_runs(parent.id)]
    data_requests = [item for item in children if item.parameters.path == "/data"]
    assert len({item.id for item in data_requests}) == len({item.action_fingerprint for item in data_requests}) == 2
    assert runtime.network.count(("GET", data)) == 2
    assert len([item for item in repository.list_endpoints(parent.task_id) if item.canonical_path == "/data"]) == 1


@pytest.mark.parametrize("sequence", [0, 1])
def test_persisted_ver01_ver02_child_ids_still_replay(tmp_path, sequence):
    repository, registry, gateway, parent = stack(tmp_path)
    from src.recon.models import BrowserExploreParams, BrowserLimits

    parent = parent.model_copy(update={"parameters": BrowserExploreParams(port=8000, limits=BrowserLimits(max_pages=2))})
    saved = []

    def execute(bound):
        url = "http://127.0.0.1:8000/data"
        old_id = "browser-" + stable_id(bound.id, "GET", url, *([str(sequence)] if sequence else []))
        old = child_request(bound, url, "GET", "fetch", sequence).model_copy(update={"id": old_id})
        permit = gateway.begin_external_dispatch(old)
        assert isinstance(permit, ExternalDispatchPermit)
        assert gateway.authorize_external_continuation(permit)
        proof = gateway.finish_external_dispatch(permit, AdapterOutput(status="success", raw_output=b"legacy"))
        saved.append((permit.request, proof))
        return AdapterOutput(status="success")

    registry.register(Capability.BROWSER_EXPLORE, SimpleNamespace(execute=execute))
    result = gateway.execute(parent)
    old, proof = saved[0]
    reopened = ReconRepository(repository.database_path)
    gateway.results = reopened
    assert gateway.execute(parent) == result
    assert gateway.begin_external_dispatch(old) == proof
    assert len(reopened.list_child_runs(parent.id)) == 1
    assert gateway.evidence.read(proof.evidence_id) == b"legacy"


def test_browser_empty_seeds_and_paths_start_at_root(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path, paths=())
    runtime = FakeRuntime([FakeRequest("http://127.0.0.1:8000/", resource_type="document", navigation=True)])
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    agent = ReconAgent(repository, ReconPlanner(), ReconService(repository, gateway))
    result = agent.run(parent.task_id)
    assert runtime.network == [("GET", "http://127.0.0.1:8000/")]
    assert result.coverage.browser_complete and result.coverage.complete
    assert result.attack_surface_inventory.entries[0].in_scope
    agent.run(parent.task_id)
    assert len(runtime.network) == 1


def test_empty_paths_do_not_bypass_validation_or_explicit_prefixes():
    assert path_allowed("/", ()) and path_allowed("/api", ())
    assert path_allowed("/api/users", ("/api",))
    assert not path_allowed("/api2", ("/api",))
    with pytest.raises(ValueError):
        path_allowed("/api/../secret", ())


@pytest.mark.parametrize("reason", ["converged", "request_limit", "depth_or_page_limit", "total_byte_limit",
                                    "response_byte_limit", "dom_size_limit", "navigation_or_dom_error",
                                    "cancelled_or_runtime_limit"])
def test_browser_limitations_are_visible_after_static_convergence(tmp_path, reason):
    repository, registry, gateway, parent = stack(tmp_path)
    repository.save_coverage(ReconCoverage(task_id=parent.task_id, complete=True, converged=True))
    registry.register(Capability.BROWSER_EXPLORE, SimpleNamespace(execute=lambda bound: AdapterOutput(
        status="success", raw_output=json.dumps({"parent_request_id": bound.id, "stop_reason": reason}).encode(),
    )))
    service = ReconService(repository, gateway)
    plan = ReconPlan(task_id=parent.task_id, actions=(ReconAction(id="browser-test", request=parent),))
    coverage = service.run(plan).coverage
    assert coverage.static_complete and coverage.static_converged
    assert coverage.browser_configured and coverage.browser_runs == 1
    assert coverage.browser_complete is (reason == "converged")
    assert coverage.complete is (reason == "converged")
    assert coverage.converged is (reason == "converged")
    assert coverage.browser_stop_reasons == (reason,)
    assert coverage.limitations == (() if reason == "converged" else (f"browser:{reason}",))
    assert service.snapshot(parent.task_id).coverage == coverage
    assert service.run(plan).coverage == coverage


@pytest.mark.parametrize("requested", [False, True])
def test_unavailable_or_unconfigured_browser_is_not_a_failure(tmp_path, requested):
    repository, _, gateway, parent = stack(tmp_path)
    task = repository.get_task(parent.task_id)
    if not requested:
        task = task.model_copy(update={"id": "static-only", "scope": task.scope.model_copy(update={
            "capabilities": (Capability.HTTP_FETCH,),
        })})
        repository.save_task(task)
    repository.save_coverage(ReconCoverage(task_id=task.id, converged=True, complete=True))
    coverage = ReconService(repository, gateway).snapshot(task.id).coverage
    assert coverage.complete and coverage.static_complete
    assert not coverage.browser_available and not coverage.browser_configured and not coverage.browser_complete
    assert coverage.browser_runs == 0 and coverage.browser_stop_reasons == ()
    assert coverage.limitations == (("browser:unavailable",) if requested else ())
