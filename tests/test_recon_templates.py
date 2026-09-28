import json
import sqlite3

import httpx
import pytest

from src.recon.agent import ReconAgent
from src.recon.planner import ReconPlanner
from src.recon.storage import ReconRepository
from src.recon.urls import match_route_template
from src.recon.web_models import EndpointObservation
from tests.test_recon_day2 import make_task, stack


def test_template_match_requires_exact_origin_method_path_segments():
    template = "http://127.0.0.1:8000/users/{id}"
    assert match_route_template(template, "http://127.0.0.1:8000/users/123?q=x") == {"id": "123"}
    for candidate in ("http://127.0.0.2:8000/users/123", "http://127.0.0.1:8001/users/123",
                      "http://127.0.0.1:8000/users/123/extra", "http://127.0.0.1:8000/users/{id}",
                      "http://127.0.0.1:8000/user/123"):
        assert match_route_template(template, candidate) is None


def test_unsupported_partial_template_is_inventory_only(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/openapi.json",)})
    body = json.dumps({"openapi": "3.0.0", "paths": {"/files/{name}.{ext}": {"get": {}}}}).encode()
    repository, _, _, service = stack(tmp_path, task, lambda request: httpx.Response(
        200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(body),
    ))
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    route = next(item for item in result.endpoints if item.canonical_path == "/files/{name}.{ext}")
    assert route.route_template is None and route.baseline_id is None
    assert all(item.endpoint_id != route.id for item in result.observations)
    assert result.coverage.complete is True


def test_v4_placeholder_observation_migrates_to_declared_route_only(tmp_path):
    task = make_task().model_copy(update={"discovery_seeds": ("/openapi.json",)})
    body = json.dumps({"openapi": "3.0.0", "paths": {"/users/{id}": {"get": {}}}}).encode()
    repository, _, _, service = stack(tmp_path, task, lambda request: httpx.Response(
        200, headers={"content-type": "application/json"}, stream=httpx.ByteStream(body),
    ))
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    route = next(item for item in result.endpoints if item.canonical_path == "/users/{id}")
    placeholder = EndpointObservation(task_id=task.id, endpoint_id=route.id, url=route.url,
                                      provenance=route.provenance)
    old_route = route.model_copy(update={"route_template": None, "provenance": tuple(
        item.model_copy(update={"observation_id": placeholder.id}) for item in route.provenance
    )})
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 5")
        connection.execute("UPDATE web_endpoints SET payload = ? WHERE id = ?", (old_route.model_dump_json(), route.id))
        connection.execute("INSERT INTO endpoint_observations VALUES (?, ?, ?, ?)",
                           (placeholder.id, task.id, route.id, placeholder.model_dump_json()))
    upgraded = ReconRepository(repository.database_path)
    assert upgraded.get_endpoint(route.id).route_template == "/users/{id}"
    assert all(item.id != placeholder.id for item in upgraded.list_observations(task.id))
    refreshed = service.snapshot(task.id)
    assert all(item.id != route.id for item in refreshed.attack_surface_inventory.entries)


@pytest.mark.parametrize("paths,merged", [
    ({"/users/{id}": {"get": {}}}, True),
    ({"/users/{id}": {"get": {}}, "/users/{name}": {"get": {}}}, False),
])
def test_openapi_template_merge_requires_a_unique_match(tmp_path, paths, merged):
    task = make_task().model_copy(update={"discovery_seeds": ("/", "/openapi.json")})

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  stream=httpx.ByteStream(b"<a href='/users/1'>one</a><a href='/users/2'>two</a>"))
        if request.url.path == "/openapi.json":
            return httpx.Response(200, headers={"content-type": "application/json"},
                                  stream=httpx.ByteStream(json.dumps({"openapi": "3.0.0", "paths": paths}).encode()))
        return httpx.Response(200, stream=httpx.ByteStream(b"observed"))

    repository, _, _, service = stack(tmp_path, task, handler)
    result = ReconAgent(repository, ReconPlanner(), service).run(task.id)
    routes = {entry.canonical_path: entry for entry in result.endpoints}
    if merged:
        route = routes["/users/{id}"]
        assert "/users/1" not in routes and "/users/2" not in routes
        assert route.route_template == "/users/{id}"
        assert {item.url for item in result.observations if item.endpoint_id == route.id} >= {
            "http://127.0.0.1:8000/users/1", "http://127.0.0.1:8000/users/2",
        }
        baseline = repository.get_baseline(route.baseline_id)
        assert baseline.endpoint_id == route.id and baseline.route_template == route.route_template
        assert baseline.observation_id in {item.id for item in result.observations}
        assert not any("{" in item.url for item in result.observations)
        exported = next(item for item in result.attack_surface_inventory.entries if item.id == route.id)
        assert any(proof.kind == "openapi" for proof in exported.provenance)
    else:
        assert "/users/1" in routes and "/users/2" in routes
        assert routes["/users/1"].id != routes["/users/2"].id
        assert routes["/users/{id}"].route_template and routes["/users/{name}"].route_template
