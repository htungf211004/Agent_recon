"""Day 03 browser boundary contracts without requiring a browser binary."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from src.recon.browser import BrowserExploreAdapter, child_request
from src.recon.execution import ToolRunState
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ExternalDispatchPermit, ToolExecutionGateway
from src.recon.models import (
    BrowserExploreParams,
    BrowserLimits,
    BrowserRequestParams,
    Capability,
    CapabilityRequest,
    ReconTask,
    Scope,
)
from src.recon.policy import PolicyService
from src.recon.storage import EvidenceStore, ReconRepository


def stack(tmp_path, *, paths=("/",), max_requests=16):
    repository = ReconRepository(tmp_path / "browser.db")
    task = ReconTask(
        id="browser-task", run_id="browser-run",
        scope=Scope(
            allowed_ips=("127.0.0.1",), allowed_ports=(8000,),
            capabilities=(Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST),
            allowed_paths=paths,
        ),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    repository.save_task(task)
    registry = CapabilityRegistry()
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    gateway = ToolExecutionGateway(PolicyService(repository), registry, evidence, repository)
    parent = CapabilityRequest(
        id="explore-1", task_id=task.id, capability=Capability.BROWSER_EXPLORE,
        target_ip="127.0.0.1", parameters=BrowserExploreParams(
            port=8000, limits=BrowserLimits(max_requests=max_requests),
        ),
    )
    return repository, registry, gateway, parent


class FakeResponse:
    status = 200

    def __init__(self, request):
        self.request = request
        self.headers = request.response_headers or {"content-length": "0", "content-type": "text/plain"}


class FakeRequest:
    def __init__(self, url, method="GET", resource_type="fetch", navigation=False, response_headers=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.navigation = navigation
        self.headers = {}
        self.service_worker = None
        self.response_headers = response_headers

    def is_navigation_request(self):
        return self.navigation

    def response(self):
        return FakeResponse()


class FakeRoute:
    def __init__(self, request, page, network, after_continue=None):
        self.request = request
        self.page = page
        self.network = network
        self.after_continue = after_continue
        self.aborted = False

    def continue_(self):
        self.network.append((self.request.method, self.request.url))
        if self.after_continue:
            self.after_continue()
        response = FakeResponse(self.request)
        self.page.context.session.handlers["Network.requestWillBeSent"]({
            "requestId": self.request.url, "type": self.request.resource_type.title(),
        })
        self.page.context.session.handlers["Fetch.requestPaused"]({
            "requestId": self.request.url,
            "networkId": self.request.url,
            "request": {"method": self.request.method, "url": self.request.url},
            "resourceType": self.request.resource_type.title(),
            "responseStatusCode": response.status,
            "responseHeaders": [{"name": k, "value": v} for k, v in response.headers.items()],
        })
        self.page.context.events["requestfinished"](self.request)

    def abort(self):
        self.aborted = True


class FakePage:
    def __init__(self, context, requests, network, after_continue):
        self.context = context
        self.requests = requests
        self.network = network
        self.after_continue = after_continue
        self.events = {}
        self.routes = []
        self.main_frame = object()

    def on(self, event, callback):
        self.events[event] = callback

    def goto(self, url, **_kwargs):
        assert url == self.requests[0].url
        for request in self.requests:
            request.frame = self.main_frame
            route = FakeRoute(request, self, self.network, self.after_continue)
            self.routes.append(route)
            self.context.handler(route)

    def wait_for_timeout(self, _ms):
        pass

    def close(self):
        pass


class FakeCDP:
    def __init__(self):
        self.handlers = {}

    def on(self, _event, handler):
        self.handlers[_event] = handler

    def send(self, method, _params=None):
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "frame"}}}
        if method == "Page.createIsolatedWorld":
            return {"executionContextId": 1}
        if method == "Runtime.evaluate":
            return {"result": {"value": []}}
        return {}


class FakeContext:
    def __init__(self, requests, network, after_continue, options):
        self.requests = requests
        self.network = network
        self.after_continue = after_continue
        self.options = options
        self.page = None
        self.web_socket_handler = None
        self.events = {}

    def on(self, event, callback):
        self.events[event] = callback

    def route(self, pattern, handler):
        assert pattern == "**/*"
        self.handler = handler

    def route_web_socket(self, pattern, handler):
        assert pattern == "**/*"
        self.web_socket_handler = handler

    def new_page(self):
        self.page = FakePage(self, self.requests, self.network, self.after_continue)
        self.events["page"](self.page)
        return self.page

    def new_cdp_session(self, _page):
        self.session = FakeCDP()
        return self.session

    def close(self):
        pass


class FakeBrowser:
    def __init__(self, runtime):
        self.runtime = runtime

    def new_context(self, **options):
        self.runtime.context = FakeContext(
            self.runtime.requests, self.runtime.network, self.runtime.after_continue, options,
        )
        return self.runtime.context

    def close(self):
        pass


class FakeChromium:
    def __init__(self, runtime):
        self.runtime = runtime

    def launch(self, **options):
        assert options["headless"] is True and 0 < options["timeout"] <= 10000
        return FakeBrowser(self.runtime)


class FakeRuntime:
    def __init__(self, requests, after_continue=None):
        self.requests = requests
        self.after_continue = after_continue
        self.network = []
        self.chromium = FakeChromium(self)
        self.context = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


def test_browser_parent_child_policy_exactly_once_and_evidence(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    initial = "http://127.0.0.1:8000/"
    api = "http://127.0.0.1:8000/api"
    runtime = FakeRuntime([
        FakeRequest(initial, resource_type="document", navigation=True),
        FakeRequest(api), FakeRequest(api),
        FakeRequest("http://127.0.0.1:8000/write", method="POST"),
        FakeRequest("http://127.0.0.2:8000/outside"),
        FakeRequest("http://127.0.0.1:8000/download", navigation=True),
    ])
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    result = gateway.execute(parent)
    assert result.status == "success"
    assert runtime.network == [("GET", initial), ("GET", api)]
    assert runtime.context.options["service_workers"] == "block"
    assert runtime.context.options["accept_downloads"] is False
    assert runtime.context.web_socket_handler is not None
    assert sum(route.aborted for route in runtime.context.page.routes) == 4
    children = repository.list_child_runs(parent.id)
    assert len(children) == 2
    for child in children:
        assert child.parent_request_id == parent.id
        assert child.external_dispatched_at is not None
        assert child.state == ToolRunState.SUCCEEDED
        decision = repository.get_policy_decision(child.request_id)
        assert decision.allowed is True
        assert decision.action_fingerprint
        proof = repository.get_tool_result(child.request_id)
        assert proof.parent_request_id == parent.id
        assert gateway.evidence.read(proof.evidence_id)
    assert len(repository.list_endpoints(parent.task_id)) == 2
    reopened = ReconRepository(tmp_path / "browser.db")
    assert len(reopened.list_child_runs(parent.id)) == 2
    restarted = ToolExecutionGateway(PolicyService(reopened), CapabilityRegistry(),
                                     EvidenceStore(tmp_path / "evidence", reopened), reopened)
    assert restarted.execute(parent) == result
    assert all(restarted.evidence.read(reopened.get_tool_result(child.request_id).evidence_id)
               for child in reopened.list_child_runs(parent.id))
    assert len(runtime.network) == 2


def test_external_permit_is_one_use_and_policy_denies_child_outside_path(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path, paths=("/allowed",))

    class ParentAdapter:
        def execute(self, bound):
            child = child_request(bound, "http://127.0.0.1:8000/allowed/x", "GET", "fetch")
            permit = gateway.begin_external_dispatch(child)
            assert isinstance(permit, ExternalDispatchPermit)
            assert not isinstance(gateway.begin_external_dispatch(child), ExternalDispatchPermit)
            assert gateway.authorize_external_continuation(permit) is True
            assert gateway.authorize_external_continuation(permit) is False
            first = gateway.finish_external_dispatch(permit, AdapterOutput(status="success", raw_output=b"{}"))
            assert gateway.finish_external_dispatch(permit, AdapterOutput(status="error")) == first
            denied = gateway.begin_external_dispatch(child_request(
                bound, "http://127.0.0.1:8000/blocked", "GET", "fetch",
            ))
            assert isinstance(denied, type(first)) and denied.status == "denied"
            assert repository.get_policy_decision(denied.request_id).allowed is False
            return AdapterOutput(status="success")

    registry.register(Capability.BROWSER_EXPLORE, ParentAdapter())
    parent = parent.model_copy(update={"parameters": BrowserExploreParams(port=8000, path="/allowed")})
    assert gateway.execute(parent).status == "success"
    assert repository.budget_usage(parent.task_id) == 2


def test_cancellation_is_durable_and_late_results_are_fenced(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    permits = []

    class ParentAdapter:
        def execute(self, bound):
            child = child_request(bound, "http://127.0.0.1:8000/api", "GET", "fetch")
            permit = gateway.begin_external_dispatch(child)
            assert isinstance(permit, ExternalDispatchPermit)
            permits.append(permit)
            assert gateway.authorize_external_continuation(permit)
            assert gateway.cancel(bound.id).status == "cancelled"
            assert gateway.authorize_external_continuation(permit) is False
            assert gateway.finish_external_dispatch(permit, AdapterOutput(status="success" )).status == "cancelled"
            late = gateway.begin_external_dispatch(child_request(
                bound, "http://127.0.0.1:8000/late", "GET", "fetch",
            ))
            assert late.status == "error"
            return AdapterOutput(status="success", raw_output=b"late parent")

    registry.register(Capability.BROWSER_EXPLORE, ParentAdapter())
    result = gateway.execute(parent)
    assert result.status == "cancelled"
    assert repository.get_tool_run(parent.id).state == ToolRunState.CANCELLED
    assert repository.get_tool_run(permits[0].request.id).state == ToolRunState.CANCELLED
    assert repository.get_tool_result(permits[0].request.id).status == "cancelled"
    assert repository.get_evidence(repository.get_tool_result(permits[0].request.id).evidence_id or "missing") is None
    assert list((tmp_path / "evidence").iterdir()) == []
    reopened = ReconRepository(tmp_path / "browser.db")
    assert reopened.get_tool_result(parent.id) == result
    assert gateway.execute(parent) == result


def test_browser_cancellation_stops_later_routes(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    initial = "http://127.0.0.1:8000/"
    runtime = FakeRuntime(
        [FakeRequest(initial, resource_type="document", navigation=True),
         FakeRequest("http://127.0.0.1:8000/after")],
        after_continue=lambda: gateway.cancel(parent.id),
    )
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    result = gateway.execute(parent)
    assert result.status == "cancelled"
    assert runtime.network == [("GET", initial)]
    assert runtime.context.page.routes[1].aborted is True
    child = repository.list_child_runs(parent.id)[0]
    assert repository.get_tool_result(child.request_id).status == "cancelled"
    assert gateway.execute(parent) == result
    assert len(runtime.network) == 1


def test_attachment_response_is_not_observed_as_endpoint(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path)
    url = "http://127.0.0.1:8000/"
    runtime = FakeRuntime([FakeRequest(
        url, resource_type="document", navigation=True,
        response_headers={"content-length": "12", "content-disposition": "attachment; filename=archive.zip"},
    )])
    registry.register(Capability.BROWSER_EXPLORE, BrowserExploreAdapter(gateway, playwright_factory=lambda: runtime))
    assert gateway.execute(parent).status == "error"
    assert runtime.network == [("GET", url)]
    child = repository.list_child_runs(parent.id)[0]
    assert repository.get_tool_result(child.request_id).status == "error"
    assert repository.list_endpoints(parent.task_id) == ()


def test_browser_models_reject_write_method_and_unbounded_limits():
    with pytest.raises(ValidationError):
        BrowserRequestParams(port=8000, method="POST")
    with pytest.raises(ValidationError):
        BrowserLimits(max_requests=1000)
    with pytest.raises(ValueError):
        child_request(CapabilityRequest(
            id="parent", task_id="task", capability=Capability.BROWSER_EXPLORE,
            target_ip="127.0.0.1", parameters=BrowserExploreParams(port=8000),
        ), "http://127.0.0.1:8000/", "POST", "fetch")


def test_parent_origin_and_durable_dispatch_limit_are_enforced(tmp_path):
    repository, registry, gateway, parent = stack(tmp_path, max_requests=1)

    class ParentAdapter:
        def execute(self, bound):
            forged = child_request(bound, "http://127.0.0.1:8001/other", "GET", "fetch")
            assert gateway.begin_external_dispatch(forged).status == "error"
            first = gateway.begin_external_dispatch(child_request(
                bound, "http://127.0.0.1:8000/one", "GET", "fetch",
            ))
            second = gateway.begin_external_dispatch(child_request(
                bound, "http://127.0.0.1:8000/two", "GET", "fetch",
            ))
            assert isinstance(first, ExternalDispatchPermit)
            assert isinstance(second, ExternalDispatchPermit)
            assert gateway.authorize_external_continuation(first) is True
            assert gateway.authorize_external_continuation(second) is False
            assert gateway.cancel(second.request.id).status == "cancelled"
            gateway.finish_external_dispatch(first, AdapterOutput(status="success"))
            return AdapterOutput(status="success")

    registry.register(Capability.BROWSER_EXPLORE, ParentAdapter())
    assert gateway.execute(parent).status == "success"
    assert len(repository.list_child_runs(parent.id)) == 2
    assert sum(run.external_dispatched_at is not None for run in repository.list_child_runs(parent.id)) == 1
