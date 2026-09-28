"""Passive, isolated Playwright observer. Every network continuation has a child ToolRun."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from src.recon.execution import ToolRunState
from src.recon.gateway import AdapterOutput, ExternalDispatchPermit, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, BrowserRequestParams, Capability, CapabilityRequest, ToolResult
from src.recon.urls import canonical_url, request_url
from src.recon.web_models import (
    DiscoveryKind,
    EndpointLifecycle,
    EndpointObservation,
    EndpointProvenance,
    HttpResponseMetadata,
    WebEndpointEntry,
    stable_id,
)


def child_request(parent: CapabilityRequest, url: str, method: str, resource_type: str) -> CapabilityRequest:
    """The same concrete browser action has one durable identity within its parent."""
    if parent.capability != Capability.BROWSER_EXPLORE:
        raise ValueError("browser parent required")
    normalized = canonical_url(url)
    parts = urlsplit(normalized)
    if method not in {"GET", "HEAD"}:
        raise ValueError("browser write method blocked")
    params = parent.parameters
    if not isinstance(params, BrowserExploreParams):
        raise TypeError("browser explore parameters required")
    identity = stable_id(parent.id, method, normalized)
    return CapabilityRequest(
        id=f"browser-{identity}", task_id=parent.task_id, run_id=parent.run_id,
        scope_version=parent.scope_version, capability=Capability.BROWSER_REQUEST,
        target_ip=parts.hostname, parent_request_id=parent.id,
        parameters=BrowserRequestParams(
            port=parts.port, scheme=parts.scheme, method=method, path=parts.path,
            query=parts.query, resource_type=resource_type,
            timeout_seconds=params.limits.max_runtime_seconds,
            max_body_bytes=params.limits.max_response_bytes,
        ),
    )


class BrowserExploreAdapter:
    """No clicks, form submissions, script injection, persistent profile or implicit traffic."""

    def __init__(self, gateway: ToolExecutionGateway, *, playwright_factory=None) -> None:
        self.gateway = gateway
        self.playwright_factory = playwright_factory

    def execute(self, parent: CapabilityRequest) -> AdapterOutput:
        params = parent.parameters
        if not isinstance(params, BrowserExploreParams):
            raise TypeError("browser explore parameters required")
        from src.recon.storage import ReconRepository

        repository = self.gateway.results
        if not isinstance(repository, ReconRepository):
            raise TypeError("browser adapter requires durable ReconRepository")
        initial = request_url(parent.target_ip, params.scheme, params.port, params.path, params.query)
        deadline = time.monotonic() + params.limits.max_runtime_seconds
        origin = urlsplit(initial)
        pending: dict[object, ExternalDispatchPermit] = {}
        responses: dict[object, object] = {}
        downloads: list[object] = []
        completed: list[ToolResult] = []
        blocked = 0
        seen = 0

        def running() -> bool:
            run = repository.get_tool_run(parent.id)
            return run is not None and run.state == ToolRunState.RUNNING and time.monotonic() < deadline

        def on_route(route) -> None:
            nonlocal blocked, seen
            request = route.request
            try:
                if not running() or seen >= params.limits.max_requests:
                    raise ValueError("browser parent cancelled or resource limit reached")
                method = request.method.upper()
                if method not in {"GET", "HEAD"}:
                    raise ValueError("browser write method blocked")
                url = canonical_url(request.url)
                parts = urlsplit(url)
                if (parts.scheme, parts.hostname, parts.port) != (origin.scheme, origin.hostname, origin.port):
                    raise ValueError("browser request outside current literal-IP origin")
                if request.is_navigation_request() and url != initial:
                    raise ValueError("secondary navigation or redirect blocked")
                if getattr(request, "service_worker", None) is not None:
                    raise ValueError("service-worker request blocked")
                host = request.headers.get("host", "")
                if host and host.lower() != parts.netloc.lower():
                    raise ValueError("Host override blocked")
                child = child_request(parent, url, method, request.resource_type)
                outcome = self.gateway.begin_external_dispatch(child)
                if not isinstance(outcome, ExternalDispatchPermit):
                    completed.append(outcome)
                    raise ValueError("browser child request denied or already claimed")
                if not self.gateway.authorize_external_continuation(outcome) or not running():
                    self.gateway.cancel(child.id)
                    raise ValueError("browser continuation permit lost")
                seen += 1
                pending[request] = outcome
                route.continue_()
            except Exception:
                blocked += 1
                route.abort()

        def finish(request, *, failed: bool = False) -> None:
            permit = pending.pop(request, None)
            if permit is None:
                return
            try:
                response = None if failed else responses.pop(request, None)
                if response is None:
                    output = AdapterOutput(status="error", message="browser request failed")
                else:
                    length = response.headers.get("content-length", "")
                    oversized = length.isdigit() and int(length) > params.limits.max_response_bytes
                    attachment = response.headers.get("content-disposition", "").lower().lstrip().startswith("attachment")
                    metadata = HttpResponseMetadata(
                        status_code=response.status, content_type=response.headers.get("content-type", "")[:512],
                        body_size=0, body_sha256=hashlib.sha256(b"").hexdigest(),
                        truncated=not (length == "0" or permit.request.parameters.method == "HEAD"),
                    )
                    envelope = {
                        "url": request_url(permit.request.target_ip, permit.request.parameters.scheme,
                                           permit.request.parameters.port, permit.request.parameters.path,
                                           permit.request.parameters.query),
                        "method": permit.request.parameters.method,
                        "response": metadata.model_dump(), "body_base64": base64.b64encode(b"").decode(),
                        "location": response.headers.get("location", "")[:2048],
                    }
                    output = AdapterOutput(
                        status="error" if oversized or attachment else "success",
                        message=("download response blocked" if attachment else "response exceeded browser byte limit"
                                 if oversized else f"HTTP {response.status}; headers observed"),
                        raw_output=json.dumps(envelope, separators=(",", ":")).encode(), http_response=metadata,
                    )
                result = self.gateway.finish_external_dispatch(permit, output)
                completed.append(result)
                if result.status == "success" and result.evidence_id and result.http_response:
                    self._record_observation(repository, permit.request, result)
            except Exception as exc:
                # Browser event callbacks must never unwind into route.continue_().
                # Cancellation has already written its terminal result.
                if repository.get_tool_result(permit.request.id) is None:
                    try:
                        completed.append(self.gateway.finish_external_dispatch(
                            permit, AdapterOutput(status="error", message=f"browser response failed: {type(exc).__name__}"),
                        ))
                    except RuntimeError:
                        pass

        factory = self.playwright_factory
        if factory is None:
            from playwright.sync_api import sync_playwright

            factory = sync_playwright
        try:
            with factory() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    context = browser.new_context(
                        service_workers="block", accept_downloads=False,
                        ignore_https_errors=False, java_script_enabled=True,
                    )
                    try:
                        if not hasattr(context, "route_web_socket"):
                            raise RuntimeError("WebSocket interception unavailable")
                        # A routed socket never reaches a server unless the handler
                        # calls connect_to_server(). Keep it local and inert.
                        context.route_web_socket("**/*", lambda _socket: None)
                        context.route("**/*", on_route)
                        context.on("page", lambda new_page: new_page.on("download", lambda download: downloads.append(download)))
                        context.on("response", lambda response: responses.__setitem__(response.request, response))
                        context.on("requestfinished", finish)
                        context.on("requestfailed", lambda request: finish(request, failed=True))
                        page = context.new_page()
                        try:
                            page.goto(initial, wait_until="load", timeout=int(params.limits.max_runtime_seconds * 1000))
                            page.wait_for_timeout(min(250, int(params.limits.max_runtime_seconds * 100)))
                        except Exception:
                            if not running():
                                return AdapterOutput(status="error", message="browser exploration cancelled")
                        finally:
                            for request in tuple(pending):
                                finish(request, failed=True)
                            for download in downloads:
                                download.cancel()
                    finally:
                        context.close()
                finally:
                    browser.close()
        except Exception as exc:
            return AdapterOutput(status="error", message=f"browser unavailable: {type(exc).__name__}: {exc}")
        summary = {
            "parent_request_id": parent.id,
            "child_request_ids": sorted({result.request_id for result in completed}),
            "continued": seen, "blocked": blocked,
        }
        return AdapterOutput(
            status="success" if running() and not downloads and any(item.status == "success" for item in completed) else "error",
            raw_output=json.dumps(summary, separators=(",", ":")).encode(),
            message=f"browser observed {len(completed)} child requests; blocked {blocked}",
        )

    @staticmethod
    def _record_observation(repository, request: CapabilityRequest, result: ToolResult) -> None:
        params = request.parameters
        url = request_url(request.target_ip, params.scheme, params.port, params.path, params.query)
        source_id = stable_id(request.task_id, "browser", request.parent_request_id)
        observation_id = stable_id(request.task_id, params.method, url)
        provenance = EndpointProvenance(
            source_id=source_id, kind=DiscoveryKind.BROWSER, relation="network_request",
            evidence_id=result.evidence_id, request_id=request.id, observation_id=observation_id,
        )
        endpoint = repository.save_endpoint(WebEndpointEntry(
            task_id=request.task_id, url=url, method=params.method,
            provenance=(provenance,), lifecycle=EndpointLifecycle.OBSERVED,
            evidence_ids=(result.evidence_id,),
        ))
        repository.save_observation(EndpointObservation(
            task_id=request.task_id, endpoint_id=endpoint.id, url=url, method=params.method,
            provenance=(provenance,), request_id=request.id, evidence_id=result.evidence_id,
            response=result.http_response, observed_at=datetime.now(UTC),
        ))
