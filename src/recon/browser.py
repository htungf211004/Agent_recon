"""Bounded passive BFS. Every network continuation has an authorized child ToolRun."""

from __future__ import annotations

import hashlib
import json
import time
from collections import deque
from urllib.parse import urlsplit

from src.recon.browser_dom import extract_dom, project_browser_response
from src.recon.browser_response import BrowserByteBudget, BrowserResponseGuard
from src.recon.execution import ToolRunState
from src.recon.gateway import AdapterOutput, ExternalDispatchPermit, ToolExecutionGateway
from src.recon.models import BrowserExploreParams, BrowserRequestParams, Capability, CapabilityRequest
from src.recon.urls import canonical_url, normalize_candidate, path_allowed, request_url
from src.recon.web_models import HttpResponseMetadata, stable_id


def child_request(parent: CapabilityRequest, url: str, method: str, resource_type: str,
                  page_sequence: int = 0) -> CapabilityRequest:
    """Deduplicate within a page; revisiting a resource on another page is a new action."""
    if parent.capability != Capability.BROWSER_EXPLORE:
        raise ValueError("browser parent required")
    normalized = canonical_url(url)
    parts = urlsplit(normalized)
    if method not in {"GET", "HEAD"}:
        raise ValueError("browser write method blocked")
    params = parent.parameters
    if not isinstance(params, BrowserExploreParams):
        raise TypeError("browser explore parameters required")
    identity = stable_id(parent.id, method, normalized, *([str(page_sequence)] if page_sequence else []))
    return CapabilityRequest(
        id=f"browser-{identity}", task_id=parent.task_id, run_id=parent.run_id,
        scope_version=parent.scope_version, capability=Capability.BROWSER_REQUEST,
        target_ip=parts.hostname, parent_request_id=parent.id,
        parameters=BrowserRequestParams(
            port=parts.port, scheme=parts.scheme, method=method, path=parts.path,
            query=parts.query, resource_type=resource_type, page_sequence=page_sequence,
            timeout_seconds=params.limits.max_runtime_seconds,
            max_body_bytes=params.limits.max_response_bytes,
        ),
    )


class BrowserExploreAdapter:
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
        task = repository.get_task(parent.task_id)
        limits = params.limits
        initial = request_url(parent.target_ip, params.scheme, params.port, params.path, params.query)
        deadline = time.monotonic() + limits.max_runtime_seconds
        origin = urlsplit(initial)[:2]
        pending: dict[object, ExternalDispatchPermit] = {}
        guarded, ready = {}, {}
        downloads, completed, pages = [], [], []
        byte_budget = BrowserByteBudget(limits.max_response_bytes, limits.max_total_bytes)
        queue, scheduled = deque([(initial, 0)]), {initial}
        blocked = seen = page_sequence = 0
        page, current_url = None, initial
        stop_reason = ""

        def running() -> bool:
            run = repository.get_tool_run(parent.id)
            return run is not None and run.state == ToolRunState.RUNNING and time.monotonic() < deadline

        def remaining_ms() -> int:
            return max(1, int((deadline - time.monotonic()) * 1000))

        def on_route(route) -> None:
            nonlocal blocked, seen
            request = route.request
            try:
                if not running() or byte_budget.stop_reason or seen >= limits.max_requests:
                    raise ValueError("browser parent cancelled or resource limit reached")
                method = request.method.upper()
                if method not in {"GET", "HEAD"}:
                    raise ValueError("browser write method blocked")
                url = canonical_url(request.url)
                parts = urlsplit(url)
                if parts[:2] != origin:
                    raise ValueError("browser request outside current literal-IP origin")
                if request.is_navigation_request() and url != current_url:
                    raise ValueError("unplanned navigation or redirect blocked")
                if getattr(request, "service_worker", None) is not None or request.frame != page.main_frame:
                    raise ValueError("unguarded worker, frame or popup blocked")
                host = request.headers.get("host", "")
                if host and host.lower() != parts.netloc.lower():
                    raise ValueError("Host override blocked")
                child = child_request(parent, url, method, request.resource_type, page_sequence)
                outcome = self.gateway.begin_external_dispatch(child)
                if not isinstance(outcome, ExternalDispatchPermit):
                    raise ValueError("browser child denied or already claimed")
                if not self.gateway.authorize_external_continuation(outcome) or not running():
                    self.gateway.cancel(child.id)
                    raise ValueError("browser continuation permit lost")
                seen += 1
                pending[request] = outcome
                route.continue_()
            except Exception:
                blocked += 1
                route.abort()

        def finish(request, *, failed=False):
            permit = pending.pop(request, None)
            if permit is None:
                return
            response = guarded.pop(permit.request.id, None)
            if response is None:
                output = AdapterOutput(status="error", message="browser request failed")
            else:
                status, headers, size, guard_error = response
                metadata = HttpResponseMetadata(
                    status_code=status, content_type=headers.get("content-type", "")[:512],
                    body_size=0, body_sha256=hashlib.sha256(b"").hexdigest(),
                    truncated=not (headers.get("content-length") == "0" or permit.request.parameters.method == "HEAD"),
                )
                envelope = {
                    "url": canonical_url(request.url), "method": permit.request.parameters.method,
                    "response": metadata.model_dump(), "body_base64": "",
                    "location": headers.get("location", "")[:2048], "admitted_body_bytes": size,
                    "transfer_complete": not failed and not guard_error,
                }
                output = AdapterOutput(
                    status="error" if guard_error else "success",
                    message=guard_error or f"HTTP {status}; headers observed; transfer complete={not failed}",
                    raw_output=json.dumps(envelope, separators=(",", ":")).encode(), http_response=metadata,
                )
            ready[permit.request.id] = (permit, output)

        def flush():
            for permit, output in tuple(ready.values()):
                result = self.gateway.finish_external_dispatch(permit, output)
                ready.pop(permit.request.id)
                completed.append(result)
                if result.status == "success" and result.evidence_id and result.http_response:
                    project_browser_response(repository, permit.request, result, json.loads(output.raw_output))

        def lookup(method, url):
            return next((permit for request, permit in pending.items()
                         if request.method == method and canonical_url(request.url) == url), None)

        factory = self.playwright_factory
        if factory is None:
            from playwright.sync_api import sync_playwright

            factory = sync_playwright
        try:
            with factory() as playwright:
                browser = playwright.chromium.launch(headless=True, timeout=remaining_ms())
                try:
                    context = browser.new_context(
                        service_workers="block", accept_downloads=False,
                        ignore_https_errors=False, java_script_enabled=True,
                    )
                    try:
                        context.route_web_socket("**/*", lambda _socket: None)
                        context.route("**/*", on_route)
                        context.on("page", lambda new_page: new_page.on("download", lambda item: downloads.append(item)))
                        context.on("requestfinished", finish)
                        context.on("requestfailed", lambda request: finish(request, failed=True))
                        while queue and len(pages) < limits.max_pages and running() and not byte_budget.stop_reason:
                            if seen >= limits.max_requests:
                                stop_reason = "request_limit"
                                break
                            current_url, depth = queue.popleft()
                            page_sequence = len(pages)
                            pages.append({"url": current_url, "depth": depth, "page_sequence": page_sequence})
                            page = context.new_page()
                            session = context.new_cdp_session(page)
                            guard = BrowserResponseGuard(session, byte_budget, lookup,
                                lambda permit, *response: guarded.__setitem__(permit.request.id, response), running)
                            guard.install()
                            try:
                                page.goto(current_url, wait_until="load", timeout=remaining_ms())
                                if running():
                                    page.wait_for_timeout(min(250, remaining_ms()))
                                document_id = child_request(parent, current_url, "GET", "document", page_sequence).id
                                document = ready.get(document_id)
                                if (running() and not byte_budget.stop_reason and document and document[1].status == "success"
                                        and json.loads(document[1].raw_output).get("transfer_complete")):
                                    dom = extract_dom(session, remaining_ms())
                                    if len(json.dumps(dom).encode()) <= min(65536, limits.max_response_bytes):
                                        permit, output = document
                                        envelope = json.loads(output.raw_output)
                                        envelope["dom"] = dom
                                        ready[document_id] = (permit, AdapterOutput(
                                            status=output.status, message=output.message, http_response=output.http_response,
                                            raw_output=json.dumps(envelope, separators=(",", ":")).encode(),
                                        ))
                                        links = {normalize_candidate(item["url"], current_url) for item in dom
                                                 if item["relation"] == "anchor" and item["method"] == "GET"}
                                        for url in sorted(link for link in links if link is not None):
                                            if (url not in scheduled and path_allowed(urlsplit(url).path, task.scope.allowed_paths)
                                                    and not any(c in urlsplit(url).path for c in "{}")):
                                                if depth < limits.max_depth and len(scheduled) < limits.max_pages:
                                                    scheduled.add(url)
                                                    queue.append((url, depth + 1))
                                                else:
                                                    stop_reason = "depth_or_page_limit"
                                    else:
                                        stop_reason = "dom_size_limit"
                            except Exception:
                                stop_reason = stop_reason or "navigation_or_dom_error"
                            finally:
                                page.close()
                                for request in tuple(pending):
                                    finish(request, failed=True)
                                flush()
                        for download in downloads:
                            download.cancel()
                    finally:
                        context.close()
                finally:
                    browser.close()
        except Exception as exc:
            stop_reason = f"browser unavailable: {type(exc).__name__}: {exc}"
        finally:
            for request in tuple(pending):
                finish(request, failed=True)
            flush()
        if not running():
            stop_reason = "cancelled_or_runtime_limit"
        summary = {
            "parent_request_id": parent.id, "child_request_ids": sorted({result.request_id for result in completed}),
            "continued": seen, "blocked": blocked, "pages": pages, "admitted_body_bytes": byte_budget.used,
            "stop_reason": byte_budget.stop_reason or stop_reason or "converged",
        }
        return AdapterOutput(
            status="success" if running() and not downloads and any(item.status == "success" for item in completed) else "error",
            raw_output=json.dumps(summary, separators=(",", ":")).encode(),
            message=f"browser observed {len(completed)} child requests; {summary['stop_reason']}",
        )
