"""Chromium response interception prevents implicit redirects and unbounded bodies."""

from dataclasses import dataclass

from src.recon.urls import canonical_url


@dataclass
class BrowserByteBudget:
    max_response_bytes: int
    max_total_bytes: int
    used: int = 0
    stop_reason: str = ""

    def admit(self, method: str, status: int, headers: dict[str, str]) -> tuple[int, str]:
        if 300 <= status < 400:
            return 0, "browser redirects blocked"
        if headers.get("content-disposition", "").lower().lstrip().startswith("attachment"):
            return 0, "download response blocked"
        if method == "HEAD" or status in {204, 205}:
            return 0, ""
        length = headers.get("content-length", "")
        if (not length.isascii() or not length.isdigit() or len(length) > 16
                or headers.get("transfer-encoding")
                or headers.get("content-encoding", "identity").lower() not in {"", "identity"}):
            self.stop_reason = "unbounded_response"
            return 0, "response requires an identity-encoded, explicit Content-Length"
        size = int(length)
        if size > self.max_response_bytes:
            self.stop_reason = "response_byte_limit"
            return 0, "response byte limit exceeded"
        if self.used + size > self.max_total_bytes:
            self.stop_reason = "total_byte_limit"
            return 0, "total response byte limit exceeded"
        self.used += size
        return size, ""


class BrowserResponseGuard:
    def __init__(self, session, budget: BrowserByteBudget, lookup, record, live):
        self.session, self.budget = session, budget
        self.lookup, self.record, self.live = lookup, record, live
        self.resource_types = {}

    def install(self):
        self.session.on("Network.requestWillBeSent", self.on_request)
        self.session.send("Network.enable")
        self.session.on("Fetch.requestPaused", self.on_response)
        self.session.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]})

    def on_request(self, event):
        # Fetch.requestPaused labels fetch() as XHR on Chromium. Network's type
        # is the same source Playwright uses and networkId correlates the events.
        if len(self.resource_types) < 256:
            self.resource_types[event["requestId"]] = event.get("type", "").lower()

    def on_response(self, event):
        request_id = event["requestId"]
        try:
            request = event["request"]
            resource_type = self.resource_types.pop(event.get("networkId"), "")
            permit = self.lookup(request["method"], canonical_url(request["url"]), resource_type)
            if permit is None or not self.live() or "responseStatusCode" not in event:
                # Aborted navigation/POST can still produce a CDP error pause.
                # Reject it without stopping unrelated, already authorized responses.
                self.session.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
                return
            headers = {}
            for item in event.get("responseHeaders", []):
                key = item["name"].lower()
                headers[key] = headers[key] + "," + item["value"] if key in headers else item["value"]
            size, reason = self.budget.admit(request["method"], event["responseStatusCode"], headers)
            self.record(permit, event["responseStatusCode"], headers, size, reason)
            if reason:
                self.session.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            else:
                self.session.send("Fetch.continueResponse", {"requestId": request_id})
        except Exception:
            self.budget.stop_reason = self.budget.stop_reason or "response_guard_error"
            try:
                self.session.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
            except Exception:
                pass  # Never continue a response when the guard cannot prove its state.
