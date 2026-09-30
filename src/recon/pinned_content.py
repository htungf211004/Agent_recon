"""Small trusted HEAD discovery on pinned hostname transport."""

import json
import ssl
import time
from urllib.parse import urlsplit

import httpx

from src.recon.gateway import AdapterOutput
from src.recon.models import ContentDiscoveryParams
from src.recon.urls import request_url
from src.recon.wordlists import load_wordlist


class PinnedContentDiscoveryAdapter:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.transport = transport

    def execute(self, request):
        params = request.parameters
        if not isinstance(params, ContentDiscoveryParams) or not request.target_host:
            raise TypeError("pinned content discovery parameters required")
        wordlist = load_wordlist(params.wordlist_id)
        candidates = []
        start = time.monotonic()
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False,
                              verify=ssl.create_default_context(),
                              timeout=2.0, headers={"Accept-Encoding": "identity"}) as client:
                for word in wordlist.entries:
                    if time.monotonic() - start > 15:
                        return AdapterOutput(status="error", timed_out=True, message="content discovery deadline exceeded")
                    display_url = request_url(request.target_ip, params.scheme, params.port,
                                              params.path_prefix + word, target_host=request.target_host)
                    transport_url = request_url(request.target_ip, params.scheme, params.port, params.path_prefix + word)
                    try:
                        response = client.head(transport_url, headers={"Host": urlsplit(display_url).netloc},
                                               extensions={"sni_hostname": request.target_host})
                        if response.status_code != 404:
                            candidates.append({"url": display_url, "status_code": response.status_code})
                    except httpx.HTTPError:
                        continue
                    time.sleep(0.5)
        except (OSError, ValueError):
            return AdapterOutput(status="error", message="pinned content discovery failed")
        return AdapterOutput(status="success", raw_output=json.dumps({
            "wordlist_id": wordlist.id, "wordlist_sha256": wordlist.sha256,
            "method": "HEAD", "candidates": candidates}, separators=(",", ":")).encode())


class ContentDiscoveryAdapter:
    def __init__(self, ip_adapter, *, ip_available: bool):
        self.ip_adapter = ip_adapter
        self.ip_available = ip_available
        self.pinned_adapter = PinnedContentDiscoveryAdapter()

    def supports(self, request) -> bool:
        return bool(request.target_host) or self.ip_available

    def execute(self, request):
        if not self.supports(request):
            return AdapterOutput(status="error", message="FFUF adapter unavailable")
        return (self.pinned_adapter if request.target_host else self.ip_adapter).execute(request)
