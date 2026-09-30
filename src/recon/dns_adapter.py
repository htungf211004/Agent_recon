"""Bounded DNS observation through ToolExecutionGateway."""

import json

from src.recon.adapters import bounded_dns_answers
from src.recon.gateway import AdapterOutput
from src.recon.models import DnsResolveParams


class DnsResolveAdapter:
    def execute(self, request):
        params = request.parameters
        if not isinstance(params, DnsResolveParams):
            raise TypeError("DNS parameters required")
        try:
            addresses = bounded_dns_answers(params.host, 443, limit=params.max_answers,
                                            timeout=params.timeout_seconds)
            return AdapterOutput(status="success", raw_output=json.dumps({
                "host": params.host, "addresses": addresses}, separators=(",", ":")).encode())
        except ValueError:
            return AdapterOutput(status="error", message="bounded DNS resolution failed")
