"""Fixed GraphQL endpoint discovery and shallow read-only introspection."""

import base64
import json
import re
import ssl
from urllib.parse import urlsplit

import httpx

from src.recon.adapters import HttpFetchAdapter
from src.recon.gateway import AdapterOutput
from src.recon.models import (
    Capability,
    GraphqlDiscoveryParams,
    GraphqlIntrospectionParams,
    HttpFetchParams,
    ReconObservation,
)
from src.recon.urls import request_url

_INTROSPECTION = {"query": "query ReconSchema { __schema { queryType { name } mutationType { name } types { name kind } } }"}
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


class GraphqlDiscoveryAdapter:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.fetcher = HttpFetchAdapter(transport)

    def execute(self, request):
        params = request.parameters
        if not isinstance(params, GraphqlDiscoveryParams):
            raise TypeError("GraphQL discovery parameters required")
        fetch = request.model_copy(update={"capability": Capability.HTTP_FETCH,
            "parameters": HttpFetchParams(port=params.port, scheme=params.scheme, path=params.path,
                                          timeout_seconds=params.timeout_seconds,
                                          max_body_bytes=params.max_body_bytes)})
        response = self.fetcher.execute(fetch)
        if response.status != "success" or not response.raw_output or response.http_response is None:
            return AdapterOutput(status="error", timed_out=response.timed_out,
                                 message="GraphQL discovery request failed")
        payload = json.loads(response.raw_output)
        body = base64.b64decode(payload["body_base64"], validate=True).lower()
        status = response.http_response.status_code
        indicator = status in {200, 400, 405} and (b"graphql" in body or b"query" in body
            or "graphql" in response.http_response.content_type.lower())
        url = request_url(request.target_ip, params.scheme, params.port, params.path,
                          target_host=request.target_host)
        evidence = json.dumps({"url": url, "status_code": status, "indicator": indicator},
                              sort_keys=True).encode()
        observations = ((ReconObservation(kind="PROTOCOL", value=url,
                                          source=Capability.GRAPHQL_DISCOVERY),) if indicator else ())
        return AdapterOutput(status="success", raw_output=evidence, observations=observations)


class GraphqlIntrospectionAdapter:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.transport = transport

    def execute(self, request):
        params = request.parameters
        if not isinstance(params, GraphqlIntrospectionParams):
            raise TypeError("GraphQL introspection parameters required")
        url = request_url(request.target_ip, params.scheme, params.port, params.path,
                          target_host=request.target_host)
        transport_url = request_url(request.target_ip, params.scheme, params.port, params.path)
        options = ({"headers": {"Host": urlsplit(url).netloc},
                    "extensions": {"sni_hostname": request.target_host}} if request.target_host else {})
        body = bytearray()
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False,
                              verify=ssl.create_default_context() if request.target_host else True,
                              timeout=params.timeout_seconds,
                              headers={"Accept-Encoding": "identity", "Content-Type": "application/json"}) as client:
                with client.stream("POST", transport_url, content=json.dumps(_INTROSPECTION).encode(),
                                   **options) as response:
                    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
                        return AdapterOutput(status="error", message="encoded GraphQL response unsupported")
                    for chunk in response.iter_raw():
                        remaining = params.max_body_bytes - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            return AdapterOutput(status="error", message="GraphQL response size limit")
                    status = response.status_code
        except httpx.HTTPError:
            return AdapterOutput(status="error", message="GraphQL introspection request failed")
        schema = None
        if status == 200:
            try:
                document = json.loads(body)
                schema = document.get("data", {}).get("__schema")
            except (ValueError, AttributeError, TypeError):
                pass
        enabled = isinstance(schema, dict)
        types = schema.get("types", []) if enabled else []
        types = types if isinstance(types, list) else []
        query_type = schema.get("queryType") if enabled else None
        names = sorted({row.get("name") for row in types if isinstance(row, dict)
                        and isinstance(row.get("name"), str) and _NAME.fullmatch(row["name"])})[:64]
        query_name = query_type.get("name") if isinstance(query_type, dict) else None
        mutation_type = schema.get("mutationType") if enabled else None
        mutation_name = mutation_type.get("name") if isinstance(mutation_type, dict) else None
        summary = {"url": url, "status_code": status, "introspection_enabled": enabled,
                   "type_count": len(types), "type_names": names,
                   "query_type": query_name if isinstance(query_name, str) and _NAME.fullmatch(query_name) else None,
                   "mutation_type": mutation_name if isinstance(mutation_name, str) and _NAME.fullmatch(mutation_name) else None}
        evidence = json.dumps(summary, sort_keys=True).encode()
        observations = ((ReconObservation(kind="PROTOCOL", value=url,
                                          source=Capability.GRAPHQL_INTROSPECTION),) if enabled else ())
        return AdapterOutput(status="success", raw_output=evidence, observations=observations)
