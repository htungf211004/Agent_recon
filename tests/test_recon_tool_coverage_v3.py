"""Request-kind, provider and offline evidence security regressions."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.graphql_recon import GraphqlDiscoveryAdapter, GraphqlIntrospectionAdapter
from src.recon.models import (
    Capability,
    CapabilityRequest,
    EvidenceCapabilityRequest,
    EvidenceParams,
    ExposureDiscoveryParams,
    GraphqlDiscoveryParams,
    GraphqlIntrospectionParams,
    HttpFetchParams,
    ProviderCapabilityRequest,
    ProviderParams,
    ReconTask,
    Scope,
    parse_execution_request,
)
from src.recon.offline_analysis import OfflineEvidenceAdapter
from src.recon.offline_phase import OfflineAnalysisExecutor
from src.recon.policy import PolicyService
from src.recon.provider_search import ProviderSearchAdapter, RdapAdapter
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import HttpResponseMetadata


def _gateway(tmp_path, capabilities):
    repository = ReconRepository(tmp_path / "recon.db")
    task = ReconTask(id="task", run_id="run", scope=Scope(allowed_ips=("127.0.0.1",),
                     allowed_ports=(80,), capabilities=tuple(capabilities)),
                     expires_at=datetime.now(UTC) + timedelta(minutes=5))
    repository.save_task(task)
    repository.save_authorization(AuthorizationBoundary(task_id=task.id,
                                  root=AuthorizedTarget(kind="DOMAIN", value="example.com")))
    evidence = EvidenceStore(tmp_path / "evidence", repository)
    registry = CapabilityRegistry()
    return task, repository, evidence, registry, ToolExecutionGateway(PolicyService(repository), registry,
                                                                     evidence, repository)


def test_provider_fingerprint_replay_and_root_boundary(tmp_path, monkeypatch):
    task, repository, evidence, registry, gateway = _gateway(tmp_path, (Capability.EXTERNAL_ASSET_SEARCH,))
    monkeypatch.setenv("SHODAN_API_KEY", "sensitive-test-token")
    outbound = []

    def fetch(request, timeout):
        outbound.append(request.full_url)
        return {"matches": [{"ip_str": "203.0.113.9", "hostnames": ["www.example.com"]}]}

    registry.register(Capability.EXTERNAL_ASSET_SEARCH, ProviderSearchAdapter("shodan", fetch=fetch))
    request = ProviderCapabilityRequest(id="provider-1", task_id=task.id, root_domain="example.com",
              capability=Capability.EXTERNAL_ASSET_SEARCH, provider="shodan",
              parameters=ProviderParams(profile="root_domain", max_results=5))
    result = gateway.execute(request)
    assert result.status == "success" and result.target_ip is None
    assert len(outbound) == 1 and gateway.execute(request) == result
    assert "sensitive-test-token" not in evidence.read(result.evidence_id).decode()
    assert all(row.evidence_id == result.evidence_id for row in result.observations)
    assert parse_execution_request(repository.get_tool_run(request.id).request_payload).provider == "shodan"
    changed = request.model_copy(update={"parameters": ProviderParams(profile="root_domain", max_results=6)})
    try:
        gateway.execute(changed)
    except ValueError as exc:
        assert "reused" in str(exc)
    else:
        raise AssertionError("request replay with changed limit accepted")
    denied = request.model_copy(update={"id": "provider-2", "root_domain": "other.example"})
    assert gateway.execute(denied).status == "denied" and len(outbound) == 1


def test_missing_provider_credential_denies_before_dispatch(tmp_path, monkeypatch):
    from src.recon.provider_search import ProviderRouter

    task, repository, _evidence, registry, gateway = _gateway(tmp_path, (Capability.PUBLIC_CODE_SEARCH,))
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    registry.register(Capability.PUBLIC_CODE_SEARCH, ProviderRouter(("github",)))
    request = ProviderCapabilityRequest(id="missing-token", task_id=task.id, root_domain="example.com",
        capability=Capability.PUBLIC_CODE_SEARCH, provider="github",
        parameters=ProviderParams(profile="public_code"))
    assert registry.availability(Capability.PUBLIC_CODE_SEARCH, "github") == "MISSING_CREDENTIAL"
    result = gateway.execute(request)
    assert result.status == "denied" and "MISSING_CREDENTIAL" in result.message
    assert result.evidence_id is None and repository.budget_usage(task.id) == 0


def test_gateway_rejects_raw_provider_payload_before_evidence(tmp_path):
    task, repository, _evidence, registry, gateway = _gateway(tmp_path, (Capability.PUBLIC_CODE_SEARCH,))

    class UnsafeAdapter:
        def execute(self, request):
            return AdapterOutput(status="success", raw_output=b'{"api_key":"plaintext-secret"}')

    registry.register(Capability.PUBLIC_CODE_SEARCH, UnsafeAdapter())
    request = ProviderCapabilityRequest(id="unsafe-provider", task_id=task.id, root_domain="example.com",
        capability=Capability.PUBLIC_CODE_SEARCH, provider="github",
        parameters=ProviderParams(profile="public_code"))
    result = gateway.execute(request)
    assert result.status == "error" and result.evidence_id is None
    assert "plaintext-secret" not in result.message
    assert repository.get_tool_run(request.id).state == "FAILED"


def test_rdap_normalizes_without_personal_data(tmp_path):
    task, _repository, evidence, registry, gateway = _gateway(tmp_path, (Capability.WHOIS_RDAP_LOOKUP,))
    calls = []

    def fetch(request, timeout):
        calls.append(request.full_url)
        return {"objectClassName": "domain", "ldhName": "EXAMPLE.COM",
                "entities": [{"vcardArray": ["vcard", [["email", {}, "text", "private@example.com"]]]}],
                "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}]}

    registry.register(Capability.WHOIS_RDAP_LOOKUP, RdapAdapter(fetch=fetch))
    request = ProviderCapabilityRequest(id="rdap", task_id=task.id, root_domain="example.com",
        capability=Capability.WHOIS_RDAP_LOOKUP, provider="rdap",
        parameters=ProviderParams(profile="root_domain"))
    result = gateway.execute(request)
    assert result.status == "success" and calls == ["https://rdap.verisign.com/com/v1/domain/example.com"]
    assert "ns1.example.com" in evidence.read(result.evidence_id).decode()
    assert "private@example.com" not in evidence.read(result.evidence_id).decode()


def test_offline_sourcemap_and_wsdl_entity_rejection(tmp_path):
    task, repository, evidence, registry, gateway = _gateway(
        tmp_path, (Capability.HTTP_FETCH, Capability.SOURCEMAP_ANALYZE, Capability.WSDL_DISCOVERY))

    class RawAdapter:
        def __init__(self, raw, metadata):
            self.raw = raw
            self.metadata = metadata

        def execute(self, request):
            return AdapterOutput(status="success", raw_output=self.raw, http_response=self.metadata)

    raw_map = json.dumps({"version": 3,
        "sources": ["src/app.js", "https://outside.example/a", "src/routes.js"],
        "sourcesContent": ["secret=plaintext"]}).encode()
    envelope = {"body_base64": base64.b64encode(raw_map).decode(),
                "response": {"body_size": len(raw_map), "body_sha256": hashlib.sha256(raw_map).hexdigest()}}
    registry.register(Capability.HTTP_FETCH, RawAdapter(json.dumps(envelope).encode(),
        HttpResponseMetadata(status_code=200, content_type="application/json", body_size=len(raw_map),
                             body_sha256=hashlib.sha256(raw_map).hexdigest())))
    registry.register(Capability.SOURCEMAP_ANALYZE, OfflineEvidenceAdapter(evidence))
    registry.register(Capability.WSDL_DISCOVERY, OfflineEvidenceAdapter(evidence))
    source = gateway.execute(CapabilityRequest(id="source", task_id=task.id, target_ip="127.0.0.1",
              capability=Capability.HTTP_FETCH, parameters=HttpFetchParams(port=80, path="/app.js.map",
                                                                           max_body_bytes=1024)))
    assert source.status == "success"
    analysis = gateway.execute(EvidenceCapabilityRequest(id="analyze", task_id=task.id,
        capability=Capability.SOURCEMAP_ANALYZE, evidence_ref=source.evidence_id,
        parameters=EvidenceParams(profile="sourcemap_metadata")))
    assert analysis.status == "success"
    output = evidence.read(analysis.evidence_id).decode()
    assert "secret=plaintext" not in output and "outside.example" not in output
    assert "src/app.js" in output
    OfflineAnalysisExecutor(repository, gateway).run(task)
    assert any(row.capability == Capability.SOURCEMAP_ANALYZE and row.status == "success"
               for row in repository.list_tool_results(task.id))
    invalid = gateway.execute(EvidenceCapabilityRequest(id="wrong-task-evidence", task_id=task.id,
        capability=Capability.WSDL_DISCOVERY, evidence_ref="unknown",
        parameters=EvidenceParams(profile="wsdl_metadata")))
    assert invalid.status == "denied"
    with pytest.raises(ValueError, match="forbidden"):
        OfflineEvidenceAdapter._wsdl(b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>', 16)
    wsdl, operations = OfflineEvidenceAdapter._wsdl(
        b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">'
        b'<service name="Billing"><port name="Soap"><address location="https://example.com/soap?token=secret"/>'
        b'</port></service><operation name="GetStatus"/>'
        b'<import location="https://outside.example/wsdl?secret=raw"/></definitions>', 16)
    assert wsdl["operation"] == ["GetStatus"] and operations[0].value == "GetStatus"
    assert "token=" not in json.dumps(wsdl) and "secret=" not in json.dumps(wsdl)


def test_exposure_profile_is_fixed_and_budgeted(tmp_path):
    task, repository, evidence, registry, gateway = _gateway(tmp_path, (Capability.EXPOSURE_DISCOVERY,))
    with pytest.raises(ValueError):
        ExposureDiscoveryParams(port=80, wordlist_id="operator-file")

    class Spy:
        calls = 0

        def execute(self, request):
            self.calls += 1
            return AdapterOutput(status="success", raw_output=b"{}")

    spy = Spy()
    registry.register(Capability.EXPOSURE_DISCOVERY, spy)
    request = CapabilityRequest(id="exposure", task_id=task.id, target_ip="127.0.0.1",
        capability=Capability.EXPOSURE_DISCOVERY,
        parameters=ExposureDiscoveryParams(port=80, wordlist_id="scm-small-v1"))
    result = gateway.execute(request)
    assert result.status == "success" and spy.calls == 1
    assert repository.budget_usage(task.id) == 5
    assert gateway.execute(request) == result and spy.calls == 1


def test_graphql_introspection_is_fixed_and_requires_discovery_evidence(tmp_path):
    task, repository, evidence, registry, gateway = _gateway(tmp_path,
        (Capability.GRAPHQL_DISCOVERY, Capability.GRAPHQL_INTROSPECTION))
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.content if request.method == "POST" else b""))
        if request.method == "GET":
            return httpx.Response(400, stream=httpx.ByteStream(b"GraphQL query required"))
        body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"}, "types": [{"name": "Query", "kind": "OBJECT"}]}}}).encode()
        return httpx.Response(200, stream=httpx.ByteStream(body))

    transport = httpx.MockTransport(handler)
    registry.register(Capability.GRAPHQL_DISCOVERY, GraphqlDiscoveryAdapter(transport))
    registry.register(Capability.GRAPHQL_INTROSPECTION, GraphqlIntrospectionAdapter(transport))
    invalid = CapabilityRequest(id="invalid-introspection", task_id=task.id, target_ip="127.0.0.1",
        capability=Capability.GRAPHQL_INTROSPECTION,
        parameters=GraphqlIntrospectionParams(port=80, path="/graphql", discovery_evidence_ref="missing"))
    assert gateway.execute(invalid).status == "denied" and calls == []
    discovery = gateway.execute(CapabilityRequest(id="graphql-discovery", task_id=task.id,
        target_ip="127.0.0.1", capability=Capability.GRAPHQL_DISCOVERY,
        parameters=GraphqlDiscoveryParams(port=80, path="/graphql")))
    assert discovery.status == "success" and discovery.observations, discovery.message
    introspection = gateway.execute(CapabilityRequest(id="graphql-introspection", task_id=task.id,
        target_ip="127.0.0.1", capability=Capability.GRAPHQL_INTROSPECTION,
        parameters=GraphqlIntrospectionParams(port=80, path="/graphql",
                                              discovery_evidence_ref=discovery.evidence_id)))
    assert introspection.status == "success" and len(calls) == 2
    assert b"ReconSchema" in calls[1][2] and b"mutation {" not in calls[1][2].lower()
    assert "Query" in evidence.read(introspection.evidence_id).decode()
    assert gateway.execute(CapabilityRequest(id="graphql-introspection", task_id=task.id,
        target_ip="127.0.0.1", capability=Capability.GRAPHQL_INTROSPECTION,
        parameters=GraphqlIntrospectionParams(port=80, path="/graphql",
                                              discovery_evidence_ref=discovery.evidence_id))) == introspection
