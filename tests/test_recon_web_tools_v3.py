"""Pinned transport, fixed profiles and CLI result trust boundary regressions."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from src.recon.models import (
    Capability,
    CapabilityRequest,
    ParameterDiscoveryParams,
    ReconTask,
    Scope,
    TechnologyScanParams,
    VhostDiscoveryParams,
    WebCrawlParams,
)
from src.recon.web_tool_transport import web_tool_bridge
from src.recon.web_tools import ArjunAdapter, KatanaAdapter, NucleiTechnologyAdapter, VhostDiscoveryAdapter


def fixture_request(params, capability):
    task = ReconTask(id="task", run_id="run", scope=Scope(allowed_ips=("127.0.0.1",),
                     allowed_ports=(443,), capabilities=(capability,)),
                     expires_at=datetime.now(UTC) + timedelta(minutes=1))
    request = CapabilityRequest(id="request", task_id=task.id, target_ip="127.0.0.1",
                                target_host="example.com", capability=capability, parameters=params)
    return task, request


def test_bridge_pins_ip_host_sni_and_strips_credentials_redirects():
    task, request = fixture_request(WebCrawlParams(port=443, scheme="https"), Capability.WEB_CRAWL)
    seen = []

    def upstream(outbound):
        seen.append(outbound)
        return httpx.Response(302, stream=httpx.ByteStream(b""),
                              headers={"Location": "https://outside.example/", "Set-Cookie": "token=secret"})

    with web_tool_bridge(request, task, transport=httpx.MockTransport(upstream)) as bridge:
        with httpx.Client(trust_env=False) as client:
            response = client.get(bridge.origin + "/", headers={"Authorization": "secret", "Cookie": "secret"})
            assert response.status_code == 302
            assert "location" not in response.headers and "set-cookie" not in response.headers
        assert seen[0].url.host == "127.0.0.1"
        assert seen[0].headers["host"] == "example.com:443"
        assert seen[0].extensions["sni_hostname"] == "example.com"
        assert "authorization" not in seen[0].headers and "cookie" not in seen[0].headers


@pytest.mark.parametrize("method,path", [("POST", "/"), ("DELETE", "/"), ("GET", "/../private")])
def test_bridge_rejects_unapproved_requests_before_upstream(method, path):
    task, request = fixture_request(WebCrawlParams(port=443), Capability.WEB_CRAWL)
    seen = []
    with web_tool_bridge(request, task, transport=httpx.MockTransport(lambda r: seen.append(r))) as bridge:
        with httpx.Client(trust_env=False) as client:
            if ".." in path:
                response = client.get(bridge.origin + "/%2e%2e/private")
            else:
                response = client.request(method, bridge.origin + path)
        assert response.status_code == 403 and bridge.failed and not seen


def test_bridge_rejects_external_proxy_and_enforces_budget():
    task, request = fixture_request(WebCrawlParams(port=443, max_requests=1), Capability.WEB_CRAWL)
    seen = []

    def upstream(outbound):
        seen.append(outbound)
        return httpx.Response(200, stream=httpx.ByteStream(b"OK"))

    with web_tool_bridge(request, task, transport=httpx.MockTransport(upstream)) as bridge:
        with httpx.Client(proxy=bridge.origin, trust_env=False) as proxy:
            assert proxy.get("http://outside.example/").status_code == 403
        with httpx.Client(trust_env=False) as client:
            assert client.get(bridge.origin).status_code == 200
            assert client.get(bridge.origin).status_code == 403
        assert len(seen) == 1


def test_parameter_bridge_filters_bundled_dictionary_and_preserves_controls():
    task, request = fixture_request(ParameterDiscoveryParams(port=443, baseline_evidence_ref="evidence"),
                                    Capability.PARAMETER_DISCOVERY)
    seen = []

    def upstream(outbound):
        seen.append(outbound)
        return httpx.Response(200, stream=httpx.ByteStream(b"OK"))

    with web_tool_bridge(request, task, transport=httpx.MockTransport(upstream)) as bridge:
        with httpx.Client(trust_env=False) as client:
            assert client.get(bridge.origin + "/?id=1&password=x&zabc12=control").status_code == 200
        assert dict(seen[0].url.params) == {"id": "1", "zabc12": "control"}


def test_profiles_and_results_are_fixed():
    task, crawl = fixture_request(WebCrawlParams(port=443), Capability.WEB_CRAWL)
    found, _ = KatanaAdapter(None).project(crawl, b"http://127.0.0.1:9999/api?q=secret\nhttps://outside.example/", "http://127.0.0.1:9999", set())
    assert [row.value for row in found] == ["http://example.com:443/api"]
    _, vhost = fixture_request(VhostDiscoveryParams(port=443, root_domain="example.com"), Capability.VHOST_DISCOVERY)
    raw = json.dumps({"results": [{"input": {"FUZZ": "api"}, "status": 200, "length": 20},
                                   {"input": {"FUZZ": "admin"}, "status": 404, "length": 0}]}).encode()
    found, _ = VhostDiscoveryAdapter(None).project(vhost, raw, "", {(404, 0)})
    assert [row.value for row in found] == ["api.example.com"]
    _, technology = fixture_request(TechnologyScanParams(port=443), Capability.TECHNOLOGY_SCAN)
    command = NucleiTechnologyAdapter(None).command(technology, "http://127.0.0.1:9999/", "http://127.0.0.1:9999", "result.json")
    assert command.count("-t") == 2 and "-ni" in command and "-duc" in command
    with pytest.raises(ValueError):
        NucleiTechnologyAdapter(None).project(technology, b'{"template-id":"cve-untrusted"}', "", set())
    with pytest.raises(ValidationError):
        TechnologyScanParams(port=443, templates="cve.yaml")
    with pytest.raises(ValueError):
        ArjunAdapter(None).project(None, b"target skipped", "", set())


def test_katana_proxy_probe_is_local_and_vhost_proxy_never_resolves_candidate():
    task, request = fixture_request(WebCrawlParams(port=443), Capability.WEB_CRAWL)
    with web_tool_bridge(request, task, transport=httpx.MockTransport(lambda r: pytest.fail("probe forwarded"))) as bridge:
        with httpx.Client(proxy=bridge.origin, trust_env=False) as client:
            assert client.get("http://burpsuite/").status_code == 403
        assert bridge.count == 0 and not bridge.failed
    task, request = fixture_request(VhostDiscoveryParams(port=443, root_domain="example.com"), Capability.VHOST_DISCOVERY)
    seen = []

    def upstream(outbound):
        seen.append(outbound)
        return httpx.Response(200, stream=httpx.ByteStream(b""))

    with web_tool_bridge(request, task, hosts=("api.example.com",), transport=httpx.MockTransport(upstream)) as bridge:
        with httpx.Client(proxy=bridge.origin, trust_env=False) as client:
            response = client.head("http://api.example.com/", headers={"Host": "api.example.com"})
            assert response.status_code == 200
        assert seen[0].url.host == "127.0.0.1" and seen[0].headers["host"] == "api.example.com:443"
        assert seen[0].extensions["sni_hostname"] == "example.com"


@pytest.mark.parametrize("root,authorized_r2,infra,status", [
    ("DOMAIN", False, True, "COMPLETE"), ("DOMAIN", True, True, "PENDING"),
    ("IP", False, True, "COMPLETE"), ("DOMAIN", False, False, "COMPLETE"),
    ("DOMAIN", False, "host-only", "COMPLETE"),
])
def test_checklist_applicability_and_explicit_r2(monkeypatch, root, authorized_r2, infra, status):
    from src.contracts.recon_planning import ChecklistSummary
    from src.recon.checklist_v3 import project_checklist_v3
    from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget

    old = tuple(ChecklistSummary(id=f"PT_01-STT-{n:02d}", status="COMPLETE", reason="verified")
                for n in range(1, 17))
    monkeypatch.setattr("src.recon.checklist_v3.project_checklist_v2", lambda *_a, **_k: old)
    caps = {Capability.CONTENT_DISCOVERY, Capability.WEB_CRAWL, Capability.VHOST_DISCOVERY,
            Capability.PASSIVE_SUBDOMAIN_ENUM, Capability.HISTORICAL_URL_DISCOVERY, Capability.WHOIS_RDAP_LOOKUP}
    if infra:
        caps.add(Capability.PASSIVE_INFRA_ENUM)
    if root == "IP":
        caps = {Capability.NMAP_SCAN}
    results = tuple(SimpleNamespace(capability=cap, status="success", evidence_id=cap.value, observations=(),
                    message="passive_infra:metadata_unavailable"
                    if infra == "host-only" and cap == Capability.PASSIVE_INFRA_ENUM else "")
                    for cap in caps)
    scope_caps = tuple(caps | ({Capability.PARAMETER_DISCOVERY} if authorized_r2 else set()))
    task = SimpleNamespace(id="task", scope=SimpleNamespace(capabilities=scope_caps))
    boundary = AuthorizationBoundary(task_id="task", root=AuthorizedTarget(kind=root,
                                     value="example.com" if root == "DOMAIN" else "127.0.0.1"))
    repo = SimpleNamespace(get_authorization=lambda _id: boundary, list_tool_results=lambda _id: results,
                           list_tool_runs=lambda _id: ())
    service = SimpleNamespace(gateway=SimpleNamespace(evidence=SimpleNamespace(read=lambda _ref: b"verified"),
        registry=SimpleNamespace(availability=lambda *_a: "AVAILABLE")))
    rows = {row.id: row for row in project_checklist_v3(task, repo, service)}
    assert rows["PT_01-STT-02"].status == status
    if root == "IP":
        assert rows["PT_01-STT-01"].status == "NOT_APPLICABLE"
        assert rows["PT_01-STT-11"].status == "NOT_APPLICABLE"
    elif not infra:
        assert rows["PT_01-STT-01"].status != "COMPLETE"
    elif infra == "host-only":
        assert rows["PT_01-STT-01"].status == "MANUAL_REVIEW"


def test_parameter_policy_requires_baseline_scope_and_cumulative_budget(tmp_path):
    from src.recon.adapters import HttpFetchAdapter
    from src.recon.execution import ExecutionBudget
    from src.recon.gateway import CapabilityRegistry, ToolExecutionGateway
    from src.recon.models import HttpFetchParams
    from src.recon.policy import PolicyService
    from src.recon.storage import EvidenceStore, ReconRepository

    repo = ReconRepository(tmp_path / "task.db")
    task = ReconTask(id="task", run_id="run", scope=Scope(allowed_ips=("127.0.0.1",),
        allowed_ports=(80,), capabilities=(Capability.HTTP_FETCH, Capability.PARAMETER_DISCOVERY)),
        execution_budget=ExecutionBudget(max_parameter_attempts=16), expires_at=datetime.now(UTC) + timedelta(minutes=1))
    repo.save_task(task)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, HttpFetchAdapter(httpx.MockTransport(lambda r: httpx.Response(200, stream=httpx.ByteStream(b"OK")))))
    gateway = ToolExecutionGateway(PolicyService(repo), registry, EvidenceStore(tmp_path / "evidence", repo), repo)
    request = CapabilityRequest(id="arjun", task_id="task", target_ip="127.0.0.1",
        capability=Capability.PARAMETER_DISCOVERY,
        parameters=ParameterDiscoveryParams(port=80, baseline_evidence_ref="missing"))
    assert "baseline" in gateway.policy.decide(request).reason
    baseline = gateway.execute(CapabilityRequest(id="get", task_id="task", target_ip="127.0.0.1",
        capability=Capability.HTTP_FETCH, parameters=HttpFetchParams(port=80)))
    request = request.model_copy(update={"parameters": ParameterDiscoveryParams(port=80,
        baseline_evidence_ref=baseline.evidence_id, max_requests=17)})
    assert "category budget" in gateway.policy.decide(request).reason
    request = request.model_copy(update={"parameters": ParameterDiscoveryParams(port=80,
        baseline_evidence_ref=baseline.evidence_id, max_requests=16)})
    assert gateway.policy.decide(request).allowed
    restricted = task.model_copy(update={"id": "restricted", "scope": task.scope.model_copy(
        update={"capabilities": (Capability.HTTP_FETCH,)})})
    repo.save_task(restricted)
    assert gateway.policy.decide(request.model_copy(update={"task_id": restricted.id})).reason == "capability not allowed"


@pytest.mark.parametrize("with_addresses", [True, False])
def test_amass_infrastructure_output_is_observational(monkeypatch, with_addresses):
    from pathlib import Path

    from src.recon.gateway import AdapterOutput
    from src.recon.local_osint import LocalOsintAdapter
    from src.recon.models import LocalOsintCapabilityRequest, LocalOsintParams

    def fixed(command, **kwargs):
        assert "-passive" in command and "-json" in command
        Path(command[-1]).write_text(json.dumps({"name": "api.example.com",
            "addresses": [{"ip": "203.0.113.2", "asn": 64512}, {"ip": "invalid", "asn": 7}]
                          if with_addresses else None}))
        return AdapterOutput(status="success")

    monkeypatch.setattr("src.recon.local_osint._run_fixed", fixed)
    request = LocalOsintCapabilityRequest(id="infra", task_id="task", root_domain="example.com", tool="amass",
        capability=Capability.PASSIVE_INFRA_ENUM, parameters=LocalOsintParams(max_results=8))
    output = LocalOsintAdapter("amass").execute(request)
    assert output.status == "success"
    expected = {("HOST", "api.example.com")}
    if with_addresses:
        expected |= {("IP", "203.0.113.2"), ("METADATA", "asn:64512")}
    assert {(r.kind, r.value) for r in output.observations} == expected
    assert output.message == ("" if with_addresses else "passive_infra:metadata_unavailable")


def test_crawl_failed_attempt_reserves_output_limit_independently_of_request_limit(tmp_path):
    from src.recon.adapters import HttpProbeAdapter
    from src.recon.execution import ExecutionBudget
    from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
    from src.recon.models import HttpProbeParams
    from src.recon.policy import PolicyService
    from src.recon.storage import EvidenceStore, ReconRepository

    repo = ReconRepository(tmp_path / "task.db")
    task = ReconTask(id="task", run_id="run", scope=Scope(allowed_ips=("127.0.0.1",), allowed_ports=(80,),
        capabilities=(Capability.HTTP_PROBE, Capability.WEB_CRAWL)),
        execution_budget=ExecutionBudget(max_crawl_urls=12), expires_at=datetime.now(UTC) + timedelta(minutes=1))
    repo.save_task(task)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_PROBE, HttpProbeAdapter(httpx.MockTransport(
        lambda r: httpx.Response(200, stream=httpx.ByteStream(b"")))))
    calls = []

    class FailedCrawl:
        def execute(self, request):
            calls.append(request.id)
            return AdapterOutput(status="error", message="fixture crawl interrupted")

    registry.register(Capability.WEB_CRAWL, FailedCrawl())
    gateway = ToolExecutionGateway(PolicyService(repo), registry, EvidenceStore(tmp_path / "evidence", repo), repo)
    assert gateway.execute(CapabilityRequest(id="probe", task_id=task.id, target_ip="127.0.0.1",
        capability=Capability.HTTP_PROBE, parameters=HttpProbeParams(port=80))).status == "success"
    request = CapabilityRequest(id="crawl-1", task_id=task.id, target_ip="127.0.0.1",
        capability=Capability.WEB_CRAWL, parameters=WebCrawlParams(port=80, max_requests=1, max_results=8))
    assert gateway.execute(request).status == "error"
    assert gateway.execute(request).status == "error" and calls == ["crawl-1"]
    second = gateway.execute(request.model_copy(update={"id": "crawl-2"}))
    assert second.status == "denied" and "result budget" in second.message
    assert calls == ["crawl-1"]


@pytest.mark.parametrize("legacy_flag", [False, True])
def test_bare_target_cli_grants_bounded_recon_r2_by_default(tmp_path, monkeypatch, legacy_flag):
    from scripts import run_recon_live
    from src.recon.scope.admission import admit_target

    class TaskCapturedError(Exception):
        pass

    captured = []

    def save_task(task):
        captured.append(task)
        raise TaskCapturedError

    monkeypatch.setattr(run_recon_live, "admit_target", lambda root, task_id, **_kwargs:
                        admit_target(root, task_id, pinned_addresses=("127.0.0.1",)))
    monkeypatch.setattr(run_recon_live, "get_settings", lambda: SimpleNamespace(
        openai_api_key="fixture-key", model_name="fixture", openai_base_url=None))
    monkeypatch.setattr(run_recon_live, "create_recon_agent", lambda *_args: (
        SimpleNamespace(get_task=lambda _id: None, save_task=save_task), SimpleNamespace()))
    arguments = ["--target", "example.com", "--task-id", "grant", "--output-root", str(tmp_path)]
    if legacy_flag:
        arguments.append("--parameter-discovery")
    with pytest.raises(TaskCapturedError):
        run_recon_live.main(arguments)
    assert Capability.PARAMETER_DISCOVERY in captured[0].scope.capabilities


def test_cli_resume_cannot_upgrade_existing_task_to_r2(tmp_path):
    from scripts import run_recon_live
    from src.recon.scope.admission import admit_target
    from src.recon.storage import ReconRepository

    task, boundary = admit_target("example.com", "resume", pinned_addresses=("127.0.0.1",))
    task = task.model_copy(update={"scope": task.scope.model_copy(update={"capabilities": tuple(
        cap for cap in task.scope.capabilities if cap != Capability.PARAMETER_DISCOVERY)})})
    repository = ReconRepository(tmp_path / "resume" / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    with pytest.raises(SystemExit) as error:
        run_recon_live.main(["--target", "example.com", "--task-id", "resume", "--parameter-discovery",
                             "--output-root", str(tmp_path)])
    assert error.value.code == 2
    assert Capability.PARAMETER_DISCOVERY not in repository.get_task(task.id).scope.capabilities
