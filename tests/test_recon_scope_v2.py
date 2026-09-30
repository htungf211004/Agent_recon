"""Pure root identity and derived-scope tests; no DNS or network I/O."""

import pytest

from src.contracts.recon_assets import AssetScopeStatus
from src.recon.models import Capability, WhatWebParams
from src.recon.planner import ReconPlanner
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target, parse_target
from src.recon.scope.deriver import ScopeDeriver
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget, DnsObservation
from src.recon.storage import ReconRepository


@pytest.mark.parametrize(("value", "kind", "canonical"), [
    ("Example.TEST", "DOMAIN", "example.test"),
    ("192.0.2.10", "IP", "192.0.2.10"),
    ("2001:db8::10", "IP", "2001:db8::10"),
])
def test_canonical_target_admission(value, kind, canonical):
    root = parse_target(value)
    assert (root.kind, root.value) == (kind, canonical)


@pytest.mark.parametrize("value", ["https://example.test", "example.test/path", "example.test:443",
                                     "user@example.test", "127.1", "2130706433", "0x7f000001"])
def test_ambiguous_root_rejected(value):
    with pytest.raises(ValueError):
        parse_target(value)


def test_default_domain_admission_records_all_dns_answers_and_one_dispatch_pin():
    calls = []
    def resolve(host, port):
        calls.append((host, port))
        return ("192.0.2.11", "192.0.2.10")
    task, boundary = admit_target("example.test", "task-1", resolver=resolve)
    assert calls == [("example.test", 443)]
    assert boundary.root == AuthorizedTarget(kind="DOMAIN", value="example.test", include_subdomains=True)
    assert boundary.dns_observations[0].addresses == ("192.0.2.10", "192.0.2.11")
    assert task.scope.web_origin.pinned_ip == "192.0.2.10"


def test_domain_whatweb_keeps_exact_pinned_origin_policy(tmp_path):
    task, boundary = admit_target("example.test", "whatweb-domain", pinned_addresses=("192.0.2.10",))
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    request = ReconPlanner._action(task, "192.0.2.10", Capability.WHATWEB,
                                   WhatWebParams(port=443, scheme="https")).request
    assert request.target_host == "example.test"
    assert PolicyService(repository).decide(request).allowed
    forged = request.model_copy(update={"target_host": "other.test"})
    assert not PolicyService(repository).decide(forged).allowed


def test_domain_scope_derivation_uses_label_boundaries():
    boundary = AuthorizationBoundary(task_id="t", root=AuthorizedTarget(
        kind="DOMAIN", value="example.test", include_subdomains=True))
    deriver = ScopeDeriver(boundary)
    assert deriver.classify_url("https://example.test/admin") == AssetScopeStatus.IN_SCOPE
    assert deriver.classify_host("api.example.test") == AssetScopeStatus.IN_SCOPE
    assert deriver.classify_host("dev.api.example.test") == AssetScopeStatus.IN_SCOPE
    assert deriver.classify_host("deeper.dev.api.example.test") == AssetScopeStatus.OUT_OF_SCOPE
    assert deriver.classify_host("notexample.test") == AssetScopeStatus.OUT_OF_SCOPE
    assert deriver.classify_host("cdn.thirdparty.test") == AssetScopeStatus.OUT_OF_SCOPE


def test_ip_root_requires_verified_matching_resolution_for_hostname():
    root = AuthorizedTarget(kind="IP", value="192.0.2.10")
    assert ScopeDeriver(AuthorizationBoundary(task_id="t", root=root)).classify_host("api.example.test") == AssetScopeStatus.MANUAL_REVIEW
    unverified = DnsObservation(host="api.example.test", addresses=("192.0.2.10",))
    assert ScopeDeriver(AuthorizationBoundary(task_id="t", root=root, dns_observations=(unverified,))).classify_host(
        "api.example.test") == AssetScopeStatus.MANUAL_REVIEW
    verified = unverified.model_copy(update={"evidence_ref": "evidence-1"})
    deriver = ScopeDeriver(AuthorizationBoundary(task_id="t", root=root, dns_observations=(verified,)))
    assert deriver.classify_host("api.example.test") == AssetScopeStatus.IN_SCOPE
    assert deriver.classify_host("192.0.2.11") == AssetScopeStatus.OUT_OF_SCOPE
