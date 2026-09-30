import pytest

from scripts.run_recon_live import scoped_task
from src.config import Settings
from src.contracts.recon_planning import StopReason
from src.recon.llm_planner import DeterministicReconPlanner
from src.recon.models import Capability


def test_live_runner_scope_is_exact_and_does_not_add_scan_capabilities():
    task = scoped_task("http://127.0.0.1:8000/api", "live-test", browser=True)
    assert task.scope.allowed_ips == ("127.0.0.1",)
    assert task.scope.allowed_ports == (8000,)
    assert task.scope.allowed_paths == ("/api",)
    assert task.scope.capabilities == (Capability.HTTP_FETCH, Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST)
    assert task.discovery_seeds == ("/api",)
    assert task.execution_budget.max_requests == 40


@pytest.mark.parametrize("url,identifier,prefix", [
    ("ftp://example.com/", "live", None),
    ("http://user:password@127.0.0.1/", "live", None),
    ("http://127.0.0.1/", "../escape", None),
    ("http://127.0.0.1/admin", "live", "/api"),
    ("http://127.1/", "live", None),
    ("http://127.0.0.1/../admin", "live", None),
])
def test_live_runner_rejects_unsupported_or_ambiguous_scope(url, identifier, prefix):
    with pytest.raises(ValueError):
        scoped_task(url, identifier, path_prefix=prefix)


@pytest.mark.parametrize("name", ["GOOGLE_API_KEY", "GEMINI_API_KEY"])
def test_gemini_settings_accept_existing_environment_key_names(name, monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    settings = Settings(_env_file=None, **{name: "test-key"})
    assert settings.google_api_key == "test-key"
    assert settings.gemini_model == "gemini-3.1-flash-lite"


def test_deterministic_planner_needs_no_provider_key():
    decision = DeterministicReconPlanner().plan(None)
    assert len(decision.proposals) == 1
    assert decision.proposals[0].reason_code == StopReason.NO_SAFE_SUPPORTED_ACTION
