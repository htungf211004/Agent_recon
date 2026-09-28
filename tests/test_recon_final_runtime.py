import pytest

from scripts.check_recon_runtime import FINAL_CAPABILITIES, require_final_capabilities
from src.recon.gateway import CapabilityRegistry
from src.recon.models import Capability


def registry_for(capabilities):
    registry = CapabilityRegistry()
    for capability in capabilities:
        registry.register(capability, object())
    return registry


def test_final_manifest_requires_exact_public_capabilities():
    assert set(require_final_capabilities(registry_for(FINAL_CAPABILITIES))) == FINAL_CAPABILITIES


@pytest.mark.parametrize("missing", sorted(FINAL_CAPABILITIES))
def test_final_manifest_fails_when_runtime_capability_missing(missing):
    with pytest.raises(RuntimeError, match="missing="):
        require_final_capabilities(registry_for(FINAL_CAPABILITIES - {missing}))


def test_final_manifest_rejects_internal_browser_request():
    with pytest.raises(RuntimeError, match="unexpected="):
        require_final_capabilities(registry_for(FINAL_CAPABILITIES | {Capability.BROWSER_REQUEST}))
