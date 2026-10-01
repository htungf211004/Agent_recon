import pytest

from src.recon.kb.lookups import wappalyzer_runtime_metadata
from src.recon.kb.registry import load_registry
from src.recon.models import Capability, TechnologyObservation


def test_wappalyzer_fingerprints_remain_disabled_license_gated(pipeline):
    spec = load_registry()["WAPPALYZER"]
    assert not spec.enabled and spec.license_review_required
    with pytest.raises(ValueError):
        pipeline.sync("WAPPALYZER")
    with pytest.raises(ValueError, match="license"):
        spec.model_copy(update={"enabled": True}).require_enabled()
    observation = TechnologyObservation(target_ip="127.0.0.1", name="Flask", source=Capability.WHATWEB, evidence_id="ev")
    assert wappalyzer_runtime_metadata(observation).model_dump() == {
        "technology": "Flask", "categories": (), "cpe_candidate": None, "confidence": "DETECTED", "evidence_ref": "ev"}
