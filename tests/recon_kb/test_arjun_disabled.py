import pytest

from src.recon.kb.registry import load_registry


def test_arjun_cannot_enable_parameter_probing_even_if_registry_is_changed(pipeline):
    spec = load_registry()["ARJUN"]
    assert not spec.enabled and spec.license_review_required
    assert all("special.json" not in name for name in spec.paths)
    with pytest.raises(ValueError, match="disabled"):
        spec.model_copy(update={"enabled": True, "license_status": "APPROVED"}).require_enabled()
    with pytest.raises(ValueError):
        pipeline.sync("ARJUN")
