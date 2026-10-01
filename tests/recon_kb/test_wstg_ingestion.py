import pytest

from src.recon.kb.adapters import normalize
from src.recon.kb.safety import acceptance


def test_wstg_semantic_recon_subset_discards_active_prose(staged, tmp_path):
    raw, manifest, spec = staged("WSTG")
    records = normalize(raw, manifest, spec, tmp_path, [])
    assert len(records) == 10
    assert all(record.phase == "attack_surface" and not record.active_testing for record in records)
    assert all(record.content.applies_when and record.content.evidence_required and record.content.completion_rule for record in records)
    assert not any("INJECTED_PAYLOAD" in record.model_dump_json() for record in records)
    acceptance(records, manifest, tmp_path, spec)
    changed = records[0].model_copy(update={"title": "Unreviewed instructions"})
    with pytest.raises(ValueError, match="reviewed"):
        acceptance([changed, *records[1:]], manifest, tmp_path, spec)


def test_wstg_missing_scenario_is_rejected(staged, tmp_path):
    raw, manifest, spec = staged("WSTG")
    next(raw.rglob("10-*.md")).unlink()
    with pytest.raises(ValueError, match="required"):
        normalize(raw, manifest, spec, tmp_path, [])
