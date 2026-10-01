import pytest

from src.recon.kb.adapters import normalize
from src.recon.kb.safety import acceptance


@pytest.mark.parametrize("source_id,risk", [("KATANA", "R1"), ("AMASS_OAM", "R0")])
def test_curated_tool_methodology_has_registered_provenance_and_conservative_risk(staged, tmp_path, source_id, risk):
    raw, manifest, spec = staged(source_id)
    records = normalize(raw, manifest, spec, tmp_path, [])
    assert len(records) == 1 and records[0].risk == risk
    assert records[0].source_record == spec.paths[0]
    assert not records[0].active_testing
    acceptance(records, manifest, tmp_path, spec)
