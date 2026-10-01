import json

import pytest

from src.recon.kb.adapters import normalize
from src.recon.kb.safety import EXECUTABLE_KEYS, acceptance


def test_nuclei_allowlist_projection_drops_all_execution_sections(staged, tmp_path):
    raw, manifest, spec = staged("NUCLEI_META")
    record = normalize(raw, manifest, spec, tmp_path, [])[0]
    assert not (record.value.keys() & EXECUTABLE_KEYS)
    assert "INJECTED_PAYLOAD" not in record.model_dump_json()
    assert record.value["cve_ids"] == ["CVE-2024-12345"]
    assert record.value["validation_available"] and not record.value["recon_execution_allowed"]
    acceptance([record], manifest, tmp_path, spec)
    poisoned = record.model_copy(update={"value": {**record.value, "vendor": {"http": "bad"}}})
    with pytest.raises(ValueError):
        acceptance([poisoned], manifest, tmp_path, spec)
    assert "Finding" not in json.dumps(record.value)
