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


def test_nuclei_rejects_invalid_metadata_record_without_losing_valid_corpus(staged, tmp_path):
    raw, manifest, spec = staged("NUCLEI_META")
    invalid = raw / "http/technologies/invalid.yaml"
    invalid.parent.mkdir(parents=True)
    invalid.write_text("id: invalid\ninfo:\n  name: Invalid\n  classification:\n    cwe-id: CWE-0\n",
                       encoding="utf-8")
    reports = []
    records = normalize(raw, manifest, spec, tmp_path, reports)
    assert len(records) == 1
    assert reports == ["rejected Nuclei metadata: http/technologies/invalid.yaml; rule=INVALID_CWE_ID"]
