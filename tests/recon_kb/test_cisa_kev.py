import json

import pytest
from jsonschema.exceptions import ValidationError

from src.recon.kb.adapters import normalize
from src.recon.kb.lookups import kev_enrichment


def test_kev_upstream_schema_and_exact_cve_enrichment(staged, tmp_path):
    raw, manifest, spec = staged("CISA_KEV")
    records = normalize(raw, manifest, spec, tmp_path, [])
    assert kev_enrichment(records, "CVE-2024-12345") is records[0]
    assert kev_enrichment(records, "CVE-2024-99999") is None
    with pytest.raises(ValueError):
        kev_enrichment(records, "Example Vendor")
    assert records[0].value["known_exploited"]
    assert "Finding" not in records[0].model_dump_json()
    path = raw / "known_exploited_vulnerabilities.json"
    value = json.loads(path.read_text())
    del value["vulnerabilities"][0]["cveID"]
    path.write_text(json.dumps(value))
    with pytest.raises(ValidationError):
        normalize(raw, manifest, spec, tmp_path, [])


def test_kev_schema_cannot_fetch_remote_refs(staged, tmp_path):
    raw, manifest, spec = staged("CISA_KEV")
    (raw / "known_exploited_vulnerabilities_schema.json").write_text('{"$ref":"https://evil.test/schema"}')
    with pytest.raises(ValueError, match="external"):
        normalize(raw, manifest, spec, tmp_path, [])
