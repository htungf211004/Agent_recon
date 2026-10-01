import json

import pytest

from src.recon.kb.adapters import normalize
from src.recon.kb.fetchers import package_query


def test_osv_dependency_identity_provenance_and_withdrawn_advisory(staged, tmp_path):
    raw, manifest, spec = staged("OSV")
    record = normalize(raw, manifest, spec, tmp_path, [])[0]
    assert not record.value["active_candidate"]
    assert record.value["package_evidence_ref"] == "package-lock-evidence"
    assert record.value["source_database"] == "GHSA" and record.value["source_license"] is None
    query = raw / "query-0000-page-0000.context.json"
    value = json.loads(query.read_text())
    value["name"] = "different-package"
    query.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="differs"):
        normalize(raw, manifest, spec, tmp_path, [])


@pytest.mark.parametrize("query", [{"name": "nginx", "version": "1.0", "evidence_ref": "banner"},
                                   {"name": "package", "ecosystem": "npm", "version": "1.0"},
                                   {"purl": "https://evil.test", "version": "1.0", "evidence_ref": "ev"}])
def test_osv_rejects_banners_and_missing_package_evidence(query):
    with pytest.raises(ValueError):
        package_query(query)
