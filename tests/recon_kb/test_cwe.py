from src.recon.kb.adapters import normalize


def test_cwe_canonical_xml_release_projects_only_enrichment(staged, tmp_path):
    raw, manifest, spec = staged("CWE")
    record = normalize(raw, manifest, spec, tmp_path, [])[0]
    assert record.value["cwe_id"] == "CWE-79"
    assert record.value["related_weaknesses"][0]["cwe_id"] == "CWE-74"
    assert "INJECTED_PAYLOAD" not in record.model_dump_json()
