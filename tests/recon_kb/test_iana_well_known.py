from src.recon.kb.adapters import normalize


def test_well_known_candidates_require_same_origin_safe_methods_and_evidence(staged, tmp_path):
    raw, manifest, spec = staged("IANA_WELL_KNOWN")
    value = normalize(raw, manifest, spec, tmp_path, [])[0].value
    assert value["path"] == "/.well-known/security.txt"
    assert value["methods"] == ["GET", "HEAD"] and value["risk"] == "R0"
    assert value["same_origin"] and not value["target_presence_confirmed"]
