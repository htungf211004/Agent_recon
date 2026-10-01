from src.recon.kb.adapters import normalize
from src.recon.kb.lookups import registered_service_reference


def test_registered_service_is_reference_and_cannot_overwrite_observation(staged, tmp_path):
    raw, manifest, spec = staged("IANA_PORTS")
    records = normalize(raw, manifest, spec, tmp_path, [])
    observed = {"service": "custom-tls", "evidence_ref": "nmap-1", "port": 443}
    assert registered_service_reference(records, 443, "tcp")[0].value["service_name"] == "https"
    assert observed == {"service": "custom-tls", "evidence_ref": "nmap-1", "port": 443}
    assert all(record.value["record_kind"] == "registered_service" for record in records)
