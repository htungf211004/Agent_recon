from src.recon.kb.adapters import normalize
from src.recon.kb.lookups import registrable_domain


def test_psl_icann_private_wildcard_exception_and_no_scope_mutation(staged, tmp_path):
    raw, manifest, spec = staged("PSL")
    records = normalize(raw, manifest, spec, tmp_path, [])
    assert {record.value["rule_type"] for record in records} == {"EXACT", "WILDCARD", "EXCEPTION"}
    assert {record.value["section"] for record in records} == {"ICANN", "PRIVATE"}
    assert registrable_domain(records, "a.example.co.uk") == "example.co.uk"
    assert registrable_domain(records, "a.foo.ck") == "a.foo.ck"
    assert registrable_domain(records, "a.www.ck") == "www.ck"
    assert registrable_domain(records, "co.uk") is None
    assert registrable_domain(records, "a.blogspot.com") == "a.blogspot.com"
    assert registrable_domain(records, "a.blogspot.com", include_private=False) == "blogspot.com"
