import pytest

from src.recon.kb.adapters import SECLISTS_PATHS, normalize, sanitize_wordlist


def test_seclists_strict_allowlist_order_and_missing_no_substitution(staged, tmp_path):
    raw, manifest, spec = staged("SECLISTS")
    (raw / SECLISTS_PATHS[-1]).unlink()
    forbidden = raw / "Passwords" / "secrets.txt"
    forbidden.parent.mkdir()
    forbidden.write_text("credentials")
    reports = []
    records = normalize(raw, manifest, spec, tmp_path, reports)
    assert len(records) == 3 and reports
    assert all(record.source_record in SECLISTS_PATHS for record in records)
    assert sanitize_wordlist(b" z \na\nz\n# comment\n\n") == b"z\na\n"
    assert all(not record.constraints.agent_can_override_path and not record.constraints.recursive for record in records)


@pytest.mark.parametrize("content", [b"a\x00b", b"a" * 513, b"https://evil.test", b"http://evil.test", b"// comment\nhttps://evil.test",
                                     b"../secret", b"%2e%2e/secret", b"<script>", b"$(id)", b"/absolute", b"ftp://evil.test"])
def test_wordlist_rejects_dangerous_entries_without_rewriting(content):
    with pytest.raises(ValueError):
        sanitize_wordlist(content)


def test_contaminated_file_is_rejected_without_rewriting_other_allowlisted_files(staged, tmp_path):
    raw, manifest, spec = staged("SECLISTS")
    (raw / SECLISTS_PATHS[0]).write_bytes(b"safe\nhttps://unapproved.test\n")
    reports = []
    records = normalize(raw, manifest, spec, tmp_path, reports)
    assert len(records) == 3
    assert not any(record.source_record == SECLISTS_PATHS[0] for record in records)
    assert any("no rewrite or substitution" in message for message in reports)
