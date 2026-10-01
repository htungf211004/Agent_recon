import pytest
from pydantic import ValidationError

from src.contracts.recon_kb import SourceManifest
from src.recon.kb.registry import SourceSpec, load_registry


def test_manifest_requires_provenance_timezone_hash_and_ingestion_status(staged):
    _, manifest, _ = staged("WSTG")
    assert SourceManifest.model_validate_json(manifest.model_dump_json()) == manifest
    for update in ({"source_commit": None, "source_version": None}, {"content_sha256": "missing"},
                   {"status": "RUNNING"}, {"artifact_sha256": {}},
                   {"retrieved_at": "2026-10-01T00:00:00"}, {"source_url": "http://unsafe.test"}):
        with pytest.raises(ValidationError):
            SourceManifest.model_validate(manifest.model_dump() | update)


def test_registry_has_sixteen_official_sources_and_canonical_transport():
    specs = load_registry()
    assert len(specs) == 16
    assert specs["WSTG"].ref == "v4.2"
    assert specs["RECON_CURATED"].fetch_type == "local_reviewed"
    assert all(specs[key].fetch_type != "git" for key in ("PSL", "IANA_PORTS", "IANA_WELL_KNOWN", "NVD_CPE", "CWE", "OSV"))
    for change in ({"source_url": "http://github.com/x"}, {"ref": "--upload-pack=bad"}, {"paths": ("../secret",)}):
        with pytest.raises(ValidationError):
            SourceSpec.model_validate(specs["WSTG"].model_dump() | change)
