import json

import pytest
import yaml

from src.contracts.recon_kb import IngestionStatus
from src.recon.kb.coverage import audit_coverage, compile_curated_knowledge, load_curated_ids


def test_curated_uses_existing_pipeline_and_strict_manifest(pipeline):
    staged = pipeline.sync("RECON_CURATED")
    assert staged.status == IngestionStatus.STAGED
    assert staged.source_commit and staged.artifact_sha256 == {
        "src/recon/data/recon_as_curated_knowledge.yaml": next(iter(staged.artifact_sha256.values()))
    }
    normalized = pipeline.normalize("RECON_CURATED")
    assert normalized.record_count == 37
    ready = pipeline.validate("RECON_CURATED")
    assert ready.status == IngestionStatus.READY
    pipeline.diff("RECON_CURATED")
    promoted = pipeline.promote("RECON_CURATED")
    assert promoted.status == IngestionStatus.PROMOTED
    assert pipeline.store.pointer("RECON_CURATED", "CURRENT") == promoted.snapshot_id


def test_curated_all_records_have_real_provenance_and_runtime_capabilities(pipeline):
    manifest = pipeline.sync("RECON_CURATED")
    pipeline.normalize("RECON_CURATED")
    records = pipeline.store.records("RECON_CURATED", manifest.snapshot_id)
    assert records and all(record.source_refs for record in records)
    assert all(ref.source_id == "INTERNAL_RUNTIME" and len(ref.sha256) == 64
               for record in records for ref in record.source_refs)


def test_custom_curated_path_is_respected(tmp_path):
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text("records:\n- knowledge_id: FIRST\n", encoding="utf-8")
    second.write_text("records:\n- knowledge_id: SECOND\n", encoding="utf-8")
    assert load_curated_ids(first) == {"FIRST"}
    assert load_curated_ids(second) == {"SECOND"}


def test_curated_blocks_unknown_capability_and_scope_authority(pipeline):
    manifest = pipeline.sync("RECON_CURATED")
    raw = pipeline.store.path("raw", "RECON_CURATED", manifest.snapshot_id)
    source = raw / "src/recon/data/recon_as_curated_knowledge.yaml"
    value = yaml.safe_load(source.read_text(encoding="utf-8"))
    value["records"][0]["capabilities"] = ["invented_capability"]
    source.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown runtime capability"):
        compile_curated_knowledge(raw, manifest)

    value["records"][0]["capabilities"] = ["dns_resolve"]
    value["records"][0]["scope_mutation"] = True
    source.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="scope_mutation"):
        compile_curated_knowledge(raw, manifest)


def test_forward_and_reverse_attack_surface_coverage():
    result = audit_coverage()
    assert result["status"] == "PASS", json.dumps(result["errors"], indent=2)
    assert result["category_count"] == 38
    assert result["automatic_total"] == 33
    assert result["automatic_covered"] == 29
    assert result["counts"]["MISSING"] == 0


def test_internal_state_can_be_covered_without_capability_and_runtime_requires_one(tmp_path):
    curated = tmp_path / "curated.yaml"
    curated.write_text("records:\n- knowledge_id: K1\n", encoding="utf-8")
    base = {
        "category": "internal", "checklist_refs": [], "knowledge_ids": ["K1"], "capabilities": [],
        "requires": ["state"], "evidence": ["tool_output"], "produces": ["DiscoveredAsset"],
        "completion": "State is recorded.", "status": "COVERED", "source_paths": ["src/recon/models.py"],
    }
    coverage = tmp_path / "coverage.yaml"
    coverage.write_text(yaml.safe_dump({"categories": [{**base, "execution_mode": "INTERNAL_STATE"}]}),
                        encoding="utf-8")
    internal = audit_coverage(coverage, curated)
    assert not any("runtime execution requires capability" in error for error in internal["errors"])

    coverage.write_text(yaml.safe_dump({"categories": [{**base, "execution_mode": "RUNTIME_CAPABILITY"}]}),
                        encoding="utf-8")
    runtime = audit_coverage(coverage, curated)
    assert any("runtime execution requires capability" in error for error in runtime["errors"])
