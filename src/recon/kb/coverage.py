"""Compile reviewed Recon methodology and audit Attack Surface coverage."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from src.contracts.recon_kb import SourceReference, VectorKnowledgeRecord
from src.recon.kb.utils import contained, sha256_file
from src.recon.models import Capability

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CURATED_PATH = DATA_DIR / "recon_as_curated_knowledge.yaml"
COVERAGE_PATH = DATA_DIR / "recon_attack_surface_coverage.yaml"
EXECUTION_MODES = {"RUNTIME_CAPABILITY", "INTERNAL_STATE", "MANUAL_HITL", "OUT_OF_MVP"}
COVERAGE_STATUSES = {"COVERED", "PARTIAL", "MANUAL_HITL", "OUT_OF_MVP", "MISSING"}


def _load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a mapping")
    return value


def load_curated_ids(path: Path = CURATED_PATH) -> set[str]:
    """Load IDs from the caller-selected file, including alternate test fixtures."""
    records = _load_yaml(path).get("records")
    if not isinstance(records, list):
        raise ValueError("curated knowledge requires a records list")
    ids = [record.get("knowledge_id") for record in records if isinstance(record, dict)]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("curated knowledge IDs must be non-empty and unique")
    return set(ids)


def compile_curated_knowledge(raw: Path, manifest, *, project_root: Path | None = None):
    """Compile the reviewed local YAML through the same strict vector pipeline."""
    source_record = "src/recon/data/recon_as_curated_knowledge.yaml"
    source = contained(raw, source_record)
    value = _load_yaml(source)
    records = value.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("curated knowledge requires records")
    root = (project_root or Path(__file__).resolve().parents[3]).resolve()
    known_capabilities = {item.value for item in Capability}
    seen = set()
    compiled = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("curated record must be a mapping")
        payload = dict(item)
        source_paths = payload.pop("source_paths", None)
        if not isinstance(source_paths, list) or not source_paths:
            raise ValueError("curated record requires source_paths")
        capability_tokens = payload.get("capabilities")
        delivery = payload.get("delivery", "AUTOMATIC")
        if not isinstance(capability_tokens, list):
            raise ValueError("curated capabilities must be a list")
        unknown = set(capability_tokens) - known_capabilities
        if unknown:
            raise ValueError("unknown runtime capability: " + ", ".join(sorted(unknown)))
        if not capability_tokens and delivery not in {"METHODOLOGY_ONLY", "MANUAL_HITL"}:
            raise ValueError("capability-free knowledge must be methodology-only or manual/HITL")
        refs = []
        for relative in source_paths:
            if not isinstance(relative, str) or not relative.startswith("src/"):
                raise ValueError("curated provenance must be a repository src path")
            path = contained(root, relative)
            if not path.is_file():
                raise ValueError("curated provenance source is missing: " + relative)
            refs.append(SourceReference(source_id="INTERNAL_RUNTIME", source_record=relative,
                                        sha256=sha256_file(path)))
        knowledge_id = payload.get("knowledge_id")
        if knowledge_id in seen:
            raise ValueError("duplicate curated knowledge ID")
        seen.add(knowledge_id)
        compiled.append(VectorKnowledgeRecord(
            **manifest.model_dump(include={"source_id", "source_url", "source_version", "source_commit",
                                           "retrieved_at", "snapshot_id"}),
            source_record=source_record,
            source_refs=tuple(refs),
            **payload,
        ))
    return compiled


def audit_coverage(coverage_path: Path = COVERAGE_PATH, curated_path: Path = CURATED_PATH) -> dict:
    """Deterministically audit forward and reverse mappings using runtime vocabulary."""
    value = _load_yaml(coverage_path)
    rows = value.get("categories")
    if not isinstance(rows, list) or not rows:
        raise ValueError("coverage requires categories")
    knowledge_ids = load_curated_ids(curated_path)
    capabilities = {item.value for item in Capability}
    errors = []
    categories = set()
    referenced_capabilities = set()
    counts = {status: 0 for status in sorted(COVERAGE_STATUSES)}
    automatic_total = 0
    automatic_covered = 0
    for row in rows:
        category = row.get("category")
        if not isinstance(category, str) or not category or category in categories:
            errors.append(f"invalid or duplicate category: {category!r}")
            continue
        categories.add(category)
        status = row.get("status")
        mode = row.get("execution_mode")
        if status not in COVERAGE_STATUSES:
            errors.append(f"{category}: invalid status")
            continue
        counts[status] += 1
        if mode not in EXECUTION_MODES:
            errors.append(f"{category}: invalid execution_mode")
        tokens = row.get("capabilities")
        if not isinstance(tokens, list) or set(tokens) - capabilities:
            errors.append(f"{category}: unknown runtime capability")
            tokens = []
        referenced_capabilities.update(tokens)
        ids = row.get("knowledge_ids")
        if not isinstance(ids, list) or set(ids) - knowledge_ids:
            errors.append(f"{category}: missing knowledge mapping")
        if mode in {"RUNTIME_CAPABILITY", "INTERNAL_STATE"}:
            automatic_total += 1
            if status == "COVERED":
                automatic_covered += 1
        if status == "COVERED":
            for field in ("knowledge_ids", "evidence", "produces"):
                if not row.get(field):
                    errors.append(f"{category}: COVERED requires {field}")
            if not isinstance(row.get("completion"), str) or not row["completion"].strip():
                errors.append(f"{category}: COVERED requires completion")
            if mode == "RUNTIME_CAPABILITY" and not tokens:
                errors.append(f"{category}: runtime execution requires capability")
            if mode == "INTERNAL_STATE" and not row.get("source_paths"):
                errors.append(f"{category}: internal state requires source_paths")
    orphaned = sorted(capabilities - referenced_capabilities)
    if orphaned:
        errors.append("public capabilities without coverage: " + ", ".join(orphaned))
    digest = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    return {
        "status": "PASS" if not errors else "FAIL",
        "coverage_sha256": digest,
        "category_count": len(rows),
        "automatic_total": automatic_total,
        "automatic_covered": automatic_covered,
        "counts": counts,
        "errors": errors,
    }
