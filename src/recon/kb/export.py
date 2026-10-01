"""Export review artifacts from actual promoted Recon KB snapshots."""

from __future__ import annotations

import gc
import json
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

import yaml

from src.contracts.execution import Risk
from src.contracts.recon_kb import StorageClass
from src.recon.kb.coverage import COVERAGE_PATH, CURATED_PATH, audit_coverage
from src.recon.kb.registry import load_registry
from src.recon.kb.runtime import select_runner_data
from src.recon.kb.safety import no_executable_sections
from src.recon.kb.utils import atomic_write
from src.recon.rag.models import ReconKnowledgeQuery
from src.recon.rag.runtime import live_snapshot_retriever
from src.recon.storage import ReconRepository
from src.recon.wordlists import clear_external_wordlists
from src.storage.recon_kb import KBSnapshotStore


def _write_json(path: Path, value) -> None:
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n")


def _partial_nvd(store: KBSnapshotStore) -> dict | None:
    root = store.path("raw", "NVD_CPE", ".partial")
    checkpoint_path = root / ".checkpoint.json"
    if not checkpoint_path.exists():
        return None
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    pages = sorted(root.glob("page-*.json"))
    total = json.loads(pages[-1].read_text(encoding="utf-8"))["totalResults"] if pages else 0
    return {
        "source": "NVD_CPE", "status": "PARTIAL_SYNC", "pages": len(pages),
        "records": checkpoint["index"], "cursor": checkpoint["index"], "total_results": total,
        "watermark": None, "checkpoint": str(checkpoint_path.relative_to(store.root)).replace("\\", "/"),
        "resume_command": ".venv\\Scripts\\python.exe -m src.recon.kb.cli sync NVD_CPE",
    }


def current_source_summary(store: KBSnapshotStore, registry) -> list[dict]:
    result = []
    for source_id, spec in sorted(registry.items()):
        snapshot = store.pointer(source_id, "CURRENT")
        if snapshot:
            manifest = store.manifest(source_id, snapshot)
            result.append({
                "source": source_id, "version": manifest.source_version, "commit": manifest.source_commit,
                "snapshot": snapshot, "record_count": manifest.record_count,
                "hash": manifest.normalized_sha256, "status": manifest.status.value,
                "coverage_status": manifest.coverage_status,
            })
        elif source_id == "NVD_CPE" and _partial_nvd(store):
            result.append(_partial_nvd(store))
        elif source_id == "OSV" and not spec.package_queries:
            result.append({"source": source_id, "status": "NOT_APPLICABLE",
                           "reason": "no operator-approved package evidence query"})
        else:
            result.append({"source": source_id, "status": "DISABLED" if not spec.enabled else "NOT_PROMOTED"})
    return result


def _retrieval_verification(project_root: Path, store: KBSnapshotStore, registry) -> dict:
    cases = (
        ("robots_sitemap", ReconKnowledgeQuery(categories=("robots", "sitemap"),
            available_capabilities=("http_fetch",), asset_types=("PATH",), risk_ceiling=Risk.R0)),
        ("javascript_browser", ReconKnowledgeQuery(categories=("javascript_routes", "browser_routes"),
            available_capabilities=("http_fetch", "browser_explore", "browser_request"),
            asset_types=("PATH",), risk_ceiling=Risk.R0)),
        ("technology_cpe", ReconKnowledgeQuery(categories=("technology_cpe_reference",),
            available_capabilities=(), asset_types=("SERVICE",),
            verified_technologies=("Example Product",), risk_ceiling=Risk.R0)),
    )
    with tempfile.TemporaryDirectory(prefix="recon-kb-verify-", dir=project_root / "tmp") as directory:
        repository = ReconRepository(Path(directory) / "verification.db")
        retriever = live_snapshot_retriever(repository, "verification-run", root=store.root, registry=registry)
        retriever.bind_run(repository, "verification-run")
        outputs = []
        for name, query in cases:
            chunks = retriever.retrieve(query, limit=8)
            outputs.append({"case": name, "query": query.model_dump(mode="json"),
                            "returned_knowledge_ids": [item.knowledge_id for item in chunks],
                            "snapshot_ids": sorted({item.source_snapshot_id for item in chunks})})
        runner_snapshot = store.pointer("SECLISTS", "CURRENT")
        runner_records = store.records("SECLISTS", runner_snapshot)
        selection = f"SECLISTS:{runner_records[0].runner_data_id}"
        selected = select_runner_data(repository, "verification-run", (selection,), root=store.root)
        bindings = [{"source": item.source_id, "snapshot": item.snapshot_id,
                     "storage_class": item.storage_class.value}
                    for item in repository.kb_snapshots("verification-run")]
        clear_external_wordlists()
        del repository
        gc.collect()
    return {"retriever": retriever.implementation_id, "cases": outputs,
            "runner_selection": list(selected), "run_snapshot_bindings": bindings,
            "runner_data_returned_by_rag": any(item.startswith("seclists-")
                                                for output in outputs
                                                for item in output["returned_knowledge_ids"])}


def export_artifacts(project_root: Path | str = ".", kb_root: Path | str = "data/recon_kb") -> dict:
    project_root = Path(project_root).resolve()
    store = KBSnapshotStore(project_root / kb_root)
    registry = load_registry()
    sources = current_source_summary(store, registry)
    _write_json(project_root / "ingestion-manifests.json", sources)
    _write_json(store.root / "manifests/current-sources.json", sources)

    examples = {}
    for source_id in ("RECON_CURATED", "SECLISTS", "CISA_KEV", "NUCLEI_META", "CWE"):
        snapshot = store.pointer(source_id, "CURRENT")
        if snapshot:
            records = store.records(source_id, snapshot)
            examples[source_id] = records[0].model_dump(mode="json") if records else None
    examples["NVD_CPE"] = _partial_nvd(store) or {"status": "NOT_AVAILABLE"}
    _write_json(project_root / "normalized-examples.json", examples)

    diffs = {}
    for item in sources:
        source_id, snapshot = item.get("source"), item.get("snapshot")
        if not source_id or not snapshot:
            continue
        path = store.path("normalized", source_id, snapshot, "diff.json")
        if path.exists():
            value = json.loads(path.read_text(encoding="utf-8"))
            diffs[source_id] = {**value, "added_count": len(value["added"]),
                                "removed_count": len(value["removed"]),
                                "changed_count": len(value["changed"])}
    _write_json(project_root / "dataset-diff-summary.json", diffs)

    retrieval = _retrieval_verification(project_root, store, registry)
    _write_json(project_root / "retrieval-verification.json", retrieval)

    vector_counts = Counter()
    runner_refs = defaultdict(list)
    nuclei_scan = None
    for item in sources:
        source_id, snapshot = item.get("source"), item.get("snapshot")
        if not source_id or not snapshot:
            continue
        manifest = store.manifest(source_id, snapshot)
        records = store.records(source_id, snapshot)
        if manifest.storage_class == StorageClass.VECTOR_RAG:
            vector_counts.update(record.namespace for record in records)
        elif manifest.storage_class == StorageClass.RUNNER_DATA:
            for record in records:
                runner_refs[record.sha256].append(f"{source_id}:{record.runner_data_id}")
        if source_id == "NUCLEI_META":
            for record in records:
                no_executable_sections(record.value)
            nuclei_scan = {"scanned": len(manifest.expected_artifacts), "accepted": len(records),
                           "rejected": len(manifest.rejected_artifacts),
                           "execution_fields_found": 0, "hash": manifest.normalized_sha256,
                           "snapshot": manifest.snapshot_id, "status": manifest.status.value}
    verification = {
        "coverage": audit_coverage(), "sources": sources, "vector_namespace_counts": dict(vector_counts),
        "runner_blob_dedupe": {digest: references for digest, references in runner_refs.items()},
        "physical_runner_blobs": len(list((store.root / "runner_data/blobs").glob("*.txt"))),
        "nuclei": nuclei_scan, "nvd": _partial_nvd(store), "retrieval": retrieval,
    }
    test_results = {}
    for name in ("pytest-ingestion.xml", "pytest-final.xml"):
        path = project_root / name
        if not path.exists():
            continue
        suite = ET.parse(path).getroot().find("testsuite")
        test_results[name] = {key: int(suite.attrib.get(key, 0))
                              for key in ("tests", "failures", "errors", "skipped")}
        test_results[name]["time_seconds"] = float(suite.attrib.get("time", 0))
        test_results[name]["skip_reasons"] = [case.find("skipped").attrib.get("message", "")
                                                for case in suite.findall("testcase")
                                                if case.find("skipped") is not None]
    verification["test_results"] = test_results
    _write_json(project_root / "verification-results.json", verification)

    shutil.copyfile(COVERAGE_PATH, project_root / "recon-attack-surface-coverage.yaml")
    shutil.copyfile(CURATED_PATH, project_root / "recon-as-curated-knowledge.yaml")
    coverage_rows = yaml.safe_load(COVERAGE_PATH.read_text(encoding="utf-8"))["categories"]
    lines = ["# Recon Attack Surface Coverage", "",
             "Generated from `src/recon/data/recon_attack_surface_coverage.yaml` by the deterministic audit.", "",
             "| Category | Checklist refs | Knowledge IDs | Execution mode | Capabilities | Evidence | Produces | Completion | Status | Gap |",
             "|---|---|---|---|---|---|---|---|---|---|"]

    def cell(value):
        return "<br>".join(value) if isinstance(value, list) else str(value or "")

    for row in coverage_rows:
        lines.append("| " + " | ".join(cell(row.get(key)).replace("|", "\\|") for key in (
            "category", "checklist_refs", "knowledge_ids", "execution_mode", "capabilities", "evidence",
            "produces", "completion", "status", "gap")) + " |")
    atomic_write(project_root / "docs/recon-attack-surface-coverage.md", ("\n".join(lines) + "\n").encode("utf-8"))
    return verification
