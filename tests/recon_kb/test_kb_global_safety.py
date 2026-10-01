import ast
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.contracts.execution import action_fingerprint
from src.contracts.recon_kb import IngestionStatus, VectorKnowledgeRecord
from src.recon.kb.runner import RunnerDataResolver
from src.recon.kb.runtime import select_runner_data
from src.recon.models import Capability, ContentDiscoveryParams, TechnologyObservation
from src.recon.rag.models import ReconKnowledgeQuery
from src.recon.rag.runtime import live_snapshot_retriever
from src.recon.rag.snapshot_retriever import SnapshotKnowledgeRetriever
from src.recon.storage import ReconRepository
from src.recon.wordlists import available_wordlist_ids, clear_external_wordlists, load_wordlist
from tests.recon_kb.conftest import promote_fixture, replace_json


@pytest.mark.parametrize("source_id", ["WSTG", "SECLISTS", "CISA_KEV"])
def test_full_pipeline_provenance_hashes_three_storage_classes(pipeline, source_id):
    pipeline.sync(source_id)
    assert pipeline.store.pointer(source_id, "CURRENT") is None
    assert pipeline.normalize(source_id).status == IngestionStatus.STAGED
    ready = pipeline.validate(source_id)
    assert ready.status == IngestionStatus.READY
    assert pipeline.store.pointer(source_id, "CURRENT") is None
    with pytest.raises((ValueError, FileNotFoundError)):
        pipeline.promote(source_id)
    # A failed promotion attempt quarantines the staged update; re-normalize and validate explicitly.
    pipeline.normalize(source_id)
    pipeline.validate(source_id)
    diff = pipeline.diff(source_id)
    assert diff["added"]
    promoted = pipeline.promote(source_id)
    assert promoted.status == IngestionStatus.PROMOTED and promoted.artifact_sha256 and promoted.content_sha256
    records = pipeline.store.current_records(source_id)
    assert len(records) == promoted.record_count
    assert all(record.source_record and record.source_url and record.retrieved_at and record.source_commit for record in records)
    if source_id == "SECLISTS":
        assert not pipeline.store.path("vector_docs", source_id, promoted.snapshot_id).exists()
        with pytest.raises(ValidationError):
            VectorKnowledgeRecord.model_validate(records[0].model_dump())


def test_invalid_upstream_kev_schema_quarantines_without_replacing_current(pipeline):
    original = promote_fixture(pipeline, "CISA_KEV")
    pipeline.git.commit = "b" * 40
    pipeline.git.mutate = lambda path: replace_json(path / "known_exploited_vulnerabilities.json", vulnerabilities=[{"product": "missing CVE"}])
    pipeline.sync("CISA_KEV")
    assert pipeline.normalize("CISA_KEV").status == IngestionStatus.QUARANTINED
    with pytest.raises(ValueError, match="READY"):
        pipeline.promote("CISA_KEV")
    assert pipeline.store.pointer("CISA_KEV", "CURRENT") == original.snapshot_id
    assert pipeline.store.current_records("CISA_KEV")


def test_new_artifact_set_at_same_git_commit_has_distinct_immutable_snapshot(pipeline):
    original = promote_fixture(pipeline, "SECLISTS")
    def mutate(path):
        name = path / "Discovery/Web-Content/common.txt"
        name.write_bytes(b"new-route\n")
    pipeline.git.mutate = mutate
    changed = pipeline.sync("SECLISTS")
    assert changed.source_commit == original.source_commit and changed.snapshot_id != original.snapshot_id
    assert pipeline.store.pointer("SECLISTS", "CURRENT") == original.snapshot_id
    assert pipeline.store.records("SECLISTS", original.snapshot_id)
    pipeline.normalize("SECLISTS")
    assert pipeline.validate("SECLISTS").status == IngestionStatus.READY


def test_raw_normalized_and_runner_tampering_cannot_pass_validation(pipeline):
    source = "SECLISTS"
    pipeline.sync(source)
    manifest = pipeline.normalize(source)
    records = pipeline.store.records(source, manifest.snapshot_id)
    path = pipeline.store.root / records[0].local_path
    path.write_bytes(b"different\n")
    assert pipeline.validate(source).status == IngestionStatus.QUARANTINED
    assert pipeline.store.pointer(source, "CURRENT") is None


def test_normalized_seal_detects_tampering_and_old_snapshot_is_retained(pipeline):
    original = promote_fixture(pipeline, "WSTG")
    pipeline.git.commit = "b" * 40
    pipeline.sync("WSTG")
    staged = pipeline.normalize("WSTG")
    path = pipeline.store.path("normalized", "WSTG", staged.snapshot_id, "records.jsonl")
    path.write_bytes(path.read_bytes() + b"{}\n")
    assert pipeline.validate("WSTG").status == IngestionStatus.QUARANTINED
    assert pipeline.store.current_records("WSTG")[0].snapshot_id == original.snapshot_id


def test_stale_diff_cannot_change_current(pipeline):
    promote_fixture(pipeline, "WSTG")
    pipeline.git.commit = "b" * 40
    pipeline.sync("WSTG")
    manifest = pipeline.normalize("WSTG")
    pipeline.validate("WSTG")
    pipeline.diff("WSTG")
    path = pipeline.store.path("normalized", "WSTG", manifest.snapshot_id, "diff.json")
    value = json.loads(path.read_bytes())
    value["current_snapshot_id"] = "c" * 40
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="stale"):
        pipeline.promote("WSTG")
    assert pipeline.store.pointer("WSTG", "CURRENT") == "a" * 40


def test_runner_id_resolution_hash_and_technology_gate(pipeline, staged):
    manifest = promote_fixture(pipeline, "SECLISTS")
    resolver = RunnerDataResolver(pipeline.store, "SECLISTS", manifest.snapshot_id)
    identity = next(iter(resolver.catalog))
    resolved = resolver.resolve(identity)
    assert resolved.sha256 == resolver.catalog[identity].sha256
    assert resolved.entries == ("admin", "health", "status")
    for identity_bad in ("../../secret", "C:/secret.txt", "https://evil.test/list"):
        with pytest.raises(ValueError):
            resolver.resolve(identity_bad)
    with pytest.raises(TypeError):
        resolver.resolve(identity, local_path="C:/secret.txt")
    with pytest.raises(ValueError, match="operator"):
        resolver.resolve(identity, automatic=True)
    resolved.path.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="hash"):
        resolver.resolve(identity)


def test_operator_selected_runner_data_enters_runtime_catalog_and_pins_snapshot(pipeline, tmp_path):
    manifest = promote_fixture(pipeline, "SECLISTS")
    resolver = RunnerDataResolver(pipeline.store, "SECLISTS", manifest.snapshot_id)
    identity = next(iter(resolver.catalog))
    repository = ReconRepository(tmp_path / "run.db")
    try:
        selected = select_runner_data(repository, "run-1", (f"SECLISTS:{identity}",),
                                      root=pipeline.store.root)
        assert selected == (f"SECLISTS:{identity}",)
        assert load_wordlist(identity).sha256 == resolver.catalog[identity].sha256
        assert identity in available_wordlist_ids(exclude_categories={"vhost", "parameter"})
        assert repository.kb_snapshots("run-1") == (manifest,)
        clear_external_wordlists()
        pipeline.git.commit = "b" * 40
        newer = promote_fixture(pipeline, "SECLISTS")
        assert newer.snapshot_id != manifest.snapshot_id
        select_runner_data(repository, "run-1", selected, root=pipeline.store.root)
        assert load_wordlist(identity).version == manifest.snapshot_id
        assert repository.kb_snapshots("run-1") == (manifest,)
    finally:
        clear_external_wordlists()


def test_runner_data_selection_rejects_unpromoted_or_malformed_input(pipeline, tmp_path):
    pipeline.sync("SECLISTS")
    pipeline.normalize("SECLISTS")
    pipeline.validate("SECLISTS")
    repository = ReconRepository(tmp_path / "run.db")
    with pytest.raises(ValueError, match="no promoted CURRENT"):
        select_runner_data(repository, "run-1", ("SECLISTS:any",), root=pipeline.store.root)
    with pytest.raises(ValueError, match="SOURCE_ID"):
        select_runner_data(repository, "run-1", ("invalid",), root=pipeline.store.root)


def test_technology_wordlist_requires_runtime_observation(pipeline):
    # Assetnote fixture download is already captured by FixtureGit; downloader cannot access the network.
    class FixtureHTTP:
        def download(self, spec, destination, **kwargs):
            assert destination.exists()
    pipeline.http = FixtureHTTP()
    manifest = promote_fixture(pipeline, "ASSETNOTE")
    resolver = RunnerDataResolver(pipeline.store, "ASSETNOTE", manifest.snapshot_id)
    identity = next(iter(resolver.catalog))
    with pytest.raises(ValueError, match="TechnologyObservation"):
        resolver.resolve(identity)
    observation = TechnologyObservation(target_ip="127.0.0.1", name="Flask", source=Capability.WHATWEB, evidence_id="ev")
    assert resolver.resolve(identity, technologies=(observation,)).entries


def test_vector_retrieval_prefilters_and_snapshot_bindings_are_immutable(pipeline, tmp_path):
    manifest = promote_fixture(pipeline, "WSTG")
    retriever = SnapshotKnowledgeRetriever(pipeline.store, {"WSTG": manifest.snapshot_id})
    repository = ReconRepository(tmp_path / "run.db")
    retriever.bind_run(repository, "run-1")
    query = ReconKnowledgeQuery(asset_types=("SERVICE",), available_capabilities=("http_probe",))
    chunks = retriever.retrieve(query, limit=4)
    assert len(chunks) == 1 and chunks[0].source_snapshot_id == manifest.snapshot_id
    assert retriever.retrieve(query.model_copy(update={"available_capabilities": ()}), limit=4) == ()
    assert retriever.retrieve(query.model_copy(update={"phase": "exploit"}), limit=4) == ()
    assert retriever.retrieve(query, limit=0) == ()
    pipeline.git.commit = "b" * 40
    newer = promote_fixture(pipeline, "WSTG")
    with pytest.raises(ValueError, match="immutable"):
        repository.pin_kb_snapshot("run-1", newer)
    assert repository.kb_snapshots("run-1") == (manifest,)
    assert retriever.retrieve(query, limit=4) == chunks
    runner = promote_fixture(pipeline, "SECLISTS")
    with pytest.raises(ValueError, match="VECTOR_RAG"):
        SnapshotKnowledgeRetriever(pipeline.store, {"SECLISTS": runner.snapshot_id})


def test_live_retriever_selects_current_then_keeps_run_binding_on_resume(pipeline, tmp_path):
    original = promote_fixture(pipeline, "WSTG")
    repository = ReconRepository(tmp_path / "run.db")
    retriever = live_snapshot_retriever(repository, "run-1", root=pipeline.store.root,
                                        registry=pipeline.registry)
    assert retriever.implementation_id == "recon-kb-snapshot-v1"
    retriever.bind_run(repository, "run-1")
    assert repository.kb_snapshots("run-1") == (original,)

    pipeline.git.commit = "b" * 40
    newer = promote_fixture(pipeline, "WSTG")
    assert newer.snapshot_id != original.snapshot_id
    resumed = live_snapshot_retriever(repository, "run-1", root=pipeline.store.root,
                                      registry=pipeline.registry)
    assert [item.snapshot_id for item in resumed.manifests] == [original.snapshot_id]


def test_wordlist_changes_bind_a_different_existing_action_fingerprint():
    inputs = dict(run_id="r", task_id="t", target="127.0.0.1", tool="ffuf", scope_version="1", policy_version="p", scope_fingerprint="scope")
    assert action_fingerprint(**inputs, parameters={"wordlist_id": "a"}) != action_fingerprint(**inputs, parameters={"wordlist_id": "b"})
    with pytest.raises(ValidationError):
        ContentDiscoveryParams(port=80, wordlist_id="../secret")


def test_ingestion_has_no_execution_scope_or_finding_authority():
    root = Path(__file__).resolve().parents[2] / "src" / "recon" / "kb"
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in {"src.recon.policy", "src.recon.gateway", "src.recon.scope.deriver"}
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", getattr(node.func, "attr", ""))
                assert name not in {"ToolIntent", "Finding", "execute", "save_authorization", "save_binding"}


def test_sync_all_skips_disabled_sources_and_never_promotes(pipeline):
    visited = []
    original = pipeline.registry
    pipeline.registry = {key: original[key] for key in ("WSTG", "SECLISTS", "CISA_KEV", "WAPPALYZER", "ARJUN")}
    fetch = pipeline.git.fetch
    def recording(spec, destination):
        visited.append(spec.source_id)
        return fetch(spec, destination)
    pipeline.git.fetch = recording
    assert set(pipeline.sync_all().values()) == {"READY"}
    assert set(visited) == {"WSTG", "SECLISTS", "CISA_KEV"}
    assert all(pipeline.store.pointer(key, "CURRENT") is None for key in visited)
