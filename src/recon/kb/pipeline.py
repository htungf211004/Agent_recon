"""FETCH -> RAW -> NORMALIZE -> FILTER -> SCHEMA -> ACCEPT -> STAGE -> DIFF -> PROMOTE."""

import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from src.contracts.recon_kb import ArtifactRejection, IngestionStatus, SourceManifest, StorageClass, ValidationAttempt
from src.recon.kb.adapters import ADAPTER_VERSION, SECLISTS_PATHS, assetnote_downloads, normalize
from src.recon.kb.fetchers import GitFetcher, HTTPDownloader, fetch_nvd, fetch_osv
from src.recon.kb.registry import load_registry
from src.recon.kb.safety import acceptance
from src.recon.kb.utils import artifact_hashes, atomic_write, contained, json_bytes, sha256_file, tree_hash
from src.storage.recon_kb import KBSnapshotStore


class IngestionPipeline:
    def __init__(self, root: Path | str = "data/recon_kb", *, registry=None, git=None, http=None, clock=None):
        self.store = KBSnapshotStore(root)
        self.registry = registry if registry is not None else load_registry()
        self.git = git or GitFetcher()
        self.http = http or HTTPDownloader()
        self.clock = clock or (lambda: datetime.now(UTC))

    def spec(self, source_id):
        if source_id not in self.registry:
            raise ValueError("unknown registered source")
        spec = self.registry[source_id]
        spec.require_enabled()
        return spec

    def _staged(self, source_id):
        spec = self.spec(source_id)
        snapshot = self.store.pointer(source_id, "STAGED")
        if not snapshot:
            raise ValueError("no staged snapshot")
        manifest = self.store.manifest(source_id, snapshot)
        if spec.storage_class != manifest.storage_class or spec.namespace != manifest.namespace:
            raise ValueError("registry storage configuration changed")
        return spec, manifest

    def sync(self, source_id):
        spec = self.spec(source_id)
        with self.store.lock(source_id):
            now = self.clock()
            incoming = (self.store.path("raw", source_id, ".partial") if source_id == "NVD_CPE"
                        else self.store.path("raw", source_id, ".incoming-" + uuid4().hex))
            incoming.mkdir(parents=True, exist_ok=source_id == "NVD_CPE")
            reports, commit, watermark = [], None, None
            base = self.store.pointer(source_id, "CURRENT")
            try:
                if spec.fetch_type == "git":
                    commit, reports = self.git.fetch(spec, incoming)
                    if source_id == "ASSETNOTE":
                        for selected in assetnote_downloads(incoming, spec):
                            self.http.download(spec, contained(incoming, "downloads/" + selected["filename"]),
                                               trusted_url=selected["url"])
                elif spec.fetch_type == "http":
                    if len(spec.paths) != 1:
                        raise ValueError("HTTP source requires one registered artifact path")
                    self.http.download(spec, contained(incoming, spec.paths[0]))
                elif spec.fetch_type == "nvd_api":
                    prior = self.store.manifest(source_id, base) if base else None
                    watermark = fetch_nvd(spec, incoming, self.http, watermark=prior.sync_watermark if prior else None,
                                          clock=self.clock)
                elif spec.fetch_type == "osv_api":
                    fetch_osv(spec, incoming, self.http)
                elif spec.fetch_type == "local_reviewed":
                    project_root = Path(__file__).resolve().parents[3]
                    for relative in spec.paths:
                        source = contained(project_root, relative)
                        if not source.is_file():
                            raise ValueError("reviewed local source is missing")
                        destination = contained(incoming, relative)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, destination)
                    git_entry = project_root / ".git"
                    if git_entry.is_file():
                        git_dir = (project_root / git_entry.read_text(encoding="utf-8").split(":", 1)[1].strip()).resolve()
                    else:
                        git_dir = git_entry
                    head = (git_dir / "HEAD").read_text(encoding="ascii").strip()
                    if head.startswith("ref: "):
                        ref = head.removeprefix("ref: ")
                        loose = git_dir / ref
                        if loose.exists():
                            commit = loose.read_text(encoding="ascii").strip()
                        else:
                            packed = (git_dir / "packed-refs").read_text(encoding="ascii").splitlines()
                            commit = next(line.split(" ", 1)[0] for line in packed
                                          if not line.startswith(("#", "^")) and line.endswith(" " + ref))
                    else:
                        commit = head
                    if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
                        raise ValueError("invalid local Git commit")
                hashes = artifact_hashes(incoming)
                if not hashes or sum(path.stat().st_size for path in incoming.rglob("*") if path.is_file()) > spec.max_snapshot_bytes:
                    raise ValueError("empty or excessive raw snapshot")
                digest = tree_hash(hashes)
                snapshot = commit or now.strftime("%Y%m%dT%H%M%S%fZ") + "-" + digest
                raw = self.store.path("raw", source_id, snapshot)
                if raw.exists():
                    existing = self.store.manifest(source_id, snapshot)
                    self._verify_raw(existing)
                    if existing.artifact_sha256 == hashes:
                        self.store.set_pointer(source_id, "STAGED", snapshot)
                        return existing
                    # A reviewed selection or trusted CDN artifact may change at the same Git commit.
                    # Give the new artifact set its own identity; never overwrite the earlier raw snapshot.
                    snapshot = snapshot + "-" + digest[:32]
                    raw = self.store.path("raw", source_id, snapshot)
                    if raw.exists():
                        existing = self.store.manifest(source_id, snapshot)
                        self._verify_raw(existing)
                        if existing.content_sha256 != digest:
                            raise ValueError("snapshot identity collision")
                        self.store.set_pointer(source_id, "STAGED", snapshot)
                        return existing
                incoming.rename(raw)
                manifest = SourceManifest(source_id=source_id, source_url=spec.source_url, source_version=spec.ref or digest,
                    source_commit=commit, retrieved_at=now, snapshot_id=snapshot, source_record=".",
                    license=spec.license, license_status=spec.license_status, adapter_version=ADAPTER_VERSION,
                    storage_class=spec.storage_class, namespace=spec.namespace, record_count=0,
                    content_sha256=digest, artifact_sha256=hashes, status=IngestionStatus.STAGED,
                    sync_watermark=watermark, base_snapshot_id=base if source_id == "NVD_CPE" and base else None,
                    reports=tuple(reports))
                self.store.save_manifest(manifest)
                self.store.set_pointer(source_id, "STAGED", snapshot)
                return manifest
            except Exception as error:
                # Preserve failed fetch bytes and a bounded audit report without displacing STAGED or CURRENT.
                atomic_write(self.store.path("manifests", source_id, "FAILED-" + uuid4().hex + ".json"),
                    json_bytes({"source_id": source_id, "status": "FAILED", "retrieved_at": now.isoformat(),
                                "error": type(error).__name__, "raw_path": str(incoming),
                                "artifact_sha256": artifact_hashes(incoming) if incoming.exists() else {}}))
                raise
            finally:
                if incoming.exists() and not any(incoming.iterdir()):
                    incoming.rmdir()

    def _verify_raw(self, manifest):
        raw = self.store.path("raw", manifest.source_id, manifest.snapshot_id)
        if artifact_hashes(raw) != manifest.artifact_sha256 or tree_hash(manifest.artifact_sha256) != manifest.content_sha256:
            raise ValueError("raw snapshot integrity mismatch")
        return raw

    def _quarantine(self, manifest, error):
        message = type(error).__name__ + ": " + str(error)[:400]
        result = manifest.model_copy(update={"status": IngestionStatus.QUARANTINED,
                                            "reports": (*manifest.reports, "validation failed: " + message),
                                            "final_validation_errors": (message,),
                                            "attempt_history": (*manifest.attempt_history,
                                                                ValidationAttempt(status="FAILED", errors=(message,)))})
        if manifest.status != IngestionStatus.PROMOTED:
            self.store.save_manifest(result)
        return result

    def normalize(self, source_id):
        with self.store.lock(source_id):
            spec, manifest = self._staged(source_id)
            if manifest.status in {IngestionStatus.READY, IngestionStatus.PROMOTED}:
                self._verify_raw(manifest)
                self.store.records(source_id, manifest.snapshot_id)
                return manifest
            reports = list(manifest.reports)
            try:
                raw = self._verify_raw(manifest)
                records = normalize(raw, manifest, spec, self.store.root, reports)
                if manifest.base_snapshot_id:
                    base_records = self.store.records(source_id, manifest.base_snapshot_id)
                    combined = {record.record_id: record for record in base_records}
                    combined.update({record.record_id: record for record in records})
                    records = list(combined.values())
                # Dedupe exact records; conflicting identities fail acceptance instead of silently overwriting.
                unique = {record.model_dump_json(): record for record in records}
                records = list(unique.values())
                acceptance(records, manifest, self.store.root, spec)
                content = b"".join(json_bytes(record.model_dump(mode="json")) for record in records)
                path = self.store.path("normalized", source_id, manifest.snapshot_id, "records.jsonl")
                atomic_write(path, content)
                semantics = {"final_validation_errors": (), "final_warnings": tuple(reports)}
                if source_id == "SECLISTS":
                    accepted = tuple(record.source_record for record in records)
                    rejected = []
                    for name in SECLISTS_PATHS:
                        if name in accepted:
                            continue
                        report = next((item for item in reports if name in item), "artifact unavailable")
                        rule = report.split("; rule=", 1)[1] if "; rule=" in report else "MISSING"
                        rejected.append(ArtifactRejection(file=name, reason=report.split("; rule=", 1)[0],
                                                          first_failing_rule=rule))
                    semantics.update({"coverage_status": "COMPLETE" if not rejected else "PARTIAL",
                                      "expected_artifacts": SECLISTS_PATHS,
                                      "accepted_artifacts": accepted,
                                      "rejected_artifacts": tuple(rejected)})
                elif source_id == "NUCLEI_META":
                    expected = tuple(sorted(path.relative_to(raw).as_posix() for path in raw.rglob("*.yaml")))
                    accepted = tuple(record.source_record for record in records)
                    rejected = []
                    for report in reports:
                        if not report.startswith("rejected Nuclei metadata: "):
                            continue
                        detail = report.removeprefix("rejected Nuclei metadata: ")
                        name, _, rule = detail.partition("; rule=")
                        rejected.append(ArtifactRejection(file=name, reason="invalid approved metadata",
                                                          first_failing_rule=rule or "INVALID_METADATA_SCHEMA"))
                    semantics.update({"coverage_status": "COMPLETE" if not rejected else "PARTIAL",
                                      "expected_artifacts": expected, "accepted_artifacts": accepted,
                                      "rejected_artifacts": tuple(rejected)})
                result = manifest.model_copy(update={"record_count": len(records), "reports": tuple(reports),
                                                      "normalized_sha256": sha256_file(path),
                                                      "status": IngestionStatus.STAGED, **semantics})
                self.store.save_manifest(result)
                return result
            except Exception as error:
                return self._quarantine(manifest, error)

    def _validate(self, spec, manifest):
        raw = self._verify_raw(manifest)
        records = self.store.records(spec.source_id, manifest.snapshot_id)
        if len(records) != manifest.record_count:
            raise ValueError("record count mismatch")
        acceptance(records, manifest, self.store.root, spec)
        owners = {manifest.snapshot_id: manifest}
        for record in records:
            if record.snapshot_id not in owners:
                owners[record.snapshot_id] = self.store.manifest(spec.source_id, record.snapshot_id)
                self._verify_raw(owners[record.snapshot_id])
            owner = owners[record.snapshot_id]
            if record.snapshot_id != manifest.snapshot_id and (spec.source_id != "NVD_CPE" or owner.status != IngestionStatus.PROMOTED):
                raise ValueError("record provenance references an unapproved snapshot")
            if (record.source_url, record.source_version, record.source_commit, record.retrieved_at) != (
                    owner.source_url, owner.source_version, owner.source_commit, owner.retrieved_at):
                raise ValueError("record provenance differs from snapshot manifest")
            origin = record.source_record.split("#")[0].split(":")[0]
            if origin not in owner.artifact_sha256:
                raise ValueError("record provenance has no raw artifact")
        # Recompile raw content at the trust boundary; seals alone do not certify an injected normalized record.
        expected = normalize(raw, manifest, spec, self.store.root, [])
        if manifest.base_snapshot_id:
            combined = {item.record_id: item for item in self.store.records(spec.source_id, manifest.base_snapshot_id)}
            combined.update({item.record_id: item for item in expected})
            expected = list(combined.values())
        expected = list({item.model_dump_json(): item for item in expected}.values())
        if [item.model_dump(mode="json") for item in expected] != [item.model_dump(mode="json") for item in records]:
            raise ValueError("normalized records differ from raw adapter projection")
        return records, acceptance(records, manifest, self.store.root, spec)

    def validate(self, source_id):
        with self.store.lock(source_id):
            spec, manifest = self._staged(source_id)
            if manifest.status not in {IngestionStatus.STAGED, IngestionStatus.READY, IngestionStatus.PROMOTED}:
                raise ValueError("snapshot must normalize successfully before validation")
            try:
                _, report = self._validate(spec, manifest)
                atomic_write(self.store.path("normalized", source_id, manifest.snapshot_id, "acceptance.json"), json_bytes(report))
                result = manifest.model_copy(update={"status": IngestionStatus.READY,
                                                     "final_validation_errors": ()}) if manifest.status != IngestionStatus.PROMOTED else manifest
                self.store.save_manifest(result)
                return result
            except Exception as error:
                return self._quarantine(manifest, error)

    @staticmethod
    def _identity(record):
        return getattr(record, "knowledge_id", getattr(record, "record_id", getattr(record, "runner_data_id", None)))

    def diff(self, source_id):
        with self.store.lock(source_id):
            spec, manifest = self._staged(source_id)
            if manifest.status not in {IngestionStatus.READY, IngestionStatus.PROMOTED}:
                raise ValueError("diff requires READY snapshot")
            records, _ = self._validate(spec, manifest)
            current = self.store.pointer(source_id, "CURRENT")
            before = {self._identity(item): item.model_dump(mode="json") for item in self.store.current_records(source_id)}
            after = {self._identity(item): item.model_dump(mode="json") for item in records}
            def semantic(value):
                return {key: item for key, item in value.items() if key not in {
                    "retrieved_at", "snapshot_id", "source_version", "source_commit", "local_path"}}
            result = {"source_id": source_id, "current_snapshot_id": current, "staged_snapshot_id": manifest.snapshot_id,
                "normalized_sha256": manifest.normalized_sha256, "added": sorted(after.keys() - before.keys()),
                "removed": sorted(before.keys() - after.keys()),
                "changed": sorted(key for key in before.keys() & after.keys() if semantic(before[key]) != semantic(after[key]))}
            atomic_write(self.store.path("normalized", source_id, manifest.snapshot_id, "diff.json"), json_bytes(result))
            return result

    def promote(self, source_id):
        with self.store.lock(source_id):
            spec, manifest = self._staged(source_id)
            if manifest.status == IngestionStatus.PROMOTED and self.store.pointer(source_id, "CURRENT") == manifest.snapshot_id:
                return manifest
            if manifest.status != IngestionStatus.READY:
                raise ValueError("promotion requires READY")
            try:
                records, _ = self._validate(spec, manifest)
                diff = json.loads(self.store.path("normalized", source_id, manifest.snapshot_id, "diff.json").read_bytes())
                if (diff["normalized_sha256"] != manifest.normalized_sha256 or diff["staged_snapshot_id"] != manifest.snapshot_id
                        or diff["current_snapshot_id"] != self.store.pointer(source_id, "CURRENT")):
                    raise ValueError("diff is stale; review a new diff before promotion")
                if manifest.base_snapshot_id and manifest.base_snapshot_id != self.store.pointer(source_id, "CURRENT"):
                    raise ValueError("incremental base changed")
                area = {StorageClass.VECTOR_RAG: "vector_docs", StorageClass.STRUCTURED_LOOKUP: "lookup",
                        StorageClass.RUNNER_DATA: "runner_data"}[manifest.storage_class]
                content = b"".join(json_bytes(record.model_dump(mode="json")) for record in records)
                atomic_write(self.store.path(area, source_id, manifest.snapshot_id, "records.jsonl"), content)
                promoted = manifest.model_copy(update={"status": IngestionStatus.PROMOTED})
                self.store.save_manifest(promoted)
                self.store.set_pointer(source_id, "CURRENT", manifest.snapshot_id)
                return promoted
            except Exception as error:
                self._quarantine(manifest, error)
                raise

    def sync_all(self):
        results = {}
        for source_id, spec in self.registry.items():
            if not spec.enabled or (spec.license_review_required and spec.license_status != "APPROVED") or source_id == "ARJUN":
                continue
            try:
                self.sync(source_id)
                manifest = self.normalize(source_id)
                if manifest.status == IngestionStatus.STAGED:
                    manifest = self.validate(source_id)
                results[source_id] = manifest.status.value
            except Exception as error:
                results[source_id] = "FAILED: " + type(error).__name__ + ": " + str(error)[:200]
        return results
