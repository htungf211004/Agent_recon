"""Immutable raw/record snapshots and atomic STAGED/CURRENT pointers, outside Run evidence."""

import json
import os
from contextlib import contextmanager
from pathlib import Path

from src.contracts.recon_kb import RECORD_MODELS, IngestionStatus, SourceManifest
from src.recon.kb.utils import atomic_write, contained, json_bytes, sha256_file


class KBSnapshotStore:
    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()

    def path(self, area, source_id, snapshot_id, filename=None):
        relative = "/".join(part for part in (area, source_id, snapshot_id, filename) if part)
        return contained(self.root, relative)

    @contextmanager
    def lock(self, source_id):
        path = self.path("manifests", source_id, "update.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise ValueError("dataset update already in progress; stale locks require operator review") from None
        try:
            os.close(descriptor)
            yield
        finally:
            path.unlink()

    def save_manifest(self, manifest):
        atomic_write(self.path("manifests", manifest.source_id, manifest.snapshot_id + ".json"),
                     json_bytes(manifest.model_dump(mode="json")))

    def manifest(self, source_id, snapshot_id):
        return SourceManifest.model_validate_json(self.path("manifests", source_id, snapshot_id + ".json").read_bytes())

    def pointer(self, source_id, name):
        path = self.path("manifests", source_id, name + ".json")
        return json.loads(path.read_bytes())["snapshot_id"] if path.exists() else None

    def set_pointer(self, source_id, name, snapshot_id):
        if name not in {"CURRENT", "STAGED"}:
            raise ValueError("invalid dataset pointer")
        atomic_write(self.path("manifests", source_id, name + ".json"), json_bytes({"snapshot_id": snapshot_id}))

    def records(self, source_id, snapshot_id):
        manifest = self.manifest(source_id, snapshot_id)
        path = self.path("normalized", source_id, snapshot_id, "records.jsonl")
        if not manifest.normalized_sha256 or sha256_file(path) != manifest.normalized_sha256:
            raise ValueError("normalized snapshot digest mismatch")
        model = RECORD_MODELS[manifest.storage_class]
        return [model.model_validate_json(line) for line in path.read_bytes().splitlines() if line]

    def current_records(self, source_id):
        snapshot = self.pointer(source_id, "CURRENT")
        if snapshot is None:
            return []
        if self.manifest(source_id, snapshot).status != IngestionStatus.PROMOTED:
            raise ValueError("CURRENT must reference a promoted snapshot")
        return self.records(source_id, snapshot)
