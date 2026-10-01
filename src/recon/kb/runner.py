"""Resolve a pinned operator catalog by ID, never by an agent path or payload."""

from src.contracts.recon_kb import IngestionStatus, RunnerDataManifest, StorageClass
from src.recon.kb.adapters import sanitize_wordlist
from src.recon.kb.utils import contained, sha256_file
from src.recon.models import TechnologyObservation
from src.recon.wordlists import TrustedWordlist


class RunnerDataResolver:
    def __init__(self, store, source_id, snapshot_id):
        self.store = store
        self.manifest = store.manifest(source_id, snapshot_id)
        if self.manifest.status != IngestionStatus.PROMOTED or self.manifest.storage_class != StorageClass.RUNNER_DATA:
            raise ValueError("runner resolver requires promoted RUNNER_DATA snapshot")
        self.catalog = {record.runner_data_id: record for record in store.records(source_id, snapshot_id)
                        if isinstance(record, RunnerDataManifest)}

    def resolve(self, runner_data_id, *, technologies: tuple[TechnologyObservation, ...] = (), automatic=False):
        if runner_data_id not in self.catalog:
            raise ValueError("unknown packaged runner_data_id; arbitrary paths are forbidden")
        record = self.catalog[runner_data_id]
        if automatic and not record.constraints.automatic_execution:
            raise ValueError("ingested datasets require explicit operator selection through existing policy")
        if record.constraints.technology_required and not any(
                isinstance(item, TechnologyObservation) and item.evidence_id and
                item.name.casefold() == record.constraints.technology_required.casefold() for item in technologies):
            raise ValueError("technology-aware dataset requires matching TechnologyObservation evidence")
        path = contained(self.store.root, record.local_path)
        if sha256_file(path) != record.sha256:
            raise ValueError("runner wordlist hash mismatch")
        content = path.read_bytes()
        if sanitize_wordlist(content) != content or len(content.splitlines()) != record.line_count:
            raise ValueError("runner wordlist normalization mismatch")
        return TrustedWordlist(record.runner_data_id, path, record.snapshot_id, record.sha256, record.line_count,
                               "api" if record.constraints.api_related else "web", "content_discovery",
                               tuple(content.decode().splitlines()))
