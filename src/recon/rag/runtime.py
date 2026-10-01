"""Select immutable Recon KB snapshots for a live planning run."""

from src.contracts.recon_kb import StorageClass
from src.recon.kb.registry import load_registry
from src.recon.rag.retriever import NoopKnowledgeRetriever
from src.recon.rag.snapshot_retriever import SnapshotKnowledgeRetriever
from src.storage.recon_kb import KBSnapshotStore


def live_snapshot_retriever(repository, run_id: str, *, root="data/recon_kb", registry=None):
    """Use a run's existing bindings on resume, otherwise select promoted CURRENT snapshots."""
    store = KBSnapshotStore(root)
    bound = tuple(manifest for manifest in repository.kb_snapshots(run_id)
                  if manifest.storage_class == StorageClass.VECTOR_RAG)
    if bound:
        snapshots = {manifest.source_id: manifest.snapshot_id for manifest in bound}
    else:
        specs = registry if registry is not None else load_registry()
        snapshots = {}
        for source_id, spec in sorted(specs.items()):
            if not spec.enabled or spec.storage_class != StorageClass.VECTOR_RAG:
                continue
            snapshot_id = store.pointer(source_id, "CURRENT")
            if snapshot_id:
                snapshots[source_id] = snapshot_id
    return SnapshotKnowledgeRetriever(store, snapshots) if snapshots else NoopKnowledgeRetriever()
