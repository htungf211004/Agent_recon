"""Read only promoted VECTOR_RAG snapshots, prefiltering before a bounded reference retrieval."""

import hashlib

from src.contracts.recon_kb import IngestionStatus, StorageClass
from src.recon.kb.utils import json_bytes
from src.recon.rag.models import KnowledgeChunk
from src.recon.rag.query_builder import GAP_CATEGORIES


class SnapshotKnowledgeRetriever:
    implementation_id = "recon-kb-snapshot-v1"

    def __init__(self, store, snapshots: dict[str, str]):
        self.manifests, self.records = [], []
        for source_id, snapshot_id in sorted(snapshots.items()):
            manifest = store.manifest(source_id, snapshot_id)
            if manifest.status != IngestionStatus.PROMOTED or manifest.storage_class != StorageClass.VECTOR_RAG:
                raise ValueError("retrieval accepts only promoted VECTOR_RAG snapshots")
            self.manifests.append(manifest)
            self.records.extend(store.records(source_id, snapshot_id))

    def bind_run(self, repository, run_id):
        for manifest in self.manifests:
            repository.pin_kb_snapshot(run_id, manifest)

    def retrieve(self, query, *, limit):
        if not 0 <= limit <= 8:
            raise ValueError("retrieval limit exceeded")
        if limit == 0:
            return ()
        records = [record for record in self.records
            if record.phase == query.phase and not record.active_testing and record.risk <= query.risk_ceiling
            and record.delivery != "MANUAL_HITL"
            and (not record.asset_types or bool(set(record.asset_types) & set(query.asset_types)))
            and (not record.technologies or bool(set(record.technologies) & set(query.verified_technologies)))
            and set(record.capabilities).issubset(query.available_capabilities)
            and (not query.categories or record.category in query.categories)]
        def rank(record):
            gap_hits = sum(record.category in GAP_CATEGORIES.get(gap, ()) for gap in query.checklist_gaps)
            category = int(record.category in query.categories)
            capability = len(set(record.capabilities) & set(query.available_capabilities))
            technology = len(set(record.technologies) & set(query.verified_technologies))
            asset = len(set(record.asset_types) & set(query.asset_types))
            route = sum(token in record.category for token in query.route_categories)
            return -(100 * category + 80 * gap_hits + 40 * capability + 30 * technology + 20 * asset + 10 * route)
        records.sort(key=lambda record: (rank(record), record.knowledge_id))
        chunks = []
        for record in records[:limit]:
            text = record.content.objective + " " + " ".join(record.content.safe_actions) + " " + record.content.completion_rule
            chunks.append(KnowledgeChunk(knowledge_id=record.knowledge_id, namespace=record.namespace,
                source_id=record.source_id, title=record.title, excerpt=text[:512],
                content_hash=hashlib.sha256(json_bytes(record.model_dump(mode="json"))).hexdigest(),
                version=record.source_version or record.source_commit, source_snapshot_id=record.snapshot_id,
                source_commit=record.source_commit,
                metadata={"phase": record.phase, "category": record.category, "risk": record.risk,
                          "active_testing": "false", "api_related": str(record.api_related).lower()}))
        return tuple(chunks)
