"""Retrieval never dispatches Recon actions or grants scope."""

from __future__ import annotations

from typing import Protocol

from src.recon.rag.models import KnowledgeChunk, ReconKnowledgeQuery


class KnowledgeRetriever(Protocol):
    implementation_id: str

    def retrieve(self, query: ReconKnowledgeQuery, *, limit: int) -> tuple[KnowledgeChunk, ...]: ...


class NoopKnowledgeRetriever:
    implementation_id = "noop-v1"

    def retrieve(self, query: ReconKnowledgeQuery, *, limit: int) -> tuple[KnowledgeChunk, ...]:
        return ()


class InMemoryKnowledgeRetriever:
    implementation_id = "in-memory-test-v1"

    def __init__(self, chunks: tuple[KnowledgeChunk, ...]):
        self.chunks = chunks

    def retrieve(self, query: ReconKnowledgeQuery, *, limit: int) -> tuple[KnowledgeChunk, ...]:
        if not 0 <= limit <= 8:
            raise ValueError("retrieval limit exceeded")
        return self.chunks[:limit]
