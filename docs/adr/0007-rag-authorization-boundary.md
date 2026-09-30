# ADR 0007: Retrieval is planning knowledge, not execution authority

Status: Accepted for Recon V2.

`KnowledgeRetriever` receives only bounded structured checklist gaps, asset types,
verified technology and service names, route categories and limitations. The
default implementation returns no chunks; an in-memory retriever supports tests.
Real KB ingestion and vector databases are deferred.

Planning rounds persist bounded query and source/hash references. Retrieved text is
untrusted context. A proposal's `knowledge_refs` are audit references only. The
Proposal Validator still resolves trusted asset identity and PolicyService and
ToolExecutionGateway remain the sole path to network or process adapters. Knowledge
is never Evidence; controlled Recon execution creates Evidence.
