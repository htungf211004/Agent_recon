# ADR 0006: Root authorization and derived execution bindings

Status: Accepted for Recon V2.

The Operator submits one authorized domain or IP root. The root identity is
immutable and persisted separately from the legacy concrete `Scope`. Bounded DNS
answers are observations. A request executes only against a concrete persisted
hostname, IP, scheme and port binding after PolicyService and ToolExecutionGateway
check the current task, scope version, capability, path and action fingerprint.

The pure `ScopeDeriver` uses exact host equality or a dot-delimited descendant
suffix for domain roots. An external reference remains in `ReconAssetInventory`
with OUT_OF_SCOPE status and cannot trigger dispatch. For IP roots, a different
hostname requires matching verified DNS evidence and configured admission policy.

New descendant DNS observation is a typed Gateway action. Its Evidence backs a
persisted transport pin. Adding the pin changes `scope_version`; prior ToolRuns and
Evidence are not rewritten. Resumed work uses the saved pin, preserving auditability.

The retriever and LLM may rank typed actions for existing assets. Neither can add
roots, bindings or permissions. Active API security tests remain manual/HITL.
