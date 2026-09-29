# ADR 0004: bounded adaptive Recon runtime

Status: implemented locally; publication and remote CI of this revision are separate.

Keep Python 3.11. Product planning has referenced 3.12, while the verified virtual
environment, Docker and CI use 3.11. A Python upgrade requires its own compatibility
gate; this task does not silently change it.

Keep Policy/Gateway, browser interception, ToolRun fences and ASI v1.0. Migration
v8 adds stage plans, safe model diagnostics and FFUF request units. Legacy
deterministic `run()` stays available; adaptive orchestrates sensing stages explicitly.

Planning schema intentionally changes: STOP is exclusive and contains no execution
fields. Planner fingerprint binds provider/model/version/prompt/schema, preventing
old sessions from resuming with different semantics. New planner sessions need a
new scoped task; old evidence and terminal requests remain auditable.

FFUF uses Debian 1.1.0-1+b8, fixed HEAD, packaged wordlists and a separate GET
baseline. A 0.5-second delay is used because that release has no `-rate` flag.
It reserves all candidate requests and excludes concurrent same-task dispatch.

Roles stay Operator/Approver. Use Validation Agent for the future active module.
RunStatus and Approval vocabularies remain unchanged. No Approval, Fuzzing,
Validation, Finding, CVE/RAG or Browser-Use subsystem is implemented here.
