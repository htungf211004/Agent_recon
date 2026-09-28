# ADR 0002: Execution binding and route templates

Status: accepted for the final Day 02 contract freeze.

## Action identity and risk

`request_id` identifies one attempted execution. A second call with the same request ID replays the stored result, and reuse with different content fails. `action_fingerprint` is a separate SHA-256 authorization identity. Different request IDs for identical actions can share an action fingerprint and still consume separate budgets.

The canonical fingerprint covers **run ID, task ID, literal target IP, capability, complete typed parameters, scope version, policy version and a digest of the trusted stored task**. The stored task digest includes scope, expiry, discovery limits and execution budget. Runtime counters are not part of it. The Gateway binds omitted legacy Recon metadata from the stored task before claiming, persists that bound request in `ToolRun`, and the policy rejects supplied run/scope/fingerprint values that disagree with the trusted computation. `PolicyDecision` persists the action fingerprint, scope version, policy version and task-policy fingerprint before adapter dispatch. No requester can authorize itself by choosing a fingerprint.

`Risk` is a shared enum R0–R4. Recon assigns R0 to bounded HTTP and WhatWeb reads and R1 to bounded Nmap service scans. Recon still produces ALLOW or DENY only. R2–R4 and REQUIRE_APPROVAL are reserved for later policy design; this ADR does not grant new capabilities. Prior decisions retain their historical policy version; migration labels their missing action fingerprint as empty instead of fabricating an approval binding. Existing completed request IDs still replay.

`target_ip` is the typed target for current IP-only Recon; `CapabilityRequest.target` exposes the same value. Domain authority is a separate trusted-target integration gate. Product actions that introduce a target object must bind every authority/resolved-IP field into their fingerprint before dispatch.

## Path identity

Concrete query values are observations. A known OpenAPI/Swagger route with a whole-segment placeholder, such as `/users/{id}`, may also absorb `/users/1` and `/users/2` as observations. Matching requires the **same canonical origin, method, segment count and every literal segment**. The known template must be the unique match after the current deterministic discovery queue is processed. Unmatched or ambiguous paths stay separate. Numbers, UUID shapes and version-looking segments are never generalized by appearance.

`AttackSurfaceEntry.canonical_path` holds the exact route identity; `route_template` is the same path when that identity came from a declared template, otherwise null. A template string is not a concrete observation. API-only templates stay in the internal route inventory until a concrete evidenced observation supports the shared handoff. The selected baseline retains its concrete URL and observation ID. In the shared DTO, a concrete observation can therefore have a different path from `canonical_path` without losing its proof chain.

The AttackSurfaceInventory v1.0 schema fixture is amended in this final Day 02 pass, before downstream consumers are wired. Future incompatible changes require an explicit version. A Browser observation may attach to an existing **unique** template only after its network execution passes the Gateway and produces valid evidence. If later metadata creates ambiguous templates, integration must stop automatic association and resolve the conflict conservatively before downstream use.

## Migration

SQLite migration v4 updates stored ToolRun payload fingerprints for replay and converts legacy free-text risk values to R0. Migration v5 marks known OpenAPI templates and removes old placeholder observations that had no direct request. It does not repeat network calls or claim that old policy decisions carried an action fingerprint. Stop old workers before upgrading; mixed worker versions are unsupported during migration.
