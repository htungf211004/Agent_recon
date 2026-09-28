# Recon architecture — Day 03 Ver1

Runtime: **Python 3.11**, consistent with CI and Docker. Recon uses deterministic plans and parsers. The existing FastAPI/LangGraph starter is separate from the implemented Recon engine.

## Execution boundary

```mermaid
flowchart TD
    Task[Trusted ReconTask] --> Agent[ReconAgent]
    Agent --> Planner[ReconPlanner]
    Planner --> Plan[ReconPlan]
    Plan --> Service[ReconService]
    Service --> Gateway[ToolExecutionGateway]
    Gateway --> Existing{Stored ToolResult?}
    Existing -->|yes| Result[ReconResult]
    Existing -->|no| Claim[Atomic ToolRun claim and lease]
    Claim --> Policy[PolicyService: scope, method, expiry, budget]
    Policy --> Reserve[Atomic budget reservation and persisted PolicyDecision]
    Reserve -->|ALLOW| Registry[CapabilityRegistry]
    Reserve -->|DENY| Denied[Durable DENIED result]
    Registry --> Adapter[HTTP probe / HTTP fetch / Nmap / WhatWeb]
    Adapter --> Tool[Bounded HTTP or fixed tool invocation]
    Tool --> Evidence[EvidenceStore: SHA-256 and manifest]
    Evidence --> Repository[(ReconRepository / SQLite)]
    Repository --> Result
    Denied --> Repository
```

Policy runs **inside the Gateway after the atomic claim**, and its final decision is committed before any adapter executes. Agents propose typed `CapabilityRequest` objects. Parsers have no network access. There is no arbitrary shell command, HTTP header, Host override, write method or redirect-following field.

`HTTP_PROBE` and `HTTP_FETCH` are available in the standard Python runner. Nmap and WhatWeb are registered only when `shutil.which` finds their binaries. The Browser adapter is registered when the Playwright Python package is present; Chromium must also be installed for a navigation to run. `CapabilityRegistry.available_capabilities()` lists registered adapters; a missing adapter is denied before dispatch, while a missing Chromium executable produces a durable adapter error.

## Route, observation, baseline

| Record | Identity and responsibility |
|---|---|
| `WebEndpointEntry` | Task + method + canonical origin/path. Parameter schema and merged provenance. Query values never participate in the route ID. |
| `EndpointObservation` | Task + method + full canonical URL. Retains query order, repeated keys and values; discovered references can exist without fetching the endpoint. Holds its own request/response/evidence when fetched. |
| `BaselineRequest` | Route + request. Refers to the exact observation, concrete URL, complete 2xx response and evidence. |
| Shared `AttackSurfaceEntry` | Stable product handoff in `src/contracts/attack_surface.py`, with no import from Recon. Includes origin, parameters, observations, provenance, baseline/evidence refs and readiness. |

`/search?q=a` and `/search?q=b` produce one GET route and two observations. A unique OpenAPI template such as `/users/{id}` can also group concrete paths as observations. `route_template` is null for literal routes. Different methods, origins, case or trailing slashes remain distinct. The first selected baseline remains linked to its concrete observation when later sources merge. Historical baselines remain stored if readiness is revoked. See [ADR 0002](docs/adr/0002-day02-execution-and-route-contracts.md).

`FUZZ_READY` requires current scope, a verified baseline, valid evidence, resolved required inputs and a testable endpoint. A parameterless `GET /profile` with a verified 2xx baseline qualifies. Downstream testing selects inputs/checkers. Forms, authenticated/manual operations, write methods and unresolved required inputs are never automatically submitted by Recon.

Before exporting, `build_inventory` verifies artifact hashes, response metadata, request/observation/baseline links, policy and scope. Each exported route has a trace through provenance → observation → source request → evidence. A candidate discovered in a document may have no request of its own; its provenance references the request that fetched that document. Unevidenced seeds stay internal. Invalid evidence revokes readiness at snapshot/export time.

## Durable execution and budgets

`ToolRun` states are `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `DENIED`, `TIMED_OUT`, `CANCELLED`. The request ID is also the tool-run ID. The execution owner has a token, fingerprint, attempt number and 120-second lease. A completed request replays its stored result after restart. Reusing a known request ID with different content is rejected.

`action_fingerprint` is separate from request ID. It binds run, task, exact IP target, capability, typed parameters and trusted task/policy context. The Gateway binds legacy Recon callers to stored task metadata; supplied conflicting metadata is denied. `PolicyDecision` stores action/scope/policy fingerprints and typed `Risk` R0–R4. See [ADR 0002](docs/adr/0002-day02-execution-and-route-contracts.md).

Active duplicate calls return an incomplete response without dispatch. Expired QUEUED/RUNNING requests become **durable FAILED** on recovery, Gateway entry or discovery resume. An expired lease cannot prove that the original worker never reached the network, so this version never reclaims or automatically retries the same request. Late owner results cannot overwrite the failure. Attempt remains 1. Recovery uses the original stored request; migrated orphan claims also terminate as FAILED. Call `recover_expired_runs(task_id)` when resuming a task; no background sweeper is installed.

The Gateway atomically reserves request/rate budgets with the final policy decision and transition to RUNNING. Limits belong to the stored task, not to caller-supplied counters. Reservations survive crashes/restarts and are never refunded. Direct Gateway calls receive the same checks as discovery plans:

- Total adapter attempts: default 128, hard maximum 1024.
- Sliding one-second rate: default 100, hard maximum 1000 requests.
- HTTP_FETCH attempts: also capped by `DiscoveryLimits.max_requests` (default 64).
- Capability timeout and HTTP body limits must fit `ExecutionBudget`; HTTP_FETCH also has fixed maxima of 10 seconds per network operation and 128 KiB retained body.

Denied calls consume no dispatch reservation. `PolicyDecision` exposes ALLOW/DENY/REQUIRE_APPROVAL, version, fingerprint, reason, risk and attempt; Recon produces only ALLOW/DENY. `budget_context` identifies the trusted task and cannot override its limits. Coverage exposes runtime attempts; durable decisions explain budget/rate denials.

## Persistence and evidence

`src/storage/migrations.py` is the single SQLite schema authority. Ordered migrations run under `BEGIN IMMEDIATE`, record versions in `schema_migrations`, and roll back on failure. Unknown future schemas are rejected.

Stop existing Recon workers before upgrading the database; running old and new worker versions against the same database during this schema transition is unsupported.

1. Adopt existing Day-1/Day-2 tables, including unversioned databases.
2. Split concrete observations from routes, merge old query variants, migrate baseline refs.
3. Add ToolRun, policy audit, durable budget reservations and evidence manifest fields.
4. Bind historical ToolRun payloads for replay and normalize legacy risk without inventing historical approval fingerprints.
5. Mark declared path templates and discard historical placeholder observations that were never concrete requests.

Task, plan, source, result, policy and evidence history is preserved. Only derived Recon snapshots/coverage are invalidated during the route migration. Old readiness is reverified from original evidence on the next snapshot. Evidence bytes and their SHA-256 values are unchanged.

The shared `EvidenceManifest` records run/task/request/tool-run, kind, hash, byte size, content type, capture time, redaction status and metadata. `EvidenceArtifact` adds the local relative path. New captures are `UNREVIEWED`; this is a classification, not a claim that redaction was performed. HTTP evidence is an envelope with URL/method, response metadata and bounded body; both artifact and body digests are checked.

## Discovery, coverage and integration

HTML, robots, sitemap/index, OpenAPI/Swagger and simple JavaScript parsers feed deterministic discovery rounds through the same boundary. Coverage reports route, observation, source, verified baseline and FUZZ_READY counts separately, plus source statuses, rounds and runtime attempts. Convergence describes the supported discovery queue; it does not prove exhaustive application coverage.

Product API/Supervisor integration is a later step. Its input is a trusted stored `ReconTask`; execution is `ReconAgent.run(task_id)`; handoff is `ReconResult.attack_surface_inventory` serialized as shared **AttackSurfaceInventory v1.0**. Consumers import `src.contracts`, not Recon internals. [Contract and integration guide](docs/day2-endpoint-discovery.md) defines refs and versioning; [schema fixture](tests/fixtures/attack-surface-v1.schema.json) guards the freeze.

The passive Browser path implements [ADR 0003](docs/adr/0003-browser-execution-boundary.md): navigation and every child resource pass the Gateway/Policy boundary before network continuation. The Python 3.11 choice is recorded in [ADR 0001](docs/adr/0001-mvp-python-runtime.md).

**Hostname/VHost integration gate:** the implemented lab uses literal IPs, including localhost E2E. `authority` and `resolved_ip` are separate output fields, but hostname dispatch is not implemented. Before a hostname-based staging lab, trusted target configuration must pin authority, resolved IP and port, and preserve Host/TLS SNI with certificate verification. Agents must never supply arbitrary Host values. This is a P1 follow-up for the current IP lab and a P0 integration blocker if the product lab requires domains.

Browser-Use, CVE/RAG, fuzzing, validation, payload selection, findings, HITL UI and reports remain outside this implementation. Future observation sources must retain the same Policy/Gateway boundary.

## Verification

Run `python -B -m ruff check --no-cache src tests` and `python -B -m pytest -p no:cacheprovider tests -q`. Tests include all Day-1 behaviors, a real localhost multi-source fixture, route/observation merge, evidence revocation, shared schema, legacy migration, restart/lease recovery, concurrent budget reservation and registry availability. GitHub Actions uses Python 3.11 on Ubuntu; remote CI status requires a pushed run.

Day 03 verification includes parent/child authorization, a one-use external continuation permit, cancellation fencing, and a real localhost Chromium fixture. Run the Chromium test where its binary is installed; CI skips that one test when Chromium is unavailable.

## Day 03 Ver1 passive browser extension

`BROWSER_EXPLORE` is a bounded parent ToolRun. Its Playwright adapter creates a fresh non-persistent Chromium context with service workers blocked and downloads disabled. It installs HTTP and WebSocket interception before navigation. No clicks, forms, Agent JavaScript, persistent browser profile or browser-driven write action is available.

For each intercepted GET/HEAD URL, the adapter derives a deterministic child `BROWSER_REQUEST` ID from the parent ID, method and canonical literal-IP URL. It calls `begin_external_dispatch()` to claim the child, persist policy and reserve budget. It consumes `authorize_external_continuation()` once before `route.continue_()`. `finish_external_dispatch()` stores a response-header evidence envelope and the child ToolResult. It never issues a parallel `HTTP_FETCH` for that request. A duplicate child ID cannot get a second continuation permit. The repository also verifies the parent's origin and dispatch count inside the transaction.

Parent and child ToolRuns contain `parent_request_id`; evidence metadata and ToolResults retain the same correlation. `cancel_tool_run()` atomically writes terminal `CANCELLED` results for a live parent and its children. Later callbacks receive the stored cancellation result. Browser child observations enter the existing `WebEndpointEntry` and `AttackSurfaceInventory` path; they are observed routes and do not become baselines or `FUZZ_READY` without the Day 2 baseline rules.

Browser evidence retains response metadata and an empty body, marked truncated for nonempty GET bodies. Attachment responses are rejected after their headers arrive, and no download artifact is accepted. This caps evidence storage, while navigation timeout caps time spent waiting for responses. Playwright continuation does not provide a hard byte cap on the network transfer itself; a response that omits or falsifies `Content-Length` can transfer more than the configured evidence limit before the context closes. Browser Ver1 therefore remains restricted to the literal-IP lab and short time limits.
