# Recon Day 2: endpoint-discovery foundation

**Architecture frozen; shared Attack Surface contract v1.0. Runtime: Python 3.11.** Day 2 adds deterministic discovery rounds to the Day 1 execution boundary. Parsers only produce endpoint candidates. Every network request remains a typed `CapabilityRequest`, claimed and checked by `PolicyService` inside `ToolExecutionGateway` before an adapter executes it. `ReconAgent.run(task_id)` enables discovery when the stored task allows `HTTP_FETCH`.

## Run a scoped discovery task

```python
from datetime import UTC, datetime, timedelta

from src.recon.bootstrap import create_recon_agent
from src.recon.models import Capability, ReconTask, Scope
from src.recon.web_models import DiscoveryLimits

repository, agent = create_recon_agent("data/recon.db", "data/evidence")
repository.save_task(ReconTask(
    id="day2-local", run_id="local-run",
    scope=Scope(
        allowed_ips=("127.0.0.1",),
        allowed_ports=(8080,),
        capabilities=(Capability.HTTP_FETCH,),
        allowed_paths=("/",),
        allowed_methods=("GET", "HEAD"),
    ),
    expires_at=datetime.now(UTC) + timedelta(minutes=10),
    discovery_limits=DiscoveryLimits(max_rounds=8, max_requests=64),
))
result = agent.run("day2-local")
print(result.coverage)
```

The example requires an authorized HTTP server on that port. Default seeds are `/`, `/robots.txt`, `/sitemap.xml`, `/openapi.json`, and `/swagger.json` on each scoped IP/port. Set `ReconTask.discovery_seeds` to override those paths. The Day 1 scheme heuristic remains: HTTPS on 443/8443/9443, otherwise HTTP.

`allowed_paths` is empty by default, so adding the capability alone does not authorize any fetch. A prefix `/api` allows `/api` and `/api/...`, but not `/apix`. `/` explicitly permits every valid local path. Every attempted seed and candidate still passes the stored task's IP, port, path, method, capability and expiry checks.

## Multiple rounds and request identity

`recon_plans` stores each deterministic plan by its content hash. `ReconService.run(plan)` executes that plan through the gateway and rebuilds the task's aggregate result from persisted tool results. `recon_results` is now the latest task snapshot, rather than a cache that prevents later plans from executing.

Request IDs remain deterministic across rounds and restarts. An existing `ToolResult` is reused. An active claim remains pending; after its 120-second lease expires, recovery records a durable FAILED result without dispatching again. This avoids both indefinite orphan claims and duplicate execution when a crash might have happened after network dispatch. Discovery can finish parsing a persisted response after interruption without consuming another network request. Discovery rounds are sequential; atomic SQLite claims protect concurrent duplicate gateway calls.

## Bounded HTTP_FETCH

- Only GET and HEAD are accepted. The model has no body, arbitrary headers, credentials, shell command or redirect option.
- HTTPX uses a literal IP, disables environment proxies and automatic redirects, and keeps normal TLS verification.
- Network-operation timeouts default to 5 seconds and cannot exceed 10 seconds. The body stream also checks elapsed time after each received chunk.
- At most 128 KiB of body is retained. Truncated or compressed responses are not parsed or baselined; compressed content is rejected even if the server ignores `Accept-Encoding: identity`.
- Gateway evidence is a JSON envelope containing the request URL/method, response metadata, a bounded Location header, and base64 body bytes. It stays within the existing 256 KiB evidence limit. Body and artifact SHA-256 values are checked before discovery consumes the response.

## Parsers and endpoint identity

| Source | Supported extraction |
|---|---|
| HTML | Links, script URLs, simple inline JavaScript, form actions/methods and named controls. All forms require manual input, including GET forms. |
| robots.txt | Concrete Allow/Disallow paths and Sitemap directives. Wildcard rules are not expanded. |
| sitemap XML | Namespaced or plain `urlset` and `sitemapindex`, with bounded traversal and cycle deduplication. DTDs and entities are rejected. |
| OpenAPI 3 / Swagger 2 | JSON or YAML paths, operation methods, path/operation parameters, local parameter/schema references, server/base paths and request-body presence. External references are never fetched; unresolved parameters and authenticated operations require manual input. YAML aliases are rejected. |
| JavaScript | Literal `fetch`, `axios.<method>` and XHR `.open` candidates. Dynamic expressions are not evaluated; uncertain fetch options require manual input. |

The API parser follows the parameter and server structures in the [OpenAPI 3 specification](https://spec.openapis.org/oas/v3.0.3.html) and [Swagger 2 specification](https://spec.openapis.org/oas/v2.0.html). It intentionally handles a bounded subset, including no browser execution or remote reference resolution.

Route identity is `(task_id, method, canonical origin/path)`, excluding query and fragment. `/search?q=a` and `/search?q=b` create one route and two `EndpointObservation` records. Observations retain full concrete URLs, including query values, order and repeated keys. A repeated identical URL merges provenance into the same observation. Different methods/origins, path case and trailing slashes remain distinct. Normalization canonicalizes literal IPs/default ports and unreserved escapes. Off-origin URLs, credentials, traversal, ambiguous separators and control characters are rejected. Parameters merge by `(location, name)`; required stays required when sources disagree.

OpenAPI/Swagger can declare a whole-segment path template. A unique exact-origin/method match joins `/users/1` and `/users/2` to `/users/{id}` after the current discovery queue is processed. The template itself is a route, not a fabricated concrete observation. Concrete URLs and baseline evidence stay on their observations. Ambiguous template matches remain separate routes. Unsupported partial templates remain inventory only. There is no numeric or UUID guessing: `/version/v1` and `/version/v2` remain distinct without a declared template. [ADR 0002](adr/0002-day02-execution-and-route-contracts.md) records the identity rule.

## Lifecycle and baselines

| State | Deterministic rule |
|---|---|
| `DISCOVERED` | A seed or parser candidate exists. Source evidence and provenance do not by themselves prove the endpoint responded. |
| `OBSERVED` | Its own scoped fetch produced response metadata and verified evidence. Redirects, 4xx/5xx and truncated responses remain at this state. |
| `BASELINED` | An eligible GET/HEAD returned a complete 2xx response with verified evidence; a `BaselineRequest` records its exact URL/method, request ID, timestamp, status, content type, size and body hash. |
| `FUZZ_READY` | The route is in scope, has a verified baseline and valid evidence, has no unresolved required input, and is testable. Query parameters are optional. This state performs no fuzzing. |

POST/PUT/PATCH/DELETE and all forms are inventory only. Required header/cookie/body inputs, unresolved path templates and missing required query values are never invented. A parameterless `GET /profile` with a verified complete 2xx baseline can become FUZZ_READY. Optional absent query/header parameters do not block readiness. Newly merged restrictions or invalid evidence can revoke readiness while preserving the historical baseline. Baselines refer to a specific observation and exact request URL; query variants cannot silently change that reference.

SQLite stores routes, `endpoint_observations`, sources, baselines, coverage, ToolRun, execution reservations, policy audit and evidence manifests. `src/storage/migrations.py` owns versioned transactional migrations, including upgrades from unversioned databases. Original results, plans, evidence bytes and provenance are retained; derived snapshots are rebuilt and readiness reverified.

## Coverage and stopping

Default limits are 8 rounds, 64 request attempts, 128 sources, 256 endpoint identities and depth 3. The planner schedules at most 16 pending sources per round. Each parser emits at most 256 candidates per document. Limits are stored on the task and have hard model maxima.

`ReconTask.execution_budget` independently caps all adapter attempts (default 128), rate (default 100 requests per second), timeout and HTTP body size. The Gateway checks these and the HTTP_FETCH request quota even when a caller bypasses the discovery planner. Reservation and final policy persistence are atomic before adapter dispatch; reservations survive restart. Rate denial is durable for that request ID, without automatic retry. The fetch planner reduces its requested timeout/body limits to fit the trusted task. Source/route/depth/round limits remain discovery orchestration bounds; direct Gateway calls do not parse or add routes/sources.

Authorization uses `action_fingerprint` separately from the idempotent request ID. The digest binds run/task, literal target IP, capability, typed parameters, scope version, policy version and the trusted stored task fingerprint. Supplied mismatches are denied before adapter dispatch. Recon classifies bounded HTTP/WhatWeb as R0 and Nmap as R1 using shared `Risk` R0–R4; it still only emits ALLOW/DENY. Legacy Recon callers without binding metadata are filled from the stored task at the Gateway. Historical decisions without this digest retain an empty action fingerprint after migration, rather than gaining a fabricated approval binding.

Source status is `PENDING`, `PARSED`, `UNAVAILABLE`, `BLOCKED`, `ERROR`, or `LIMITED`. Missing resources and redirects are recorded as UNAVAILABLE; denied calls are BLOCKED; malformed documents or invalid evidence are ERROR. Resource limits record LIMITED or a coverage stop reason and never claim convergence.

`ReconCoverage` distinguishes `route_count`, `observation_count`, `source_count`, verified `baseline_count`, `fuzz_ready_count`, `runtime_attempts`, requests, rounds, source statuses and lifecycle counts. `converged` means the supported discovery queue is exhausted without a resource-limit stop. `complete` also requires no blocked, failed or limited sources. These fields describe the attempted source set, not exhaustive application coverage or proof that an application is secure.

## Shared product handoff v1.0

```python
# Recon producer
inventory_json = result.attack_surface_inventory.model_dump_json()

# Supervisor/Fuzz consumer: imports only shared contracts
from src.contracts.attack_surface import AttackSurfaceInventory, EndpointStatus

inventory = AttackSurfaceInventory.model_validate_json(inventory_json)
ready_routes = [entry for entry in inventory.entries if entry.status == EndpointStatus.FUZZ_READY]
```

The schema is frozen in [attack-surface-v1.schema.json](../tests/fixtures/attack-surface-v1.schema.json). A compatibility test detects shape changes. Changes to field semantics require an explicit contract version and a reviewed migration. Internal Recon records can evolve without a downstream import from `src.recon`.

| Field | Meaning |
|---|---|
| `id`, `run_id`, `target_id` | Stable route ID within a task; run reference; deterministic target reference from run + origin. Product target-ID mapping is an integration responsibility. |
| `scheme`, `authority`, `resolved_ip`, `method`, `canonical_path`, `route_template` | Origin/route identity; concrete query/path values stay on observations. `route_template` equals the canonical path only for declared templates, otherwise null. Current execution targets are literal IPs. |
| `parameters`, `observations` | Merged input schema and distinct concrete URLs with response/provenance refs. |
| `baseline_ref`, `baseline_observation_ref` | Selected durable baseline and the exact verified observation it used. |
| `evidence_refs`, `provenance` | Every exported route traces to an observation, source request and verified evidence. An unexecuted candidate uses its source document's request/evidence; `Observation.request_ref` describes its own verified fetch, if any. |
| `auth_context_ref` | Reserved; currently null because authenticated/manual operations are not submitted. |
| `status`, readiness flags | Current scope, verified baseline/evidence, required-input completeness and testability. |

`EvidenceManifest` is also shared, with run/task/request/tool-run correlation, kind, SHA-256, byte size, content type, capture time, metadata and redaction classification. Current captures are `UNREVIEWED`. Product integration must provide resolvers for baseline/evidence references and recheck authorization at its own execution boundary. A serialized inventory is an observation snapshot, not permission to execute.

The current engine has no Product API/Supervisor wiring. The trusted operator layer stores a task, invokes `ReconAgent.run(task_id)`, then delivers this DTO. Nmap/WhatWeb are usable only when their binaries are detected; `available_capabilities()` reports the actual registry.

## Integration gates and deferred scope

The real fixture uses `127.0.0.1:port`. Hostname/VHost dispatch remains a P1 follow-up for that lab and a P0 integration gate for any domain-based lab: trusted authority, pinned resolved IP/port, Host/TLS SNI and certificate verification must be designed together. Arbitrary agent-supplied Host values remain forbidden. Output DTOs already separate authority from resolved IP; this does not imply hostname transport support.

Python stays **3.11** across this implementation, CI and Docker ([ADR 0001](adr/0001-mvp-python-runtime.md)). Browser/CDP, LLM planning, CVE/RAG, fuzzing/validation, payload/checker selection, findings, HITL UI and reports are outside Day 2. The [Browser execution boundary](adr/0003-browser-execution-boundary.md) is frozen before Day 03: every browser-generated network request must pass a gateway-controlled policy decision and evidence path. Durable cancellation is an implementation gate with the Browser adapter. Domain-based labs retain the trusted authority/IP/SNI integration gate.

## Verification

`tests/integration/test_recon_discovery_e2e.py` starts a real HTTP server on `127.0.0.1` with HTML, robots, a sitemap index, OpenAPI and JavaScript. It checks multi-round discovery, merged provenance, query observation deduplication, parameterless readiness, evidence correlation, no form/write-method submissions, no redirect following, restart replay without extra HTTP, and bounded termination. Unit tests cover BASELINED routes with unresolved required input, evidence revocation, shared-contract isolation/schema, legacy migration, ToolRun recovery, policy persistence, concurrent budget reservation, rate limits and capability availability. Day 1 tests continue in the same suite.

```powershell
.\.venv\Scripts\python.exe -B -m ruff check --no-cache src tests
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests -q
```
