# Recon Day 2: endpoint-discovery foundation

Day 2 adds deterministic discovery rounds to the Day 1 execution boundary. Parsers only produce endpoint candidates. Every network request remains a typed `CapabilityRequest`, claimed and checked by `PolicyService` inside `ToolExecutionGateway` before an adapter executes it. `ReconAgent.run(task_id)` enables discovery when the stored task allows `HTTP_FETCH`.

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

Request IDs remain deterministic across rounds and restarts. An existing `ToolResult` is reused; a claimed request without a result is never redispatched under a fresh ID. Discovery can finish parsing a persisted response after interruption without consuming another network request. Discovery rounds are sequential; the existing SQLite claim protects concurrent duplicate gateway calls.

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

Identity is `(task_id, method, canonical URL)`. Normalization canonicalizes literal IPs/default ports, removes fragments and normalizes unreserved escapes. It preserves path case, trailing slashes, query values, order and repeated query keys. Different methods or concrete query strings remain separate endpoints. Off-origin URLs, credentials, traversal, ambiguous separators and control characters are rejected. The same endpoint merges provenance and parameters by `(location, name)`; a required parameter stays required when sources disagree.

## Lifecycle and baselines

| State | Deterministic rule |
|---|---|
| `DISCOVERED` | A seed or parser candidate exists. Source evidence and provenance do not by themselves prove the endpoint responded. |
| `OBSERVED` | Its own scoped fetch produced response metadata and verified evidence. Redirects, 4xx/5xx and truncated responses remain at this state. |
| `BASELINED` | An eligible GET/HEAD returned a complete 2xx response with verified evidence; a `BaselineRequest` records its exact URL/method, request ID, timestamp, status, content type, size and body hash. |
| `FUZZ_READY` | A baseline exists, all inventoried parameters are concrete query inputs in that URL, required values are present, and there is no unresolved template or manual-input requirement. This state performs no fuzzing. |

POST/PUT/PATCH/DELETE and all forms are inventory only. Required header/cookie/body inputs, unresolved path templates and missing required query values are never invented. A parameterless successful endpoint is BASELINED. Newly merged restrictions can revoke FUZZ_READY while preserving the historical baseline.

SQLite stores `web_endpoints` (including parameters and merged provenance), `discovery_sources`, `baseline_requests`, and `recon_coverage`, alongside the Day 1 tables. `ReconResult.endpoints` and `.coverage` expose the current inventory and progress.

## Coverage and stopping

Default limits are 8 rounds, 64 request attempts, 128 sources, 256 endpoint identities and depth 3. The planner schedules at most 16 pending sources per round. Each parser emits at most 256 candidates per document. Limits are stored on the task and have hard model maxima.

Source status is `PENDING`, `PARSED`, `UNAVAILABLE`, `BLOCKED`, `ERROR`, or `LIMITED`. Missing resources and redirects are recorded as UNAVAILABLE; denied calls are BLOCKED; malformed documents or invalid evidence are ERROR. Resource limits record LIMITED or a coverage stop reason and never claim convergence.

`ReconCoverage` counts requests, rounds, sources by status, and endpoints by lifecycle. `converged` means the supported discovery queue is exhausted without a resource-limit stop. `complete` also requires no blocked, failed or limited sources. These fields describe the attempted source set, not exhaustive application coverage or proof that an application is secure.

## Verification

`tests/integration/test_recon_discovery_e2e.py` starts a real HTTP server on `127.0.0.1` with HTML, robots, a sitemap index, OpenAPI and JavaScript. It checks multi-round discovery, merged provenance, all four lifecycle states, evidence correlation, no form/write-method submissions, no redirect following, replay without extra HTTP, and bounded termination. Day 1 tests continue to run in the same suite.

```powershell
.\.venv\Scripts\python.exe -B -m ruff check --no-cache src tests
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests -q
```
