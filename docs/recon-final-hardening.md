# Recon final hardening verification

Base commit: `235c239bcfeb81fc4b05a05e479d6d7f0945cdff` (Day03 Ver02).

The frozen execution boundary, shared AttackSurfaceInventory v1.0 and locked RunStatus enum are unchanged. This work implements the seven requested hardening fixes.

## Changes and focused tests

| Fix | Behavior and files | Verification |
|---|---|---|
| 1 | `browser_dom.py` projects only `document`, `xhr`, `fetch`. Asset ToolRuns, decisions and evidence remain stored. | `test_asset_evidence_retained_without_inventory_projection` tests script/CSS/image/font/manifest duplicates and application observations. Real Chromium asset fixture verifies request counts, policy, evidence and ASI exclusion. |
| 2 | `browser.py` derives versioned child IDs from parent/page/method/URL/resource type. `browser_response.py` correlates Network IDs/resource types to Fetch response pauses. Stored legacy IDs/payloads are unchanged. | Same-page script/fetch URL has distinct IDs/fingerprints, two real requests and one application route. Parametrized legacy page-zero/page-one tests replay completed Ver01/Ver02 children without another dispatch. |
| 3 | `browser_discovery.py` falls back to `/`. `urls.py` defines empty prefixes as all validated paths on the authorized target; explicit path/IP/port/method restrictions remain. | Empty-seed/empty-prefix Agent starts at `/`, projects evidence and replays without more traffic. Explicit prefixes and invalid traversal still deny. |
| 4 | `web_models.py` and `service.py` expose browser configuration/availability/runs/completion/reasons/limitations and preserve static convergence separately. Aggregate completion cannot hide a configured browser limit/error. | Eight convergence/limit/error cases, unavailable/unconfigured cases, repeated snapshot/replay checks and real BFS request/depth/page/byte limit assertions. |
| 5 | `Dockerfile` installs Chromium/system dependencies, uses `/opt/venv` and `/ms-playwright`, and executes as `appuser`. CI adds Docker build, probe, non-root and default FastAPI health gates. | Actual Docker build, browser probe, UID and FastAPI health smoke passed locally. Structural Docker/CI assertions are in pytest. |
| 6 | `requirements.txt` pins Playwright to the installed and verified `1.63.0`; CI and Docker install the same requirements. | Installed-version test and container version check both confirm `1.63.0`. No other dependency constraints were changed. |
| 7 | `tests/test_recon_architecture_boundary.py` scans all source ASTs and resolves import aliases/relative imports. Business modules cannot import Playwright/trusted adapter entry points, perform browser/CDP operations, dynamically load code, or add subprocess/shell paths. Existing fixed runners require `shell=False`. | Positive source-tree scan plus injected violations across Agent/planner/service/discovery/policy/contracts, alias/dynamic imports, direct browser/CDP calls and shell/Popen attempts. |

New focused suites:

- `tests/test_recon_final_hardening.py`
- `tests/test_recon_architecture_boundary.py`

Existing suites extended:

- `tests/integration/test_recon_browser_local_e2e.py`: actual assets, script/fetch semantics and coverage assertions. The previous asset-inclusive endpoint count was replaced with explicit application inclusion and asset exclusion; request/evidence/security checks remain.
- `tests/test_recon_browser_boundary.py`: fake CDP now emits Network correlation data used by the real guard.

Other modified files: `.github/workflows/ci.yml`, `src/recon/browser_runtime.py` (explicit `shell=False`), `README.md`, `ARCHITECTURE.md`, `docs/day3-browser-discovery.md`, `docs/adr/0003-browser-execution-boundary.md`, and this report.

## Verification results

| Gate | Result |
|---|---|
| `python -B -m ruff check --no-cache src tests` | PASS |
| `python -B -m pytest -p no:cacheprovider tests -q` | **221 passed; 0 skipped** |
| Real Chromium localhost tests | PASS; forbidden sink remains at zero requests; writes, redirects, downloads, WebSockets, service workers, cancellation/restart and Day 2 FUZZ_READY baseline regressions remain green |
| `docker build -t agent-recon-final .` | PASS |
| `docker run --rm agent-recon-final python -m src.recon.browser_runtime --probe` | PASS, exit 0 |
| Container identity/version | UID **1000**, Playwright **1.63.0** |
| Default container FastAPI startup | PASS: `/health` returned `{"status":"ok","env":"test"}` |
| New GitHub Actions run | **Not yet verified**: these changes have not been pushed; no claim is made about a remote run for this patch |

See the [container commands](day3-browser-discovery.md#container-gate) for reproducible smoke steps.

## Compatibility and remaining limits

- Existing completed child ToolRuns retain their old IDs, fingerprints, results and evidence. Completed or uncertain parent execution is not regenerated. The resource filter is applied to new projections and evidence replay; this change does not destructively rewrite historical evidence or snapshots.
- Empty path prefixes now follow the requested whole-target-path semantics. Explicit prefixes still restrict paths, and path validation occurs before allowing an empty-prefix match. No network boundary is bypassed.
- If browser was requested but unavailable and no run exists, coverage records `browser:unavailable` without inventing a failed run; static completion remains independently visible. Consumers should inspect `limitations` alongside `complete`.
- Browser byte limits remain response-admission bounds, not exact TCP wire-byte limits. Literal-IP scope and passive fixed DOM behavior remain in force.
- All seven code fixes and local/container checks pass. **Recon MVP is not declared complete until the new GitHub CI gates pass on the published patch.**
