# Recon final P0 verification

Changes on top of `fc97ed7`, preserving the Policy/Gateway/ToolRun and AttackSurfaceInventory v1.0 contracts.

## Implemented

1. Trusted policy snapshot, `recon-3.0`, migration v6 and explicit legacy v4 binding. Old v3/v5 databases preserve historical fingerprints and completed replay. New actions on stale policy snapshots are denied; expired executions remain terminal.
2. Separate `BrowserBaselinePromotion` after BrowserDiscovery. Conservative evidence-backed GET/HEAD selection, concrete template eligibility, persisted deterministic selection and request identity, and bounded HTTP_FETCH through Policy/Gateway. Complete verified 2xx evidence replaces the primary observation response while retaining browser provenance. No fake DiscoverySource or extra static rounds.
3. Promotion tests cover GET/HEAD, lexical selection, template reconciliation, unresolved inputs, forms/writes, browser errors, scope/expiry/budget denial, missing HTTP_FETCH, baseline redirects/errors/truncation, corruption and crash/restart recovery.
4. Real Chromium fixture builds `/dynamic?source=browser` at runtime so static discovery cannot find it. Exactly one browser GET plus one baseline GET produces FUZZ_READY; reopening the repository adds zero network requests. Forbidden sink remains at zero.
5. Final Docker stage installs Nmap and WhatWeb alongside pinned Playwright Chromium. The runtime smoke requires exactly five public capabilities, then runs each real adapter through the production Gateway against localhost, checking policy, evidence and replay. WhatWeb's supported `--follow-redirect=never` replaces its ineffective old flag; a real redirect sink verifies zero follow-up traffic.

## Gate results

| Gate | Result |
|---|---|
| Ruff: `src tests scripts/check_recon_runtime.py` | PASS |
| Full pytest suite | **258 passed, zero skipped** (all prior 221 retained) |
| Chromium localhost suite | **12 passed**, including browser-only promotion and zero extra traffic on restart |
| Docker build | PASS |
| Nmap binary | **7.93**, PASS |
| WhatWeb binary | **0.5.5**, PASS |
| Chromium probe as non-root | PASS |
| Exact runtime manifest | PASS: `browser_explore`, `http_fetch`, `http_probe`, `nmap_scan`, `whatweb` |
| Real five-adapter Gateway smoke + WhatWeb redirect sink | PASS |
| Default FastAPI health | PASS: `{"status":"ok","env":"test"}` |
| GitHub Actions for this patch | Pending; user requested local changes only, with no commit or push |

The workflow now requires Chromium, full tests/Ruff, image build, binary versions, exact capability manifest, real adapter smoke and FastAPI health. The local gates are verified; **MVP freeze remains pending a successful GitHub Actions run on the published changes**.

## Compatibility and limits

- Stop old workers before schema upgrade. Historical policy/evidence is not rewritten by v6. Create a new trusted task to perform new actions under `recon-3.0`.
- Browser evidence remains metadata/headers with bounded fixed DOM capture. Baseline body evidence comes only from HTTP_FETCH. Body admission is not a TCP wire-byte firewall.
- The first selected baseline remains frozen even if denied, interrupted, truncated or corrupted. No automatic retry or alternate concrete selection is introduced.
- Promotion consumes the existing shared request/rate/body/time limits. Discovery completeness does not guarantee every observed endpoint has a successful baseline.
- Scope remains literal-IP, passive and bounded. No Browser-Use, CVE/RAG, Fuzzing, Validation, Approval or Finding behavior is added.
