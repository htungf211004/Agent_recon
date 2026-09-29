# Bounded adaptive Recon: implementation and verification

## Baseline and publication

Inspected HEAD and the complete diff before editing: HEAD was exactly
`8295fea79707299a9013c65ec467fcd3cd8c726e`, with a clean working tree.
Baseline was reproduced locally: **309 passed**, mandatory Chromium enabled.
[GitHub Actions run 36514030963](https://github.com/htungf211004/Agent_recon/actions/runs/36514030963)
for that exact commit was independently checked: completed/success.

This revision remains **local, uncommitted and unpushed**, as requested. No remote
CI result is claimed for these edits. The baseline's successful CI is not a gate
result for the changed source.

## Implemented changes

- Sequential deterministic sensing with durable stage plans and verified-origin static discovery.
- Browser only after a persisted validated adaptive proposal; existing child interception/fences retained.
- Strict discriminated proposal union and exclusive target-free STOP with consistency checks.
- Versioned safe checklist, typed evidence-backed context, explicit round semantics and redirect classification.
- Bounded CONTENT_DISCOVERY/FFUF, packaged integrity-checked wordlists and separate HTTP baseline.
- Atomic FFUF request-unit reservations and exclusive same-task batch dispatch.
- Sanitized provider failures preserving verified ASI; planner fingerprint binds provider/model/version/prompt/schema.
- Additive worker completion/readiness metadata, stable audit bundle and explicit trusted mission CLI.
- Non-root pinned FFUF image, expanded real localhost runtime smoke and regression coverage.
- Updated architecture/product terminology, Python compatibility ADR and examples.

## Schema and compatibility

SQLite migration **v8**, `adaptive_stages_and_bounded_content_budget`:

| Change | Reason |
|---|---|
| `recon_stages` | Freeze stage plans before dispatch; replay across restarts |
| `recon_planning_rounds.error_code` | Persist sanitized provider/schema diagnostics |
| `execution_reservations.request_units` | Reserve the whole trusted FFUF wordlist atomically; old rows default to 1 |

Policy remains `recon-3.0`. ASI remains **v1.0**. Historical action/task fingerprints,
ToolRuns, browser continuation identity and evidence bytes are preserved.
`ReconAgent.run()` and the URL-only HTTP profile retain compatibility.
`ReconResult.worker_status` and `handoff_ready` are additive fields.

Planning schema intentionally changes. STOP plus actions is malformed, STOP cannot
carry execution fields, content discovery is now implemented, and model-name-only
planner IDs are replaced by fingerprints. Existing v7 adaptive sessions cannot
silently resume under the new planner. Use a new trusted mission. The obsolete
test that expected all content discovery proposals to be unsupported was replaced
by schema, authorization, budget, baseline and replay tests. Migration assertions
now include v8. Stop old workers before upgrading databases.

## Final public capability manifest

```json
["browser_explore", "content_discovery", "http_fetch", "http_probe", "nmap_scan", "whatweb"]
```

`browser_request` remains internal. Missing binaries/runtime remove their public
capability from availability; the final Docker gate requires the full manifest.

## Acceptance scenarios

| Scenario | Evidence in tests/runtime gate |
|---|---|
| A: sequential sensing | Real Nmap on localhost HTTP, SSH-banner and closed ports; HTTP probe then WhatWeb only on the HTTP origin; stage replay |
| B: browser-only dynamic root | Fixed root JS builds `/dynamic`; first model call sees no Browser run; dispatch observes a durable VALIDATED decision; separate baseline yields FUZZ_READY |
| C: hidden content | Real FFUF HEAD discovers `/hidden`; candidate initially has no baseline; separate Gateway HTTP fetch makes it ready |
| D: off-scope redirect | Real HTTP 301 points to an unauthorized HTTPS sink; sink records TCP accepts and remains at zero; redirect context is OUT_OF_SCOPE |
| E: provider failure | Durable safe error code and adaptive limitation; verified ASI survives; restart makes no uncertain retry |
| F: restart checkpoints | Frozen bootstrap stages, DECIDED, VALIDATED, execution/projection, Browser, FFUF, baseline and EXECUTED/STOP checkpoints; no duplicate model/network work |

Browser security regressions continue checking parent/child policy, one-use dispatch,
off-scope/POST zero dispatch, bounded BFS, cancellation and late-result fencing.
No public target or live provider was contacted by these acceptance tests.

## Commands

```powershell
.venv\Scripts\python.exe -m ruff check src/ tests/ scripts/check_recon_runtime.py scripts/run_recon_live.py
$env:RECON_REQUIRE_CHROMIUM = '1'
.venv\Scripts\python.exe -m pytest -q tests --tb=short
docker build -t agent-recon-final .
docker run --rm agent-recon-final python -m src.recon.browser_runtime --probe
docker run --rm agent-recon-final nmap --version
docker run --rm agent-recon-final whatweb --version
docker run --rm agent-recon-final ffuf -V
docker run --rm agent-recon-final id
docker run --rm agent-recon-final python -m scripts.check_recon_runtime
docker run --detach --name recon-adaptive-health -e APP_ENV=test agent-recon-final
docker exec recon-adaptive-health python -c "import json,urllib.request; assert json.load(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=5))['status']=='ok'"
docker rm -f recon-adaptive-health
```

The cleanup command names only the temporary container created by the preceding command.

## Results

Final complete regression run: **356 passed in 231.67 seconds, zero skipped**,
with `RECON_REQUIRE_CHROMIUM=1`. **Ruff PASS** and `git diff --check` PASS. Existing browser E2E: **13 passed**; new real adaptive E2E: **5 passed**.
Final Docker image build, Chromium probe, six-adapter localhost smoke, sequential real sensing,
non-root UID and FastAPI `/health` passed. Final image ID: `sha256:2c793f00f446eacd608b54c91620e61a4d1c918c364856262e24319dfe1c604a`. Verified binaries: Nmap **7.93**, WhatWeb
**0.5.5**, FFUF **1.1.0** (Debian package **1.1.0-1+b8**); UID **1000**.

During implementation the initial FFUF smoke rejected `-rate`, which is absent in
the pinned release. It was replaced by fixed `-t 1 -p 0.5`; the real smoke then
passed. All local mandatory gates passed; no test was skipped. A localhost SSH-banner fixture logged a connection reset when Nmap closed a probe early; its service classification and all smoke assertions passed.

## Examples and known limits

### PT_01 reconciliation follow-up (2026-09-29)

The supplied DOCX was reconciled by STT and SHA-256 against all ten registry items.
Updated only registry source references/notes, the checklist example and related
documentation; no dispatch logic changed. Execution-relevant registry fields were
compared before/after (excluding only `source_reference` and `notes`) and matched
exactly; the example also matches the strict loaded registry model.

```powershell
.venv\Scripts\python.exe -m pytest -q tests/test_recon_bounded_adaptive.py tests/test_recon_adaptive_planning.py --tb=short
.venv\Scripts\python.exe -m ruff check src/ tests/ scripts/check_recon_runtime.py scripts/run_recon_live.py
git diff --check
```

Follow-up results: **82 passed in 59.03 seconds**, zero skipped; **Ruff PASS**;
`git diff --check` PASS. The full **356-test** run and Docker image results above
precede this metadata/documentation change and were not rerun for it. No external
target or live model was contacted. Changes remain local, uncommitted and unpushed.

### Limits

- [Graph, mission and contracts](recon-bounded-adaptive.md).
- [Generated strict ReconTask, complete planning context, FFUF params and checklist item](recon-bounded-examples.json).
- [Python 3.11/product 3.12 compatibility ADR](adr/0004-bounded-adaptive-runtime.md).
- Literal IP only; domain/DNS pinning/Host/TLS SNI integration remains separate.
- FFUF uses bounded HEAD candidates; GET-only behavior may be missed. It has no arbitrary lists, payloads or recursion.
- Temporary process output is capped when read; it is not an OS filesystem quota.
- Browser admission limits retain the documented transport/header buffering limits.
- No new live Gemini call is required for these deterministic acceptance tests; baseline live integration is retained.
- PT_01 source reconciliation is complete: [STT mapping, source digest and exclusions](recon-checklist-source-mapping.md). This maps the ten curated groups to bounded objectives; it does not claim all 97 source items are implemented.

## Freeze verdict

**NOT FROZEN.** Local implementation/gates and baseline remote CI are documented
separately. Remote CI for this changed revision cannot be confirmed while changes
remain local. Publishing was explicitly withheld. PT_01 source mapping has been
verified against the supplied document. No deployment/push was performed.

## Changed files

Tracked-file diff at the full regression/Docker verification, before PT_01 metadata reconciliation: `31 files changed, 687 insertions(+), 241 deletions(-)`. New files are listed separately below; git diff does not include untracked files until staged.

**31 modified files; 16 new files**, including the subsequent PT_01 mapping. No files were committed or pushed.

### Modified

- `.github/workflows/ci.yml`
- `.gitignore`
- `ARCHITECTURE.md`
- `Dockerfile`
- `README.md`
- `docs/gate-1/02-prd.md`
- `docs/gate-1/03-wireframe-ui-flow.md`
- `docs/recon-adaptive-planning.md`
- `docs/user-stories.md`
- `scripts/check_recon_runtime.py`
- `scripts/run_recon_live.py`
- `src/contracts/recon_planning.py`
- `src/recon/adapters.py`
- `src/recon/adaptive_agent.py`
- `src/recon/adaptive_projection.py`
- `src/recon/agent.py`
- `src/recon/bootstrap.py`
- `src/recon/discovery.py`
- `src/recon/llm_planner.py`
- `src/recon/models.py`
- `src/recon/planning_context.py`
- `src/recon/planning_store.py`
- `src/recon/policy.py`
- `src/recon/proposal_validator.py`
- `src/recon/service.py`
- `src/recon/storage.py`
- `src/storage/migrations.py`
- `tests/integration/test_recon_browser_local_e2e.py`
- `tests/test_recon_adaptive_planning.py`
- `tests/test_recon_handoff_migrations.py`
- `tests/test_recon_policy_snapshot.py`

### New

- `docs/adr/0004-bounded-adaptive-runtime.md`
- `docs/recon-bounded-adaptive.md`
- `docs/recon-bounded-examples.json`
- `docs/recon-bounded-verification.md`
- `docs/recon-checklist-source-mapping.md`
- `src/recon/checklist.py`
- `src/recon/completion.py`
- `src/recon/content_discovery.py`
- `src/recon/data/recon_checklist_v1.yaml`
- `src/recon/data/wordlists/api-common-small-v1.txt`
- `src/recon/data/wordlists/web-common-small-v1.txt`
- `src/recon/data/wordlists/well-known-small-v1.txt`
- `src/recon/sensing.py`
- `src/recon/wordlists.py`
- `tests/integration/test_recon_adaptive_acceptance.py`
- `tests/test_recon_bounded_adaptive.py`
