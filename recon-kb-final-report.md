# Recon Knowledge Dataset Final Report

## 1. Repository baseline

| Field | Result |
|---|---|
| Branch | `main` |
| Commit | `d7645c2127662cea50a15f128a157a947ca76be3` |
| Initial git status | Dirty implementation worktree: 13 modified files and 4 untracked Recon KB/runtime files were present before this master-task pass. No existing change was reset. |
| Initial pytest | Aborted while writing pytest cache because the host volume had no free space; after deleting the exact 91 MB pytest temp tree, the suite ran normally. |
| Initial Ruff | PASS |

## 2. Actual architecture discovered

The strict storage contracts are in `src/contracts/recon_kb.py`; the shared ingestion lifecycle is in `src/recon/kb/pipeline.py`; adapters and structural acceptance are in `src/recon/kb/adapters.py` and `src/recon/kb/safety.py`; immutable persistence is in `src/storage/recon_kb.py`; production vector retrieval is in `src/recon/rag/snapshot_retriever.py`; production CURRENT selection is in `src/recon/rag/runtime.py`; runner ID resolution is in `src/recon/kb/runner.py` and `src/recon/kb/runtime.py`. Runtime execution remains bounded by `src/recon/policy.py`, `src/recon/gateway.py`, scope contracts, and evidence storage.

## 3. Runtime contract vocabulary

The complete mapping is in `docs/recon-runtime-contract-map.md`.

| Concept | Actual token/model | Source file |
|---|---|---|
| Capabilities | `Capability` (25 public tokens) | `src/recon/models.py` |
| Capability policy | `CapabilityDefinition`, `DEFINITIONS` | `src/recon/capability_catalog.py` |
| Evidence | `EvidenceManifest`, `EvidenceArtifact` | `src/contracts/evidence.py`, `src/recon/models.py` |
| Assets | `DiscoveredAsset` | `src/contracts/recon_assets.py` |
| Inventory | `AttackSurfaceInventory`, `AttackSurfaceEntry` | `src/contracts/attack_surface.py` |
| Technology | `TechnologyObservation` | `src/recon/models.py` |
| Coverage | `ReconCoverage`, PT_01 checklist states | `src/recon/web_models.py`, `src/recon/checklist_v3.py` |
| Risk | `R0` through `R4` | `src/contracts/execution.py` |
| RAG | `ReconKnowledgeQuery`, `SnapshotKnowledgeRetriever` | `src/recon/rag/models.py`, `src/recon/rag/snapshot_retriever.py` |
| Dataset records | `VectorKnowledgeRecord`, `LookupRecord`, `RunnerDataManifest` | `src/contracts/recon_kb.py` |

## 4. Attack Surface coverage before work

The initial untracked draft had 38 categories and the same broad status count (29 covered, 4 partial, 4 manual, 1 out of MVP), but it had no explicit `execution_mode`, no deterministic forward/reverse audit, and its 37 curated records were not a registered pipeline source. `RECON_CURATED` could not be fetched, validated, diffed, promoted, or retrieved from CURRENT. SecLists/CWE attempt semantics and the full-corpus Nuclei rejection path were also not production-complete.

## 5. Files created

| Path | Purpose |
|---|---|
| `src/recon/data/recon_as_curated_knowledge.yaml` | 37 reviewed methodology records |
| `src/recon/data/recon_attack_surface_coverage.yaml` | 38-row coverage source with explicit execution mode |
| `src/recon/kb/coverage.py` | Curated compiler and deterministic forward/reverse audit |
| `src/recon/kb/export.py` | Export actual CURRENT manifests, examples, retrieval and verification artifacts |
| `tests/recon_kb/test_curated_knowledge.py` | Pipeline, provenance, capability and coverage acceptance |
| `docs/recon-runtime-contract-map.md` | Actual runtime vocabulary audit |
| `docs/recon-attack-surface-coverage.md` | Full generated coverage table |
| `pytest-ingestion.xml`, `pytest-final.xml` | Actual JUnit output |
| `ingestion-manifests.json`, `normalized-examples.json`, `dataset-diff-summary.json` | Machine-readable ingestion outputs |
| `retrieval-verification.json`, `verification-results.json` | Production retrieval/security outputs |
| `recon-attack-surface-coverage.yaml`, `recon-as-curated-knowledge.yaml` | Requested exported dataset copies |

## 6. Files modified

| Path | Reason |
|---|---|
| `src/contracts/recon_kb.py` | Strict coverage, rejection, attempt-history, delivery and source-reference fields |
| `src/recon/data/recon_kb_sources.yaml` | Register `RECON_CURATED`; preserve Wappalyzer and Arjun gates |
| `src/recon/kb/pipeline.py` | Local reviewed source, final/history semantics, per-artifact rejection, shared promotion path |
| `src/recon/kb/adapters.py` | Curated compilation, runner blob dedupe, real-corpus Nuclei rejection handling |
| `src/recon/kb/fetchers.py` | NVD retry, time bound and resumable page/cursor checkpoint |
| `src/recon/kb/registry.py` | Validate local reviewed source and bounded sync settings |
| `src/recon/kb/safety.py` | Admit curated vector records only under structural acceptance |
| `src/recon/kb/cli.py` | `coverage-audit` and `export-artifacts` commands |
| Existing Recon runtime/planning/docs files shown by `git status` | Preserve and verify the pre-existing KB runtime integration in this worktree |
| Recon KB tests | Add real semantic, security, Nuclei, NVD resume and registry coverage |

## 7. Final Attack Surface coverage

The exact 38-row table, including checklist refs, knowledge IDs, execution mode, capabilities, evidence, outputs, completion and gaps, is generated at `docs/recon-attack-surface-coverage.md`. The machine source is `recon-attack-surface-coverage.yaml`.

| Status | Categories |
|---|---|
| COVERED | 29 |
| PARTIAL | `passive_infrastructure`, `websocket_indicators`, `technology_cpe_reference`, `vulnerability_references` |
| MISSING | none |
| MANUAL_HITL | `graphql_schema_review`, `package_advisory_reference`, `parameter_review`, `active_api_review` |
| OUT_OF_MVP | `exploit_validation` |

Deterministic audit: PASS, SHA-256 `50f72e0a6418dc11243136ff71c6ec69fdae29c1ccea58721cbd874515273594`.

## 8. VECTOR_RAG

| Namespace | Records | Sources |
|---|---:|---|
| `attack_surface_methodology` | 48 | WSTG, RECON_CURATED, AMASS_OAM |
| `tool_capability_reference` | 1 | KATANA |
| `technique_reference` | 0 | Remaining P1 classification gap; no empty namespace artifact was created |

Promoted vector snapshots and hashes are recorded in `ingestion-manifests.json`. `RECON_CURATED` contains 37 records at snapshot `d7645c2127662cea50a15f128a157a947ca76be3`, normalized hash `b92c2af9bd1c3c1b10c43a8a7c5e6e70c6a4b8a1201d53b5fc12da6bf651cfa7`.

## 9. STRUCTURED_LOOKUP

| Dataset | Records | Status |
|---|---:|---|
| PSL | 10,334 | PROMOTED |
| IANA well-known | 105 | PROMOTED |
| IANA ports | 12,577 | PROMOTED |
| CISA KEV | 1,730 | PROMOTED |
| CWE | 969 | PROMOTED |
| Nuclei metadata | 5,454 | PROMOTED, PARTIAL artifact coverage |
| NVD CPE | 54,000 of 1,850,452 fetched | PARTIAL_SYNC, not promoted |
| OSV | 0 | NOT_APPLICABLE: no approved package evidence query |

## 10. RUNNER_DATA

| runner_data_id | Source | SHA-256 | Lines | Constraints |
|---|---|---|---:|---|
| `seclists-27f4da6b9b3fcff9` | SECLISTS | `226eaa23b54107ba5eb4c0c0bc415b6c8ce7289109b05591908d695757c019a2` | 11,424 | no recursion/path override/payload/automatic execution |
| `seclists-383631a274007ddb` | SECLISTS | `38db856024fd1cd858ad2e29737eedc321749d92fdf4accd` | 106 | API-related; no recursion/path override/payload/automatic execution |
| `assetnote-c8988118e5cd9349` | ASSETNOTE | `226eaa23b54107ba5eb4c0c0bc415b6c8ce7289109b05591908d695757c019a2` | 11,424 | technology selection still evidence-gated |

Two physical blobs serve three provenance-preserving manifests; the duplicate Assetnote/SecLists bytes are stored once.

## 11. Nuclei result

| Field | Result |
|---|---|
| Files scanned | 5,506 |
| Accepted | 5,454 |
| Rejected | 52 (`INVALID_CWE_ID`) |
| Snapshot | `8b9d065ccb0492d39f7680c908b3030a97ddfe1b` |
| Normalized SHA-256 | `58ba056cab71760363d9480a97e5257764ecbaaacde28618f899876e20527fb5` |
| Structural execution fields found | 0 |
| Status | PROMOTED; coverage PARTIAL because rejected records remain explicit |

## 12. NVD CPE result

| Field | Result |
|---|---|
| Pages | 27 |
| Records | 54,000 / 1,850,452 |
| Cursor | 54,000 |
| Watermark | none (correctly not advanced) |
| Checkpoint | `data/recon_kb/raw/NVD_CPE/.partial/.checkpoint.json` |
| Snapshot/hash | none; incomplete data was not staged or promoted |
| Status | PARTIAL_SYNC |

Resume: `.venv\Scripts\python.exe -m src.recon.kb.cli sync NVD_CPE`.

## 13. Retrieval verification

| Query context | Returned IDs |
|---|---|
| verified origin; robots/sitemap; `http_fetch` | `RECON-AS-ROBOTS-01`, `RECON-AS-SITEMAP-01` |
| JS route gap; static/browser capabilities | `RECON-AS-JS-01`, `RECON-AS-BROWSER-01` |
| `TechnologyObservation` context | `RECON-AS-CPE-01` |

The production retriever was `recon-kb-snapshot-v1`; all returned IDs came from pinned promoted snapshots. RunnerData returned by RAG: false. Exact queries, filters and snapshot IDs are in `retrieval-verification.json`.

## 14. End-to-end verification

The authorized local integration flow exercised scope admission, pinned local origin discovery, gateway execution, evidence persistence, static/JS/robots/content candidates, `AttackSurfaceInventory`/coverage progression, and idempotent resume. The focused local run completed with 9 passed tests. Actual CURRENT retrieval and runner resolution were executed separately in the production verification export and pinned to the same verification run bindings.

The enrichment chain cannot be accepted end-to-end through CPE because full NVD CPE has no promoted CURRENT. KEV/CWE/Nuclei lookups are promoted and remain reference/candidate-only; no Finding authority exists.

## 15. Test results

| Command | Passed | Failed | Skipped |
|---|---:|---:|---:|
| `pytest -q tests/recon_kb --junitxml=pytest-ingestion.xml` | 70 | 0 | 0 |
| Focused local integration (three files) | 9 | 0 | 0 |
| `pytest -q --junitxml=pytest-final.xml` | 524 | 1 | 2 |
| `ruff check src tests` | PASS | 0 | 0 |
| `git diff --check` | PASS | 0 | 0 |
| `python -m src.recon.kb.cli coverage-audit` | PASS | 0 | 0 |

The one final-suite failure is `test_real_tls_pinned_ip_preserves_sni_and_certificate_validation`: the trusted local TLS case returns `ConnectError`. The two skips are real WhatWeb integration tests because the WhatWeb binary is unavailable. Neither was hidden or counted as passed.

## 16. Security verification

| Boundary | Evidence |
|---|---|
| No scope expansion | strict scope/gateway suite and local out-of-scope host assertion pass |
| No arbitrary shell | architecture boundary and strict request models pass |
| No arbitrary payload | runner constraints and wordlist rejection tests pass |
| No active API attacks | curated manual boundary and `active_testing=false` structural model pass |
| No RUNNER_DATA vectorization | production retrieval output and class-isolation tests pass |
| No Nuclei execution content | all 5,454 normalized records scanned; zero execution fields |
| No vulnerability confirmation | lookup helpers return references/candidates and accept no Finding input |
| `action_fingerprint` preserved | changing runner/wordlist ID changes the existing fingerprint test |
| Knowledge grants no execution | strict schema has no command/payload/scope/approval authority fields |

## 17. Remaining gaps

| Priority | Exact gap |
|---|---|
| P0 | NVD initial CPE sync is 54,000 / 1,850,452 with no promoted CURRENT; resume from cursor 54,000. This blocks a usable technology-to-CPE core lookup. |
| P1 | Real TLS pinned-IP/SNI test still fails with `ConnectError` in this Windows environment. |
| P1 | `technique_reference` has no promoted record; current useful records are classified as methodology or tool capability. |
| P2 | Assetnote live refresh returned CDN HTTP 522; the already downloaded, validated same-day snapshot was promoted. |
| P2 | SecLists accepted 2/4 allowlisted files; two files remain rejected by `PAYLOAD_OR_MUTATION_CHARACTER`. |
| P2 | Nuclei rejected 52/5,506 files for invalid upstream CWE IDs; accepted metadata remains usable and safe. |

## 18. Final status

```text
Automatic categories: 29 / 33 covered
Partial: passive_infrastructure, websocket_indicators, technology_cpe_reference, vulnerability_references
Missing: none
Manual/HITL: graphql_schema_review, package_advisory_reference, parameter_review, active_api_review
Out-of-MVP: exploit_validation

RECON DATASET STATUS:
NOT_COMPLETE_FOR_MVP

USABLE_NOW:
NO
```

`NOT_COMPLETE_FOR_MVP` and `USABLE_NOW=NO` are required because the core NVD CPE lookup is still partial and the full final suite retains one real TLS failure. No incomplete or quarantined dataset was promoted.
