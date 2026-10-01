# Recon Knowledge Metadata Ingestion v1

This is an operator maintenance pipeline under `src/recon/kb`. It does not participate in target execution.
Registry entries live in `src/recon/data/recon_kb_sources.yaml`; contracts extend `src/contracts`, and
`src/storage/recon_kb.py` maintains content-addressed snapshots independently of Run Evidence.

## Operator workflow

From the repository, with the normal Python environment and requirements installed:

```powershell
python -m src.recon.kb.cli sync WSTG
python -m src.recon.kb.cli normalize WSTG
python -m src.recon.kb.cli validate WSTG
python -m src.recon.kb.cli diff WSTG
python -m src.recon.kb.cli promote WSTG
```

`sync` saves raw bytes and a STAGED pointer. `normalize` runs deterministic adapters and security checks.
`validate` verifies raw hashes, strict record schemas, provenance, adapter projections and source acceptance
before marking READY. `diff` records changes against the current snapshot. `promote` repeats validation,
requires that diff to match both snapshot identities and the normalized digest, then atomically changes
CURRENT. Failed validation is QUARANTINED and never replaces CURRENT. Fetch failures preserve a separate
FAILED audit report and available raw bytes. A failed update can be explicitly normalized again after its
underlying cause is resolved. The source lock prevents concurrent writers; stale locks need operator review.

`python -m src.recon.kb.cli sync-all` processes enabled, license-approved sources through READY only.
OSV needs operator-configured versioned package evidence queries. It reports failure when none exist.
Wappalyzer fingerprints stay disabled/license gated, and Arjun cannot be enabled by this pipeline.

Use `--root <directory>` and `--registry <file>` before the subcommand for isolated operator fixtures or
reviewed registry configuration. There is no CLI argument for an arbitrary download URL, payload, or shell.
Git refs are explicit registry settings; mutable refs resolve to a captured immutable commit. Git uses shallow
fetch and sparse checkout, disables global/system configuration and hooks, and invokes only fixed argv with
`shell=False`. On Windows it uses OpenSSL with the Windows trusted CA roots to work with sandbox tokens;
TLS verification remains enabled. HTTP downloads enforce HTTPS hosts, timeouts, redirects, byte limits,
SHA-256, and atomic writes. Failed HTTP transfers never overwrite an existing artifact.

## Storage and history

```text
data/recon_kb/
  raw/<SOURCE>/<SNAPSHOT>/
  normalized/<SOURCE>/<SNAPSHOT>/records.jsonl
  normalized/<SOURCE>/<SNAPSHOT>/acceptance.json
  normalized/<SOURCE>/<SNAPSHOT>/diff.json
  vector_docs/<SOURCE>/<SNAPSHOT>/records.jsonl
  lookup/<SOURCE>/<SNAPSHOT>/records.jsonl
  runner_data/<SOURCE>/<SNAPSHOT>/
  manifests/<SOURCE>/<SNAPSHOT>.json
  manifests/<SOURCE>/STAGED.json
  manifests/<SOURCE>/CURRENT.json
```

Production class directories are populated at promotion; CURRENT controls selection. Raw snapshots may
contain upstream active sections for provenance, but raw files never enter vector documents or the planner.
Generated datasets are covered by the repository's existing `data/` ignore rule. Only small offline fixtures
and source configuration belong in Git. `content_sha256` hashes a canonical map of artifact paths and
their SHA-256 digests; `normalized_sha256` seals the exact JSONL. Runner manifests also hash the sanitized
wordlist bytes, preserving upstream entry order after exact deduplication.

SQLite migration 11 adds immutable `(run_id, source_id)` snapshot bindings. Call
`repository.pin_kb_snapshot(run_id, promoted_manifest)` when a Run selects a dataset. A different snapshot
cannot replace an existing Run binding; a new Run can select the new CURRENT. `kb_snapshots(run_id)`
returns the historical manifests. Evidence, scope, approvals, and findings are not rewritten.

## Retrieval and runner integration

`SnapshotKnowledgeRetriever(store, {source_id: snapshot_id})` implements the existing bounded retriever
interface. It accepts only PROMOTED VECTOR_RAG records. Before returning references, it filters phase,
category, asset types, technologies, available capabilities, risk ceiling, and active-testing eligibility.
It pins its manifests in the Run repository when used by the existing planning context, which now persists
source version, commit and snapshot ID on knowledge references. v1 provides deterministic reference
selection; it does not add an embedding provider or change the Recon Planner prompt.

The live runner selects promoted VECTOR_RAG `CURRENT` snapshots automatically. A resumed run reconstructs
the retriever from its immutable `recon_kb_bindings` instead of following a newer `CURRENT`. Both the
retriever implementation ID and full snapshot manifests (`kb_snapshots`) are exported in
`run-manifest.json`.

`RunnerDataResolver(store, source_id, snapshot_id).resolve(runner_data_id)` resolves an operator-pinned
catalog by ID, verifies its byte digest and normalization, and returns the existing `TrustedWordlist` shape.
It accepts no caller-supplied local path or payload. Technology-aware lists require a matching
`TechnologyObservation` with evidence. Automatic resolution is forbidden, including API-route datasets.
Ingested IDs are not automatically added to the runtime `TRUSTED` catalog. After reviewing and promoting a
RUNNER_DATA snapshot, an operator can select an exact entry for one live run with
`--runner-data SOURCE_ID:runner_data_id`. Selection verifies the snapshot, record and bytes, pins the
manifest to the Run, and installs only that ID in the process-local catalog. The deterministic coverage
stage then sends it through the existing typed request, policy and gateway path. A resume reloads the
same pinned snapshot only when the operator repeats the exact `--runner-data` option; the exported manifest
is informational and is never trusted as selection authority. Existing action fingerprints bind
`wordlist_id`, so changing a dataset cannot reuse an earlier execution identity.

KEV joins only exact uppercase CVE IDs and returns reference metadata. IANA port helpers return
`registered_service` references without updating observed services. PSL calculates a registrable-domain
reference but has no scope authority. CPE text matches remain CANDIDATE and need evidence. OSV requires
package identity/version/evidence, preserves advisory source provenance, and deactivates withdrawn records.

## Adapter boundaries

WSTG is pinned to v4.2 INFO-01 through INFO-10, with manually reviewed semantic Recon documents rather
than upstream markdown chunks. SecLists reads only four explicit Discovery/Web-Content paths. If a file
has unsafe entries, the entire file is excluded with a report; other independently safe allowlisted files
may be staged. Blank/comment lines drop, exact duplicates deduplicate in order, and dangerous entries are
never rewritten or replaced by similar filenames. An update with no safe files is quarantined.

Assetnote selects exact operator-approved manifest filenames and downloads only manifest-proven CDN URLs.
Nuclei uses explicit metadata projection, never template execution. KEV validates the upstream JSON Schema
without permitting external schema fetches. PSL handles ICANN/PRIVATE and EXACT/WILDCARD/EXCEPTION.
IANA CSV parsers validate required columns and keep read-only reference semantics. NVD paginates with
bounded requests, overlaps and splits incremental windows at 120 days, merges deltas with preserved record
provenance, and advances the durable watermark only at promotion. A capped or incomplete fetch fails
without advancing CURRENT. Its initial full dictionary fetch may require operator-reviewed limits for a
large deployment. CWE reads bounded XML archive members without extracting arbitrary paths or entities,
keeping descriptions/relationships while excluding detailed examples. OSV paginates package-keyed API
responses. Katana and Amass/OAM compile curated capability/asset methodology from upstream README provenance.

The live IANA Well-Known CSV link is `well-known-uris-1.csv` (the requested `well-known-uris.csv` returns
404). The canonical registry page links the current CSV:
https://www.iana.org/assignments/well-known-uris.
CISA KEV's upstream HEAD is `develop`; Katana's upstream HEAD is `dev`. Both are explicit registry refs.
WSTG v4.2 lacks the requested `checklists/checklist.md`; the absence is reported without substitution.

## Verification

```powershell
python -m pytest -q tests/recon_kb
python -m pytest -q
python -m ruff check .
```

All tests in `tests/recon_kb` use small committed fixtures or mocked transports and require no internet.
Coverage includes all source adapters, class/provenance isolation, exact joins, gates, HTTP/Git bounds,
incremental merging, immutable Run bindings, stale diffs, quarantine preservation, wordlist integrity,
and the existing action-fingerprint behavior. The architecture boundary still forbids business-logic
process execution; its only addition is the explicit operator-maintenance Git runner.
