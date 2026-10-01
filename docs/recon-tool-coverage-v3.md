# Recon Tool Coverage V3 implementation status

This document tracks the Pre-KB/RAG Freeze gate. The freeze is **open**. KB ingestion
must wait until every required local tool, provider, protocol check, runtime image,
and acceptance scenario has passed.

## Contracts now available

- `CapabilityRequest` remains the target network request with a concrete IP pin.
  `ProviderCapabilityRequest` binds the authorized domain, provider, fixed query
  profile and limits. `LocalOsintCapabilityRequest` binds the authorized root,
  selected passive CLI and result/time limits without a synthetic IP.
  `EvidenceCapabilityRequest` binds an existing evidence ref.
  Request fingerprints include the scope and policy snapshot. Old target request
  JSON and default budget serialization remain replayable.
- Gateway execution persists all four request kinds through the same ToolRun and
  policy lifecycle. Provider and offline results have no synthetic target IP.
  Generic observations carry the evidence ref. Risk comes from the capability
  catalog. Availability is exported to summary and run manifest.
- Provider adapters use fixed HTTPS endpoints and refuse redirects. Supported API
  providers are Shodan, Censys, FOFA, GitHub, GitLab and Brave when configured with
  credentials. Query profiles are fixed. Raw provider responses and credential
  values are not persisted; normalized references omit URL queries and fragments.
  Provider IPs and URLs remain observations until the scope and DNS flow verifies
  them.
- RDAP uses Verisign's fixed endpoint for .com and .net roots. Other TLDs are
  reported as unsupported until a reviewed registry endpoint is added.
- Offline source-map and WSDL parsers require successful HTTP_FETCH evidence owned
  by the task. They verify the encoded body digest and size. Source content is
  excluded from output; WSDL DTDs and processing instructions are rejected and
  imports are recorded without fetching them.
- GraphQL discovery checks four fixed paths and emits an indicator without keeping
  response bodies. Fixed shallow introspection uses POST only when R2 is explicitly
  in scope and a positive discovery evidence ref matches the same endpoint. It
  stores type metadata only; it does not execute mutations.
- Exposure discovery reuses the bounded pinned HEAD/FFUF transport with separate
  backup and SCM wordlists. The new backup profile is `backup-small-v2`; V1 is
  retained for replay. It does not download archives or repository contents.
- Subfinder, Amass and gau now have fixed passive CLI profiles behind the
  `local_osint` request kind. Output is restricted to normalized in-root host/URL
  references, with query strings stripped. Registration reports missing binaries.
  These adapters have fixture tests but no final-image smoke or pinned binaries yet.
  The separate passive infrastructure capability remains unsupported until it has
  an IP/ASN-specific parser and projection.
- Policy version is `recon-3.1`; tasks persisted under the earlier policy version
  are denied rather than resumed under the expanded execution contract.
- Mandatory coverage now runs the API document wordlist per verified origin and
  seeds `/?wsdl` and `/?WSDL`. V3 rows cannot complete STT2, STT3 or STT11 from
  new tool evidence alone when legacy coverage is incomplete.

## Remaining freeze gates

| Gate | Status | Remaining work |
|---|---|---|
| 1 Contracts and budgets | In progress | Add per-category cumulative result limits and tool-process limit enforcement. |
| 2 Passive and active local tools | In progress | Subfinder, Amass passive and gau contracts/adapters/fixtures are wired; pin binaries and run local-tool smoke. Katana, VHost FFUF and Arjun adapters remain open. |
| 3 Fingerprinting and exposure | In progress | Restricted Nuclei template set, pinned templates, binary install and local smoke. |
| 4 GraphQL and WSDL | In progress | `?wsdl` and `?WSDL` seeds are wired; complete protocol fixture matrix and runtime smoke. |
| 5 External providers | In progress | Extend reviewed RDAP registry coverage, provider fixture matrix and field-level redaction audit. |
| 6 Checklist and phases | In progress | V3 projection is wired; complete phase orchestration and outcome tests. |
| 7 Docker and CI | Open | Pin and review local binary versions/hashes/licenses; run all local-tool smoke cases. |
| 8 Acceptance | Open | All 18 listed scenarios and full CI/container verification. |
| 9 Freeze | Open | Do not declare tool taxonomy frozen or ingest KB yet. |

`recon-checklist-v2` remains in code for old runs. New authorized-root projections
use `recon-checklist-v3`; missing runtime or credentials are reported as unsupported
or incomplete rather than a negative finding. The legacy target-network path is
unchanged for older persisted requests.

The current runtime smoke verifies the earlier final-image capabilities. Set
`RECON_REQUIRE_V3_RUNTIME=1` when invoking `scripts/check_recon_runtime.py` to
fail immediately if any required V3 local capability is unavailable. This is
an explicit pre-freeze gate; it does not replace adapter-specific smoke cases.
