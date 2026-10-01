# Recon Tool Coverage V3 implementation status

This document tracks the Pre-KB/RAG Freeze gate. The freeze is **open**. KB ingestion
must wait until every required local tool, provider, protocol check, runtime image,
and acceptance scenario has passed.

## Contracts now available

- `CapabilityRequest` remains the target network request with a concrete IP pin.
  `ProviderCapabilityRequest` binds the authorized domain, provider, fixed query
  profile and limits. `EvidenceCapabilityRequest` binds an existing evidence ref.
  Request fingerprints include the scope and policy snapshot. Old target request
  JSON and default budget serialization remain replayable.
- Gateway execution persists all three request kinds through the same ToolRun and
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
  backup and SCM wordlists. It does not download archives or repository contents.

## Remaining freeze gates

| Gate | Status | Remaining work |
|---|---|---|
| 1 Contracts and budgets | In progress | Add per-category cumulative result limits and tool-process limit enforcement. |
| 2 Passive and active local tools | Open | Subfinder, Amass passive, gau, RDAP, Katana, VHost FFUF and Arjun adapters, pinned runtime, projection and fixtures. |
| 3 Fingerprinting and exposure | In progress | Restricted Nuclei template set, pinned templates, binary install and local smoke. |
| 4 GraphQL and WSDL | In progress | WSDL `?wsdl` seed expansion, complete protocol fixture matrix and runtime smoke. |
| 5 External providers | In progress | Extend reviewed RDAP registry coverage, provider fixture matrix and field-level redaction audit. |
| 6 Checklist and phases | In progress | V3 projection is wired; complete phase orchestration and outcome tests. |
| 7 Docker and CI | Open | Pin and review local binary versions/hashes/licenses; run all local-tool smoke cases. |
| 8 Acceptance | Open | All 18 listed scenarios and full CI/container verification. |
| 9 Freeze | Open | Do not declare tool taxonomy frozen or ingest KB yet. |

`recon-checklist-v2` remains in code for old runs. New authorized-root projections
use `recon-checklist-v3`; missing runtime or credentials are reported as unsupported
or incomplete rather than a negative finding. The legacy target-network path is
unchanged for older persisted requests.
