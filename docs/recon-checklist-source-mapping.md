# PT_01 source mapping for bounded Recon

## Source and interpretation

Reconciled on 2026-09-29 against the user-supplied
`PT_01_Checklist_Pentest_Web.docx` (title: **BẢNG CHECKLIST KIỂM THỬ**).
SHA-256 of the original file:
`73663b9d7b95ff3c24289a3dfecbe23554e410fbbc3aa396d85a72c342e8e785`.
The document contains one checklist table with 97 numbered items in 13 groups.
References below use the table's **STT** column, not page numbers or physical row
numbers (the table also has a header row). Text and table structure were read from
the original DOCX; no visual-layout review or external standards validation is claimed.
The source document is not copied into this repository.

The ten-item [registry](../src/recon/data/recon_checklist_v1.yaml) uses selected
information-gathering objectives from group 1. Document commands, payloads,
recommended tools and imperative wording are reference material; they do not
authorize execution. Trusted task scope, deterministic Policy/Gateway checks,
runtime availability and budgets remain authoritative.

## Mapping

**Subset** means that the source explicitly names the objective, with only the
bounded portion below implemented. **Derived** means a project implementation
step supports the source objective. **Extension** means the mechanism is a project
addition, not an explicit PT_01 requirement. None means full completion of the
referenced pentest item.

| Registry ID | PT_01 STT and item | Relationship | Implemented boundary |
|---|---|---|---|
| `RECON-SERVICE-DISCOVERY` | 2 — Active Recon | Subset | Fixed bounded Nmap service discovery on scoped IPs/ports; no full-port sweep, arbitrary NSE or source-command import. |
| `RECON-WEB-PROBE` | 2 — Active Recon; 3 — Fingerprinting (Web Server & Framework) | Derived | Verify HTTP origins from scoped service candidates before web discovery; this is a project stage, not a separate PT_01 row. |
| `RECON-TECH-FINGERPRINT` | 3 — Fingerprinting (Web Server & Framework) | Subset | Existing bounded WhatWeb observations; no aggressive source recipe, CVE lookup or vulnerability scanning. |
| `RECON-ROBOTS` | 4 — Robots.txt | Subset | Fetch and parse scoped robots directives; extracted paths remain candidates subject to scope and budgets. No archive or subdomain lookup. |
| `RECON-SITEMAP` | 5 — Sitemap.xml | Subset | Bounded sitemap and sitemap-index parsing; declared URLs require authorization. No claim of exhaustive URL coverage or archive lookup. |
| `RECON-WELL-KNOWN` | 6 — .well-known Directory | Subset | Three curated paths: security.txt, openid-configuration and jwks.json. No assetlinks seed, arbitrary metadata wordlist or JWT testing. |
| `RECON-API-DOCS` | 7 — Swagger / OpenAPI | Subset | Existing six seed paths and deterministic OpenAPI 3/Swagger 2 endpoint parsing; `/v2/api-docs` is not a seed. No automatic execution of declared write operations or authentication testing. |
| `RECON-STATIC-ROUTES` | 2 — Active Recon; 11 — Hidden Endpoints | Subset | Bounded links/forms/scripts and simple JS route extraction. No form submission, parameter guessing or source-map reconstruction. |
| `RECON-BROWSER-DYNAMIC` | 2 — Active Recon; 11 — Hidden Endpoints | Extension | Passive Playwright navigation and fixed DOM extraction implement the crawl/route objective. PT_01 does not specify this browser architecture. Every child request retains external-dispatch authorization. |
| `RECON-CONTENT-DISCOVERY` | 2 — Active Recon; 11 — Hidden Endpoints | Subset | Fixed small trusted FFUF wordlists, bounded HEAD candidates, then separate scoped GET baselines. No arbitrary wordlists, recursion, auto-calibration or virtual-host fuzzing. |

## Excluded source work

- STT 1, 14 and 16: external OSINT, domain/subdomain discovery, search engines and
  historical URL sources are outside the current literal-IP runtime.
- STT 8–9: GraphQL introspection and WSDL/SOAP discovery/testing are not implemented.
  An observed URL can enter inventory without implementing these protocols' tests.
- STT 10, 12–13 and 15: backup/credential harvesting, repository dumping, source-map
  reconstruction and public code-host leak searches are not checklist actions.
- Groups 2–13 (STT 17–97): configuration assessment, authentication/session/
  authorization testing, business-logic testing, injection, cryptographic testing,
  client-side exploitation, API abuse and other vulnerability validation remain
  outside this Recon worker. Ordinary response observations do not prove those
  tests were performed or passed.

PT_01 mixes read-only observations with higher-impact testing even within group 1.
Its inclusion of a technique never overrides task restrictions. No source tool
command or payload is copied into planner context or used to generate arguments.
`BROWSER-DYNAMIC` means passive interaction with the page; it still sends real,
bounded network requests and is not the external-OSINT sense of Passive Recon in
STT 1. Discovered methods/forms are inventory data; only authorized GET/HEAD can
be dispatched by the web capabilities.

## Coverage and compatibility

`COMPLETE` applies to a registry item's deterministic evidence rule for a specific
task. It does not mean all steps in the associated PT_01 row were performed, that
the application is secure, or that all 97 items have been covered. `FUZZ_READY`
remains a baseline/readiness state, not permission to fuzz.

This reconciliation changes only `source_reference` and `notes` in the registry,
plus documentation and the generated checklist example. Checklist IDs, version,
capabilities, risk labels, paths, status rules and execution contracts are unchanged.
The reference digest identifies the supplied document revision; document availability
is not a runtime dependency. Remote CI for the unpublished working tree remains
the outstanding freeze gate; see [verification](recon-bounded-verification.md).
