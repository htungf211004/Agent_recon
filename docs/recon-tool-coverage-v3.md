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
- Subfinder, Amass and gau have fixed passive profiles behind `local_osint`.
  Amass infrastructure JSONL emits in-root hosts, IP observations and ASN metadata.
  IP observations require manual review and cannot create DNS pins or widen scope.
  Amass 3.23.3 passive mode disables DNS resolution and dependent IP features
  ([upstream implementation](https://github.com/owasp-amass/amass/blob/v3.23.3/cmd/amass/enum.go)).
  Host-only/null-address output is retained with an explicit metadata-unavailable
  marker; STT1 cannot become COMPLETE from that result. A passive provider capable
  of supplying real IP/ASN metadata remains a freeze gate. Positive parser fixtures
  do not certify that the passive Amass process can produce those records.
- Katana, VHost FFUF, Arjun and restricted Nuclei profiles use an HTTP bridge to
  the persisted IP. The bridge verifies upstream TLS and SNI, strips credentials
  and redirects, enforces method/path/body/time/rate/request limits, and serializes
  task dispatch. Only packaged VHost/parameter dictionaries and hash-locked Nuclei
  templates are accepted. Nuclei currently detects nginx and Apache headers only.
  Arjun needs an explicit R2 capability and a successful complete GET baseline at
  the same endpoint. It runs in a separate virtualenv with hash-locked dependencies.
  The bare-target CLI grants it only with `--parameter-discovery`; existing tasks
  cannot gain this capability on resume and must keep their frozen authorization.
  A bounded negative result is distinct from a timeout or failed CLI invocation.
- VHost results remain candidates for DNS verification. The pinned FFUF 1.1.0 HEAD
  profile uses status/zero-body signatures against two negative hosts; applications
  with identical status codes across VHosts can produce false negatives.
- Policy version is `recon-3.1`; tasks persisted under the earlier policy version
  are denied rather than resumed under the expanded execution contract.
- Mandatory coverage now runs the API document wordlist per verified origin and
  seeds `/?wsdl` and `/?WSDL`. V3 rows cannot complete STT2, STT3 or STT11 from
  new tool evidence alone when legacy coverage is incomplete.
- Checklist STT1 requires passive infrastructure evidence. DOMAIN STT2 excludes
  IP-wide Nmap; VHost applies only with subdomains authorized. R2 parameter discovery
  is required only when explicitly authorized. An IP root with no verified HTTP
  origin uses Nmap for STT2 and marks web endpoint discovery not applicable.

## Remaining freeze gates

| Gate | Status | Remaining work |
|---|---|---|
| 1 Contracts and budgets | Implemented | Cumulative category/process/request reservations; verify the final acceptance matrix. |
| 2 Passive and active local tools | Partial | Actual active adapter fixture smoke passed; passive offline process smoke does not certify positive IP/ASN provider coverage. |
| 3 Fingerprinting and exposure | Implemented | Two restricted hash-locked header templates passed the local final-image runtime smoke. |
| 4 GraphQL and WSDL | In progress | `?wsdl` and `?WSDL` seeds are wired; complete protocol fixture matrix and runtime smoke. |
| 5 External providers | In progress | Extend reviewed RDAP registry coverage, provider fixture matrix and field-level redaction audit. |
| 6 Checklist and phases | Implemented | Applicability tests and replayable mandatory per-origin execution; full acceptance gate remains open. |
| 7 Docker and CI | In progress | Official release hashes/license texts locked for linux/amd64; local V3 runtime passed. Default clean image build and remote CI remain required. |
| 8 Acceptance | Open | All 18 listed scenarios and full CI/container verification. |
| 9 Freeze | Open | Do not declare tool taxonomy frozen or ingest KB yet. |

`recon-checklist-v2` remains in code for old runs. New authorized-root projections
use `recon-checklist-v3`; missing runtime or credentials are reported as unsupported
or incomplete rather than a negative finding. The legacy target-network path is
unchanged for older persisted requests.

## Reproduce runtime checks

```sh
docker build -t agent-recon-final .
docker run --rm --network none -e RECON_REQUIRE_V3_RUNTIME=1 agent-recon-final python -m scripts.check_recon_runtime
```

The V3 gate runs actual Katana/FFUF/Arjun/Nuclei against a local fixture through
the production Gateway, checks discovered values and idempotent replay, and runs
Subfinder/Amass/gau versions plus actual bounded adapters against `.invalid`.
Passive offline timeouts/errors are reported as such, never as verified negative
provider findings. Positive passive parsing/projection is covered with fixtures.
The complete V3 runtime gate has passed locally as the non-root image user:
two crawl URLs, exactly one VHost, GET
parameter `id`, nginx header detection, and zero writes. Amass returned an error
in the offline passive smoke; it was retained as an error, without findings.

`scripts/recon-tools.lock.json` records release URLs, SHA256 values, license IDs
and license-text hashes. The installer extracts only named binaries and legal
files. Other CPU architectures fail explicitly. Refresh locks with
`scripts/resolve_recon_tool_lock.py` only after reviewing new upstream releases.

For a corporate TLS proxy, Docker accepts an optional BuildKit secret:
`--secret id=build_ca,src=/path/to/trusted-ca.pem`. The CA is used only during
dependency downloads and is not copied into the runtime image. TLS verification
stays enabled.

The local image `agent-recon-v3-verified` was built through the current Dockerfile
using `--build-arg RECON_RUNTIME_BASE=agent-recon-v3` to reuse the cached
Playwright 1.63.0 Chromium revision. Tool installation and system dependency
checks still ran. FastAPI startup and `/health` passed in that image. This result
does not certify the default clean base build: its Chromium CDN download did not
complete locally. Remote CI must build from the default base before freeze.

Windows validation had 497 passed, 2 skipped and one localhost TLS ConnectError;
the same strict TLS test passed on Linux. The final full Linux rerun passed
**515 tests** in 285.83 seconds with `RECON_REQUIRE_CHROMIUM=1`, no network, and
`PYTHONPYCACHEPREFIX=/tmp/recon-test-pycache`. Ruff and `git diff --check` passed.
The preceding full run had 513 passed and one UI test failure
(`stale_or_expired_task` before dispatch). All 12 UI tests passed on isolated
rerun, followed by the green full rerun; the cause of the intermittent first-run
failure remains unconfirmed. Remote CI and the final acceptance matrix are still
required before declaring the freeze closed.
