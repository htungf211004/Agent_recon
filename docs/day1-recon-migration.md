# Day-1 Recon migration plan

## Source inspection

- `pentest_ai_v2/core/executor.py` centralizes subprocess calls, timeout, output capture, and audit. Keep the single execution chokepoint, but retire its `execute(tool, args)` interface, flag prefix matching, RFC1918 blanket permission, and public override.
- `pentest_ai_v2/core/analyzer.py::parse_nmap_output` extracts open TCP/UDP ports, service names, versions, and an OS label from Nmap text. Port and service parsing can be adapted into typed attack surface observations; the old attack-chain flags are outside Day 1.
- `pentest_ai_v2/config/tool_whitelist.yaml` includes tools and modes beyond Day 1. Replace it with an in-code registry of three fixed capabilities: HTTP probe, bounded Nmap service scan, and passive WhatWeb fingerprinting.
- `pentest_ai_v2/samples/auto_capture/whatweb_*` supplies verbose, ANSI-colored WhatWeb fixtures. Parse only reported technologies and versions; do not synthesize vulnerabilities.
- `pentest_ai_v2/database.py` stores generic scans and execution records. Use small new SQLite repositories for trusted tasks/scopes, decisions/results, and evidence metadata.

## Incremental implementation

1. Define strict typed Recon contracts and a stored task scope. Test invalid parameters and serialization.
2. Add a deny-by-default PolicyService, capability registry, and ToolExecutionGateway. A request names a capability and typed parameters; the gateway loads the trusted task, checks scope immediately before dispatch, and records denials. Test unknown tasks/capabilities, out-of-scope targets and ports, and that denied requests never reach an adapter.
3. Add HTTP, Nmap, and WhatWeb adapters and migrate the Nmap parser. Adapters construct their own fixed operations; no agent-supplied command or flags. Test parsers, fixed subprocess arguments, redirects, and tool failures without live scanning.
4. Persist raw bounded evidence with a digest, then SQLite metadata and Recon results. Test retrieval, result correlation, and a complete mocked Recon plan.

## Day-1 boundary

Only exact IP address targets explicitly stored in a task are executable. URL hostnames, redirects, arbitrary scripts, external wordlists, and raw shell arguments fail closed. This avoids DNS rebinding and unreviewed target expansion until a later hostname pinning design exists. No Browser-Use, CVE/RAG, fuzzing, validation, or endpoint discovery is included.

## Implemented path

`src/recon/bootstrap.py::create_recon_service` wires the SQLite repository, policy, capability registry, evidence store, gateway, and the three adapters. A trusted operator layer stores a `ReconTask` with exact IPs, ports, capabilities, and expiry. A Recon planner submits a `ReconPlan` of typed actions to `ReconService.run`; it has no field for executable commands or flags. Every action flows through `PolicyService` immediately before adapter dispatch. Tool results and denials are stored by request ID, and successful outputs reference digest-checked evidence files.

Run the tests with `python -B -m pytest -p no:cacheprovider tests -q` and lint with `python -B -m ruff check --no-cache src tests`. Adapter tests use fake subprocesses and HTTP transport; the suite does not contact a target. Nmap and WhatWeb must be installed on the runner for real calls. Subprocess output goes to a temporary file; only the first 256 KiB is retained as evidence.
