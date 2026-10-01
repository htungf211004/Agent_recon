# Domain and IP targets in Recon V2

The primary CLI input is `python -m scripts.run_recon_live --target example.test`
or `--target 10.10.10.5` (IPv6 literals also work). The local UI starts from the
same Target field. The URL and explicit IP/ports forms below are compatibility
paths. Submitting the root grants Recon authorization; the worker does not add an
initial target Approval step.

`AuthorizationBoundary` v2 persists an immutable domain or IP root. A domain
includes descendant hostnames using exact label boundaries and a bounded depth.
Lookalike and third-party hosts remain OUT_OF_SCOPE observations with zero active
dispatch. A discovered descendant receives a Gateway DNS observation, a persisted
transport pin, and a new scope version before any HTTP verification. Root admission
records bounded A/AAAA answers; resume reuses the persisted binding. An IP root
does not authorize arbitrary hostnames mentioned in content.

The default domain profile starts at HTTPS/443 and may verify HTTP/80, HTTP/8080
and HTTPS/8443 through the same frozen root DNS pin. The default IP profile uses
bounded ports 80, 443, 8080 and 8443; it never sweeps all ports. A domain HTTP pin does
not authorize Nmap scans of shared/CDN infrastructure. Bounded content discovery
uses pinned HTTP requests for hostname targets. WhatWeb runs against the hostname
with a process-local resolver pin. HTTP requests also pass through an exact-host
loopback proxy; HTTPS uses WhatWeb's direct TLS path because its proxy implementation
does not support a standard TLS CONNECT sequence. The initial HTTP probe validates
TLS certificates before a hostname origin reaches technology fingerprinting;
WhatWeb itself does not validate TLS certificates, so its output is a supplementary
fingerprint rather than proof of certificate identity.

The local console also accepts HTTP(S) domain/IP URLs through the advanced legacy
profile. Restart the UI after updating:

```powershell
cd C:\VinAI\Agent_recon
.\.venv\Scripts\python.exe -m scripts.recon_ui
```

Open `http://127.0.0.1:8765/`, select **Legacy URL** under Advanced configuration, and enter the intended URL,
for example `https://juice-shop.herokuapp.com/#/`. Use `/` as path prefix for the
whole authorized origin. Choose Gemini and optionally Browser, then start a new
run. The runner reads the existing key/model from `.env`.

CLI equivalent:

```powershell
.\.venv\Scripts\python.exe -m scripts.run_recon_live --url "https://juice-shop.herokuapp.com/#/" --path-prefix / --provider gemini --browser --task-id juice-demo-01
```

These are invocation examples, not a claim that the public site's current response
or deployment has been tested. Use the site only within the operator's authorization.

## Legacy URL compatibility

- Hostnames are now supported instead of being rejected by IP parsing.
- The legacy eight-second DNS admission step selects and freezes one address. The UI passes
  that pin to the CLI; the CLI records it in the trusted task. A resumed task uses
  its saved pin, even if DNS changed.
- `run-manifest.json` exposes `trusted_scope.web_origin` with the hostname, pinned
  IP, scheme and port. Inventory shows the website authority and actual scoped IP.
- HTTP uses the pinned address plus correct Host/TLS SNI; Chromium uses an explicit
  resolver map. Certificate validation stays enabled. HTTP hostname transport uses
  Python's default system trust context, including locally installed trusted roots;
  it never sets `verify=False` or bypasses hostname checks.
- Explicit URL schemes also work on nonstandard ports. `--target-ip` retains its
  existing port-to-scheme heuristic and service-discovery behavior.

## Limits to expect

Only the submitted origin is authorized. Redirects are recorded but never followed
automatically; submit the destination as a new task if appropriate. Another hostname
on the same IP remains outside scope. A failed/stale DNS pin is not silently replaced.
Nmap, WhatWeb and FFUF remain available for the legacy explicit IP profile.
External provider references are observations, never direct authorization for a
new IP scan. Configured provider APIs use fixed endpoints and fixed query profiles;
their availability appears in the run manifest. See
[Recon Tool Coverage V3](recon-tool-coverage-v3.md) for the current freeze status.

The fragment (`#...`) is removed from HTTP identity; it is not a server path.
Root `/#/` works as root navigation. Arbitrary SPA hash-route exploration is not
implemented. Large scripts, compressed or unknown-length Browser responses, required
authentication, third-party assets and existing byte/time/request limits can still
limit discovery. Accepting a URL does not guarantee full coverage or FUZZ_READY.

## Verification

The new fixtures cover hostname admission, DNS pin propagation, resume without DNS
or model re-execution, Host/SNI and certificate validation, tampered bindings,
exactly-once browser dispatch, POST/off-origin zero dispatch, domain inventory,
separate baseline promotion and evidence integrity. The UI/CLI test uses an HTTP
lab and an OpenAI-compatible provider fixture, both on localhost; no real provider
quota or public-site scan is used.

On the development Windows machine, Avast Web/Mail Shield replaces the self-signed
TLS fixture certificate. The strict positive TLS test correctly fails there because
the presented leaf is no longer issued by the fixture's trusted CA. Verification
must run in an environment that presents the actual fixture certificate (Linux
container/CI). Do not disable production TLS checks or trust the substituted
self-signed chain to make this test pass.
