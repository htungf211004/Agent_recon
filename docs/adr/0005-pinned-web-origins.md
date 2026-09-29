# ADR 0005: Explicit pinned web origins

Status: implemented; additive to the Policy/Gateway/browser boundary in ADR 0003.

Operator URL admission accepts canonical HTTP(S) hostnames and literal IPs. DNS
resolution is bounded to eight seconds in the CLI admission layer. One usable
address is selected deterministically (IPv4 before IPv6), then persisted in
`Scope.web_origin` with hostname, scheme and port. Scope still contains exactly
the authorized IP and port. A trusted operator may supply `--pinned-ip`; model
proposals cannot supply or change this binding. Restarts use the stored pin,
not a new DNS answer. Another URL or pin requires a new task.

`CapabilityRequest.target_host` is derived by deterministic planning from the
trusted scope. Policy checks the complete IP/host/scheme/port tuple; its fingerprint
binds the host, parameters and scope snapshot. Browser child admission also checks
the parent host. Unbound hostname requests are denied. Legacy tasks/requests omit
the new null fields when serialized, preserving their stored identities and hashes.
No SQLite schema change or ASI version change is needed; old worker binaries must
not be used to resume new hostname tasks.

HTTP connects to the literal pinned IP. Only the bound authority becomes Host;
httpcore's `sni_hostname` extension supplies the original hostname for TLS SNI and
certificate hostname verification. Verification is never disabled. Redirects remain
responses with evidence, not automatic network continuations.

Chromium navigates to the hostname with fixed host-resolver rules for its pin;
other DNS names fail closed. Proxies and QUIC are disabled for these sessions.
The existing request interception and one-use Gateway child permit still precede
network continuation. Same-origin enforcement covers scheme, hostname and port,
including hostnames that happen to resolve to the same IP. Redirect response
guards, download/WebSocket/service-worker blocks, cancellation and size limits stay
in place. TLS errors are not ignored.

Only HTTP_FETCH, HTTP_PROBE and Browser transports implement this origin contract.
Nmap, WhatWeb and FFUF remain literal-IP capabilities; Policy refuses them for a
bound hostname scope. Inventory retains the hostname authority and the pinned
`resolved_ip`, with the existing observation/baseline/provenance contract.

URL fragments are excluded from network identity. This admits Juice Shop's root
`/#/` URL, but does not implement exploration of arbitrary hash routes such as
`/#/login`. This feature does not increase task budgets or remove SPA/resource,
body-size, authentication or same-origin limitations.

Verification and platform limits: [domain support](../recon-domain-support.md).
