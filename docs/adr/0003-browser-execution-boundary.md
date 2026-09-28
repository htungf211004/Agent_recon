# ADR 0003: Browser execution boundary before Day 03

Status: Day 03 Ver02 implemented for literal-IP lab targets; external-dispatch contracts preserved.

Every Browser planner or agent proposes a typed capability request to the existing `ToolExecutionGateway`. `PolicyService` evaluates trusted run, target, scope, method, risk and budget before `BrowserAdapter` may create a navigation. Browser-Use has no independent execution authority.

A navigation can trigger document, script, style, image, XHR/fetch and redirect requests. The Browser adapter must intercept **every outbound request before network continuation** and route it through a Gateway-controlled child request and policy decision. The adapter must not rely on checking the initial navigation URL alone. Child requests need stable request IDs, action fingerprints, durable ToolRuns, evidence and shared task budgets. Continuation must be available only to the adapter after the corresponding child request is allowed. A policy denial aborts that browser request.

The first browser mode is a deterministic passive observer. Permit only GET/HEAD to the same trusted authorized origin and scoped paths, subject to resource-count, byte and time bounds. Block write methods, off-scope or unknown navigation, cross-origin or unapproved redirects, downloads, WebSocket traffic, service-worker initiated traffic, and arbitrary Host overrides. Browser context, redirect handling and resource interception must fail closed when their coverage is uncertain. No form submission or click is implied by passive discovery.

The implementation gate for Day 03 is a local fixture in which JavaScript attempts an off-scope fetch, a POST, a redirect, a download and a WebSocket. The test must show zero forbidden network dispatches, allow and record authorized GET/HEAD resources through the Gateway, and prove evidence/request correlation after restart. A second gate verifies cancellation: a requested cancellation reaches a durable terminal `CANCELLED` state, fences late results and stops further child dispatch. These acceptance tests precede any Browser-Use agent.

The current lab is literal `127.0.0.1`. A domain-based lab adds a separate P0 integration gate: trusted authority, pinned resolved IP/port, Host and TLS SNI with certificate validation must be bound and checked together. Agents cannot supply Host values. Until that transport exists, Browser navigation remains restricted to the literal-IP lab.

Implementation note: `BROWSER_REQUEST` uses the two-phase Gateway permit. A durable continuation marker is consumed before Playwright sends a request. Cancellation writes a terminal parent/child result and fences later writes. Chromium WebSocket routes remain local without calling `connect_to_server()`.

Ver02 adds a CDP response pause because Chromium redirect continuations can bypass the Playwright route callback. All redirects and attachments are aborted before consumption. Body-bearing responses require an explicit identity-encoded Content-Length within per-response and total admission budgets. Unknown-length, chunked and compressed responses fail closed. Headers and transport bytes buffered before response admission are not a hard wire-byte guarantee.

ReconAgent now executes a persisted BrowserDiscovery plan and a bounded same-origin anchor BFS. Stable page sequence participates in child identity and fingerprint, while page-zero defaults preserve Ver1 replay. DOM reads use fixed code in an isolated world, and their evidence feeds the existing EndpointObservation/template/inventory contracts. CI requires a usable Chromium runtime and real zero-dispatch assertions against a reachable forbidden sink. See [Day 03 guide](../day3-browser-discovery.md).
