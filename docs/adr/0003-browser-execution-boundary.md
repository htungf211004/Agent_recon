# ADR 0003: Browser execution boundary before Day 03

Status: design gate accepted; no Browser adapter is implemented in Day 02.

Every Browser planner or agent proposes a typed capability request to the existing `ToolExecutionGateway`. `PolicyService` evaluates trusted run, target, scope, method, risk and budget before `BrowserAdapter` may create a navigation. Browser-Use has no independent execution authority.

A navigation can trigger document, script, style, image, XHR/fetch and redirect requests. The Browser adapter must intercept **every outbound request before network continuation** and route it through a Gateway-controlled child request and policy decision. The adapter must not rely on checking the initial navigation URL alone. Child requests need stable request IDs, action fingerprints, durable ToolRuns, evidence and shared task budgets. Continuation must be available only to the adapter after the corresponding child request is allowed. A policy denial aborts that browser request.

The first browser mode is a deterministic passive observer. Permit only GET/HEAD to the same trusted authorized origin and scoped paths, subject to resource-count, byte and time bounds. Block write methods, off-scope or unknown navigation, cross-origin or unapproved redirects, downloads, WebSocket traffic, service-worker initiated traffic, and arbitrary Host overrides. Browser context, redirect handling and resource interception must fail closed when their coverage is uncertain. No form submission or click is implied by passive discovery.

The implementation gate for Day 03 is a local fixture in which JavaScript attempts an off-scope fetch, a POST, a redirect, a download and a WebSocket. The test must show zero forbidden network dispatches, allow and record authorized GET/HEAD resources through the Gateway, and prove evidence/request correlation after restart. A second gate verifies cancellation: a requested cancellation reaches a durable terminal `CANCELLED` state, fences late results and stops further child dispatch. These acceptance tests precede any Browser-Use agent.

The current lab is literal `127.0.0.1`. A domain-based lab adds a separate P0 integration gate: trusted authority, pinned resolved IP/port, Host and TLS SNI with certificate validation must be bound and checked together. Agents cannot supply Host values. Until that transport exists, Browser navigation remains restricted to the literal-IP lab.
