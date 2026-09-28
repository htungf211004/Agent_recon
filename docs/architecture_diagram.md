# Implemented Recon architecture — Day 2 freeze

Python 3.11. See [architecture decisions](../ARCHITECTURE.md) and the [shared handoff contract](day2-endpoint-discovery.md).

```mermaid
flowchart TD
    Task[Trusted ReconTask] --> Agent[ReconAgent]
    Agent --> Planner[Deterministic ReconPlanner]
    Planner --> Plan[ReconPlan]
    Plan --> Service[ReconService]
    Service --> Gateway[ToolExecutionGateway]
    Gateway --> Claim[ToolRun claim / lease / replay]
    Claim --> Policy[PolicyService]
    Policy --> Audit[Persist decision + reserve budget atomically]
    Audit --> Registry[CapabilityRegistry]
    Registry --> Adapter[Bounded adapter]
    Adapter --> Network[Tool or GET/HEAD HTTP]
    Network --> Evidence[EvidenceStore + shared manifest]
    Evidence --> Repo[(ReconRepository)]
    Repo --> Parse[Deterministic parsers]
    Parse --> Route[Routes + concrete observations]
    Route --> Baseline[Verified baseline / readiness]
    Baseline --> Coverage[Coverage and convergence]
    Coverage -->|pending sources within limits| Planner
    Coverage -->|snapshot| Result[ReconResult]
    Result --> DTO[Shared AttackSurfaceInventory v1.0]
    DTO -.-> Consumer[Future Supervisor / Fuzz consumer]
```

```mermaid
stateDiagram-v2
    [*] --> QUEUED: atomic claim
    QUEUED --> RUNNING: policy ALLOW + budget reserved
    QUEUED --> DENIED: policy or availability denied
    QUEUED --> FAILED: expired lease
    RUNNING --> SUCCEEDED: durable result
    RUNNING --> FAILED: error or expired lease
    RUNNING --> TIMED_OUT: adapter timeout
```

Terminal results replay without adapter execution. Lease expiry produces a durable failure; it does not authorize another network call. Readiness and coverage are derived from verified evidence, and can be revoked when evidence or required-input information changes.

The product FastAPI/Supervisor handoff is not wired yet. Hostname dispatch needs trusted authority/IP/SNI configuration before a domain-based lab. No LLM, LangGraph or vector store participates in the current Recon execution path.

Execution identity and template rules are recorded in [ADR 0002](adr/0002-day02-execution-and-route-contracts.md). [ADR 0003](adr/0003-browser-execution-boundary.md) freezes the future Browser interception path and cancellation gate.
