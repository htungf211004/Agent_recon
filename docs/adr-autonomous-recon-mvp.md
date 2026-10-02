# ADR: Autonomous Recon controller for the MVP

Status: accepted for the current implementation.

The default live Recon controller calls the configured LLM before dispatching a
Recon tool. It repeats planning after each accepted action, with trusted scope,
available capabilities, validated evidence summaries, inventory, checklist,
coverage score, residual signals, prior actions and rejections in context. The
deterministic pipeline remains available through `--planner deterministic` for
compatibility and diagnosis.

The model returns typed capability proposals. The validator binds targets,
provider and evidence identifiers to stored facts, rejects duplicate or unsafe
actions, and submits accepted requests to Policy and the ToolExecutionGateway.
The model cannot supply commands, arbitrary arguments, payloads or evidence
claims. R0, R1 and bounded R2 Recon discovery are autonomous when the immutable
task scope and policy authorize them. Exploit and payload validation are outside
the Recon capability catalog and require their own approval boundary.

Coverage is a weighted, evidence-only checklist projection. Success requires
all mandatory goals resolved, score at least 90 and no actionable residual
signal, or all applicable goals resolved. A proposed sufficient-coverage STOP
that fails these conditions is rejected. Round, action, request, context or
provider limits produce a limited or partial result and never imply success.
The final result includes attack surface inventory, evidence-backed candidates,
checklist, score, signals, planning trace and limitations. A candidate is an
investigation lead, not a confirmed vulnerability.

Promoted vector knowledge can rank safe Recon methods for pending checklist
goals. Promoted automatic runner datasets are selected from the registry, pinned
to the run and resolved by the trusted runner. Neither knowledge nor a model
response expands authorization. Run state, decision identity, request
fingerprints and evidence remain durable for replay and resume.
