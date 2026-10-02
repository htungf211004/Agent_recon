"""Worker terminal state is separate from endpoint readiness and coverage completeness."""

from src.recon.checklist_v3 import project_checklist_v3
from src.recon.execution import ToolRunState
from src.recon.web_models import SourceStatus


def completion(agent, task_id, result):
    if getattr(agent, "execution_mode", "deterministic_fallback") == "llm":
        task = agent.repository.get_task(task_id)
        rows = agent.coverage_evaluator.project(task)
        from src.recon.residual_signals import may_stop, residual_signals

        stop = agent.store.status(task_id)
        runs = agent.repository.list_tool_runs(task_id)
        pending = any(run.state in {ToolRunState.RUNNING, ToolRunState.QUEUED} for run in runs)
        rounds = agent.store.rounds(task_id)
        terminal = bool(stop) and not pending and all(row["state"] in {"EXECUTED", "FAILED"} for row in rounds)
        signals = residual_signals(task, agent.repository, agent.service)
        if may_stop(rows, signals):
            outcome = "COMPLETE"
        elif stop in {"request_limit", "round_limit", "action_limit", "context_limit", "model_error",
                      "model_outcome_unknown"}:
            outcome = "LIMITED"
        else:
            outcome = "PARTIAL"
        return {"terminal": terminal, "run_status": "COMPLETED" if terminal else "RUNNING",
                "handoff_ready": any(e.status == "FUZZ_READY" for e in result.attack_surface_inventory.entries),
                "coverage_outcome": outcome if terminal else None}
    rounds = agent.store.rounds(task_id)
    runs = agent.repository.list_tool_runs(task_id)
    pending = any(run.state in {ToolRunState.RUNNING, ToolRunState.QUEUED} for run in runs)
    with agent.repository._connect() as connection:
        stages = connection.execute("SELECT name, state FROM recon_stages WHERE task_id = ?", (task_id,)).fetchall()
    bootstrap = {name for name, state in stages if state == "COMPLETE"} >= {
        "service_discovery", "web_service_discovery", "technology_fingerprinting"}
    static = not any(s.status == SourceStatus.PENDING for s in agent.repository.list_sources(task_id))
    planning = bool(agent.store.status(task_id)) and all(row["state"] in {"EXECUTED", "FAILED"} for row in rounds)
    boundary = agent.repository.get_authorization(task_id)
    if boundary:
        pending_assets = agent.repository.pending_verification_assets(task_id)
        origin_work = agent.repository.list_origin_work(task_id)
        pending_origins = any(item.status in {"PENDING", "RUNNING"} for item in origin_work)
        checklist = project_checklist_v3(agent.repository.get_task(task_id), agent.repository, agent.service,
                                         finalize=planning and static and not pending and not pending_assets
                                         and not pending_origins)
        checklist_terminal = all(item.status in {"COMPLETE", "BLOCKED", "UNSUPPORTED", "NOT_APPLICABLE", "MANUAL_REVIEW"}
                                 for item in checklist)
        terminal = (bootstrap and static and not pending and not pending_assets and not pending_origins
                    and planning and checklist_terminal
                    and result.attack_surface_inventory is not None
                    and agent.repository.asset_inventory(task_id) is not None)
        if not terminal:
            coverage_outcome = None
        elif (any(item.status == "LIMITED" for item in origin_work)
              or any(source.status in {SourceStatus.LIMITED, SourceStatus.ERROR}
                     for source in agent.repository.list_sources(task_id))
              or result.coverage and any(not item.startswith("handoff:")
                                         for item in result.coverage.limitations)):
            coverage_outcome = "LIMITED"
        elif any(item.status in {"BLOCKED", "UNSUPPORTED"}
                 for item in checklist):
            coverage_outcome = "PARTIAL"
        else:
            coverage_outcome = "COMPLETE"
    else:
        terminal = bootstrap and static and not pending and planning and result.attack_surface_inventory is not None
        coverage_outcome = None
    return {"terminal": terminal, "run_status": "COMPLETED" if terminal else "RUNNING",
            "handoff_ready": any(e.status == "FUZZ_READY" for e in result.attack_surface_inventory.entries),
            "coverage_outcome": coverage_outcome}
