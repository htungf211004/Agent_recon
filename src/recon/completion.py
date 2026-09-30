"""Worker terminal state is separate from endpoint readiness and coverage completeness."""

from src.recon.checklist_v2 import project_checklist_v2
from src.recon.execution import ToolRunState
from src.recon.web_models import SourceStatus


def completion(agent, task_id, result):
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
        checklist = project_checklist_v2(agent.repository.get_task(task_id), agent.repository, agent.service,
                                         finalize=planning and static and not pending and not pending_assets)
        checklist_terminal = all(item.status in {"COMPLETE", "BLOCKED", "UNSUPPORTED", "NOT_APPLICABLE", "MANUAL_REVIEW"}
                                 for item in checklist)
        terminal = (bootstrap and static and not pending and not pending_assets and planning and checklist_terminal
                    and result.attack_surface_inventory is not None
                    and agent.repository.asset_inventory(task_id) is not None)
    else:
        terminal = bootstrap and static and not pending and planning and result.attack_surface_inventory is not None
    return {"terminal": terminal, "run_status": "COMPLETED" if terminal else "RUNNING",
            "handoff_ready": any(e.status == "FUZZ_READY" for e in result.attack_surface_inventory.entries)}
