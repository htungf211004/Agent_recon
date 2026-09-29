"""Optional LangGraph stage orchestration over the unchanged deterministic engine."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from src.contracts.recon_planning import ReconPlanningDecision, ReconPlanningLimits
from src.recon.adaptive_projection import project_action
from src.recon.baseline_promotion import BrowserBaselinePromotion
from src.recon.models import Capability, ReconPlan
from src.recon.planning_context import assemble_context
from src.recon.planning_store import ReconPlanningStore
from src.recon.policy import PolicyService
from src.recon.proposal_validator import ReconProposalValidator


class ReconGraphState(TypedDict):
    task_id: str
    planning_round: int
    stop_reason: str | None


class AdaptiveReconAgent:
    def __init__(self, engine, planner, limits: ReconPlanningLimits | None = None):
        self.engine, self.planner = engine, planner
        self.repository, self.service = engine.repository, engine.service
        self.limits = limits or ReconPlanningLimits()
        self.store = ReconPlanningStore(self.repository)
        self.validator = ReconProposalValidator(self.repository, self.service, self.limits)
        graph = StateGraph(ReconGraphState)
        graph.add_node("deterministic_recon", self._deterministic)
        graph.add_node("llm_plan", self._plan)
        graph.add_node("validate_proposals", self._validate)
        graph.add_node("execute_recon_actions", self._execute)
        graph.add_node("refresh_inventory", self._refresh)
        graph.add_edge(START, "deterministic_recon")
        graph.add_edge("deterministic_recon", "llm_plan")
        graph.add_conditional_edges("llm_plan", lambda s: "stop" if s["stop_reason"] else "validate",
                                    {"stop": END, "validate": "validate_proposals"})
        graph.add_edge("validate_proposals", "execute_recon_actions")
        graph.add_edge("execute_recon_actions", "refresh_inventory")
        graph.add_conditional_edges("refresh_inventory", lambda s: "stop" if s["stop_reason"] else "next",
                                    {"stop": END, "next": "llm_plan"})
        self.graph = graph.compile()  # SQLite owns durability; graph state only carries refs.

    def run(self, task_id):
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        self.store.open_session(task, self.limits, self.planner.planner_id)
        self.graph.invoke({"task_id": task_id, "planning_round": 0, "stop_reason": None},
                          config={"recursion_limit": 24})
        return self.service.snapshot(task_id)

    def _deterministic(self, state):
        if not self.store.rounds(state["task_id"]):
            self.engine.run(state["task_id"])
        return {}

    def _plan(self, state):
        task = self.repository.get_task(state["task_id"])
        reason = self.store.status(task.id)
        if reason:
            return {"stop_reason": reason}
        if task.policy_version != PolicyService.VERSION or not task.expires_at.tzinfo or task.expires_at <= datetime.now(UTC):
            self.store.stop(task.id, "stale_or_expired_task")
            return {"stop_reason": "stale_or_expired_task"}
        rounds = self.store.rounds(task.id)
        if rounds and rounds[-1]["state"] in {"DECIDED", "VALIDATED"}:
            return {"planning_round": rounds[-1]["number"]}
        number = len(rounds) + 1
        used = self.store.actions_used(task.id)
        if rounds and rounds[-1]["state"] == "PLANNING":
            # claim recovers expired model leases without generating another call.
            self.store.claim(task.id, number, None, self.limits)
            return {"stop_reason": self.store.status(task.id) or "planning_in_progress"}
        if number > self.limits.max_llm_rounds or used >= self.limits.max_total_llm_actions:
            reason = "round_limit" if number > self.limits.max_llm_rounds else "action_limit"
            self.store.stop(task.id, reason)
            return {"stop_reason": reason}
        if self.repository.budget_usage(task.id) >= task.execution_budget.max_requests:
            self.store.stop(task.id, "request_limit")
            return {"stop_reason": "request_limit"}
        try:
            context = assemble_context(task, self.repository, self.service, self.limits, number, used)
        except ValueError:
            self.store.stop(task.id, "context_limit")
            return {"stop_reason": "context_limit"}
        owner = self.store.claim(task.id, number, context, self.limits)
        if owner is None:
            return {"stop_reason": self.store.status(task.id) or "planning_in_progress"}
        try:
            worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="recon-planning")
            try:
                decision = next(worker.map(self.planner.plan, (context,), timeout=self.limits.model_timeout_seconds))
            finally:
                # A late provider response has no path to storage or target execution.
                worker.shutdown(wait=False, cancel_futures=True)
            if not self.store.decide(task.id, number, owner, decision):
                return {"stop_reason": "model_outcome_unknown"}
        except Exception:
            # Never echo provider errors (credentials/content) or retry malformed/refused responses.
            self.store.fail_model(task.id, number, owner, "model_error")
            return {"stop_reason": "model_error"}
        return {"planning_round": number}

    def _validate(self, state):
        row = self.store.get(state["task_id"], state["planning_round"])
        if row["state"] == "DECIDED":
            task = self.repository.get_task(state["task_id"])
            plan, rejected = self.validator.validate(task, ReconPlanningDecision.model_validate_json(row["decision"]),
                self.limits.max_total_llm_actions - self.store.actions_used(task.id))
            self.store.validate(task.id, row["number"], plan, rejected, self.limits)
        return {}

    def _execute(self, state):
        row = self.store.get(state["task_id"], state["planning_round"])
        if row["state"] == "EXECUTED":
            return {}
        if row["state"] != "VALIDATED":
            return {"stop_reason": "planning_in_progress"}
        plan = ReconPlan.model_validate_json(row["plan"])
        if not plan.actions:
            reason = "model_stop" if '"model_stop"' in row["rejections"] else "no_valid_actions"
            self.store.executed(plan.task_id, row["number"])
            self.store.stop(plan.task_id, reason)
            return {"stop_reason": reason}
        try:
            self.service.run(plan)
        except RuntimeError:
            if any(self.repository.get_tool_result(action.request.id) is None for action in plan.actions):
                return {"stop_reason": "execution_in_progress"}
            raise
        for action in plan.actions:
            project_action(self.repository, self.service, action.request)
        return {}

    def _refresh(self, state):
        task = self.repository.get_task(state["task_id"])
        if not state["stop_reason"] and Capability.HTTP_FETCH in task.scope.capabilities:
            BrowserBaselinePromotion(self.repository, self.engine.planner, self.service).run(task)
        self.service.snapshot(state["task_id"])
        if not state["stop_reason"]:
            self.store.executed(task.id, state["planning_round"])
        return {}
