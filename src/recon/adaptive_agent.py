"""Autonomous bounded Recon loop with an explicit deterministic fallback."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from src.contracts.recon_planning import ReconPlanningContext, ReconPlanningDecision, ReconPlanningLimits
from src.recon.adaptive_projection import project_action
from src.recon.asset_verification import AssetVerifier
from src.recon.baseline_promotion import BrowserBaselinePromotion
from src.recon.coverage_evaluator import CoverageEvaluator, score_coverage
from src.recon.deterministic_coverage import DeterministicCoverageExecutor
from src.recon.external_osint import ExternalOsintExecutor
from src.recon.models import Capability, ReconPlan
from src.recon.offline_phase import OfflineAnalysisExecutor
from src.recon.origin_recon import OriginReconCoordinator
from src.recon.planning_context import assemble_context
from src.recon.planning_store import ReconPlanningStore
from src.recon.policy import PolicyService
from src.recon.proposal_validator import ReconProposalValidator
from src.recon.protocol_phase import ProtocolCoverageExecutor
from src.recon.rag.retriever import NoopKnowledgeRetriever
from src.recon.residual_signals import may_stop, residual_signals


class ReconGraphState(TypedDict):
    task_id: str
    planning_round: int
    stop_reason: str | None


class AdaptiveReconAgent:
    def __init__(self, engine, planner, limits: ReconPlanningLimits | None = None, retriever=None,
                 *, execution_mode=None):
        self.engine, self.planner = engine, planner
        self.repository, self.service = engine.repository, engine.service
        self.execution_mode = execution_mode or getattr(planner, "execution_mode", "llm")
        if self.execution_mode not in {"llm", "deterministic_fallback"}:
            raise ValueError("unknown Recon execution mode")
        self.limits = limits or (ReconPlanningLimits(max_llm_rounds=2, max_total_llm_actions=8)
                                if self.execution_mode == "deterministic_fallback" else ReconPlanningLimits())
        self.retriever = retriever or NoopKnowledgeRetriever()
        self.store = ReconPlanningStore(self.repository)
        self.validator = ReconProposalValidator(self.repository, self.service, self.limits)
        self.coverage_evaluator = CoverageEvaluator(self.repository, self.service)
        if self.execution_mode == "llm":
            self.graph = self._llm_graph()
            return
        graph = StateGraph(ReconGraphState)
        graph.add_node("load_task", lambda state: {})
        graph.add_node("external_osint", self._external_osint)
        for name in ("service_discovery", "web_service_discovery", "technology_fingerprinting"):
            graph.add_node(name, self._stage(name))
        graph.add_node("static_discovery", self._static)
        graph.add_node("refresh_inventory", lambda state: self._bootstrap_refresh(state))
        graph.add_node("verify_assets", self._verify_assets)
        graph.add_node("recon_derived_origins", self._derived_origins)
        graph.add_node("mandatory_coverage", self._mandatory_coverage)
        graph.add_node("offline_analysis", self._offline_analysis)
        graph.add_node("protocol_discovery", self._protocol_discovery)
        graph.add_node("llm_plan", self._plan)
        graph.add_node("validate_proposals", self._validate)
        graph.add_node("execute_recon_actions", self._execute)
        graph.add_node("refresh_adaptive_inventory", self._refresh)
        stages = [START, "load_task", "external_osint", "service_discovery", "web_service_discovery",
                  "technology_fingerprinting", "static_discovery", "refresh_inventory", "verify_assets",
                  "recon_derived_origins", "mandatory_coverage", "protocol_discovery",
                  "offline_analysis", "llm_plan"]
        for before, after in zip(stages, stages[1:]):
            graph.add_edge(before, after)
        graph.add_conditional_edges("llm_plan", lambda s: "stop" if s["stop_reason"] else "validate",
                                    {"stop": END, "validate": "validate_proposals"})
        graph.add_edge("validate_proposals", "execute_recon_actions")
        graph.add_edge("execute_recon_actions", "refresh_adaptive_inventory")
        graph.add_conditional_edges("refresh_adaptive_inventory", lambda s: "stop" if s["stop_reason"] else "next",
                                    {"stop": END, "next": "verify_assets"})
        self.graph = graph.compile()  # SQLite owns durability; graph state only carries refs.

    def _llm_graph(self):
        graph = StateGraph(ReconGraphState)
        graph.add_node("load_state", self._load_state)
        graph.add_node("evaluate_coverage", self._evaluate_coverage)
        graph.add_node("llm_plan", self._plan)
        graph.add_node("validate", self._validate)
        graph.add_node("execute", self._execute)
        graph.add_node("normalize", self._refresh)
        graph.add_edge(START, "load_state")
        graph.add_edge("load_state", "evaluate_coverage")
        graph.add_conditional_edges("evaluate_coverage", lambda s: "stop" if s["stop_reason"] else "plan",
                                    {"stop": END, "plan": "llm_plan"})
        graph.add_conditional_edges("llm_plan", lambda s: "stop" if s["stop_reason"] else "validate",
                                    {"stop": END, "validate": "validate"})
        graph.add_edge("validate", "execute")
        graph.add_conditional_edges("execute", lambda s: "stop" if s["stop_reason"] else "normalize",
                                    {"stop": END, "normalize": "normalize"})
        graph.add_conditional_edges("normalize", lambda s: "stop" if s["stop_reason"] else "next",
                                    {"stop": END, "next": "evaluate_coverage"})
        return graph.compile()

    def _load_state(self, state):
        from src.recon.loop_projection import ensure_root_asset
        ensure_root_asset(self.repository, self.repository.get_task(state["task_id"]))
        return {}

    def _evaluate_coverage(self, state):
        if self.store.status(state["task_id"]):
            return {"stop_reason": self.store.status(state["task_id"])}
        rounds = self.store.rounds(state["task_id"])
        if rounds and rounds[-1]["state"] != "EXECUTED":
            return {}
        task = self.repository.get_task(state["task_id"])
        rows = self.coverage_evaluator.project(task)
        signals = residual_signals(task, self.repository, self.service)
        if rounds and may_stop(rows, signals):
            self.store.stop(task.id, "coverage_complete")
            return {"stop_reason": "coverage_complete"}
        return {}

    def run(self, task_id):
        task = self.repository.get_task(task_id)
        if task is None:
            raise ValueError("unknown Recon task")
        self.store.open_session(task, self.limits, self.planner.planner_id, self.retriever.implementation_id,
                                execution_mode=self.execution_mode)
        self.graph.invoke({"task_id": task_id, "planning_round": 0, "stop_reason": None},
                          config={"recursion_limit": max(48, self.limits.max_llm_rounds * 6 + 16)})
        from src.recon.completion import completion
        result = self.service.snapshot(task_id)
        state = completion(self, task_id, result)
        if state["terminal"] and not state["handoff_ready"] and result.coverage:
            coverage = result.coverage.model_copy(update={"limitations": tuple(sorted(set(
                (*result.coverage.limitations, "handoff:no_fuzz_ready"))))})
            self.repository.save_coverage(coverage)
            result = result.model_copy(update={"coverage": coverage})
        final_task = self.repository.get_task(task_id)
        final_checklist = self.coverage_evaluator.project(final_task, finalize=state["terminal"])
        final_signals = residual_signals(final_task, self.repository, self.service)
        from src.recon.candidate_synthesis import synthesize_candidates
        candidates = synthesize_candidates(final_task, result, self.repository, self.service, self.store)
        result = result.model_copy(update={"worker_status": state["run_status"],
                                           "handoff_ready": state["handoff_ready"],
                                           "coverage_outcome": state["coverage_outcome"],
                                           "checklist": tuple(row.model_dump(mode="json") for row in final_checklist),
                                           "coverage_score": score_coverage(final_checklist).score,
                                           "mandatory_resolved": score_coverage(final_checklist).mandatory_resolved,
                                           "residual_signals": tuple(row.model_dump(mode="json") for row in final_signals),
                                           "attack_surface_candidates": candidates,
                                           "execution_mode": self.execution_mode,
                                           "stop_reason": self.store.status(task_id)})
        self.repository.save_recon_result(result)
        return result

    def _stage(self, name):
        def run(state):
            if not self.store.rounds(state["task_id"]):
                getattr(self.engine, "run_" + name)(state["task_id"])
            return {}
        return run

    def _external_osint(self, state):
        task = self.repository.get_task(state["task_id"])
        if not self.store.rounds(task.id):
            ExternalOsintExecutor(self.repository, self.service.gateway).run(task)
        return {}

    def _static(self, state):
        from src.recon.sensing import ReconSensing
        task = self.repository.get_task(state["task_id"])
        if not self.store.rounds(task.id):
            self.engine.run_static_discovery(task.id, ReconSensing(self.engine).verified_origins(task))
        return {}

    def _bootstrap_refresh(self, state):
        self.engine.refresh_inventory(state["task_id"])
        return {}

    def _verify_assets(self, state):
        task = self.repository.get_task(state["task_id"])
        AssetVerifier(self.repository, self.service).verify(task)
        return {}

    def _derived_origins(self, state):
        task = self.repository.get_task(state["task_id"])
        if self.repository.get_authorization(task.id):
            OriginReconCoordinator(self.repository, self.service, self.engine.planner).run(task)
        return {}

    def _mandatory_coverage(self, state):
        task = self.repository.get_task(state["task_id"])
        DeterministicCoverageExecutor(self.engine).run(task)
        return {}

    def _offline_analysis(self, state):
        task = self.repository.get_task(state["task_id"])
        OfflineAnalysisExecutor(self.repository, self.service.gateway).run(task)
        return {}

    def _protocol_discovery(self, state):
        task = self.repository.get_task(state["task_id"])
        ProtocolCoverageExecutor(self.repository, self.service, self.engine).run(task)
        return {}

    def _plan(self, state):
        task = self.repository.get_task(state["task_id"])
        from src.recon.execution import ToolRunState
        from src.recon.web_models import SourceStatus
        self.repository.recover_expired_runs(task.id)
        if (any(run.state in {ToolRunState.RUNNING, ToolRunState.QUEUED} for run in self.repository.list_tool_runs(task.id))
                or self.execution_mode == "deterministic_fallback" and any(
                    s.status == SourceStatus.PENDING for s in self.repository.list_sources(task.id))):
            return {"stop_reason": "execution_in_progress"}
        reason = self.store.status(task.id)
        if reason:
            return {"stop_reason": reason}
        if task.policy_version != PolicyService.VERSION or not task.expires_at.tzinfo or task.expires_at <= datetime.now(UTC):
            self.store.stop(task.id, "stale_or_expired_task")
            return {"stop_reason": "stale_or_expired_task"}
        rounds = self.store.rounds(task.id)
        if rounds and rounds[-1]["state"] == "EXECUTED" and rounds[-1]["plan"]:
            previous = ReconPlan.model_validate_json(rounds[-1]["plan"])
            if not previous.actions:
                rejected = rounds[-1]["rejections"] or ""
                if self.execution_mode == "deterministic_fallback" or '"model_stop"' in rejected or (
                        len(rounds) >= 3 and all(row["plan"] and not ReconPlan.model_validate_json(
                            row["plan"]).actions for row in rounds[-3:])):
                    reason = "model_stop" if '"model_stop"' in rejected else "no_valid_actions"
                    self.store.stop(task.id, reason)
                    return {"stop_reason": reason}
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
            context = assemble_context(task, self.repository, self.service, self.limits, number, used, self.retriever)
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
        except Exception as error:
            from src.recon.llm_planner import model_error_code
            # Never echo provider errors (credentials/content) or retry malformed/refused responses.
            self.store.fail_model(task.id, number, owner, "model_error", model_error_code(error))
            return {"stop_reason": "model_error"}
        return {"planning_round": number}

    def _validate(self, state):
        row = self.store.get(state["task_id"], state["planning_round"])
        if row["state"] == "DECIDED":
            task = self.repository.get_task(state["task_id"])
            context = ReconPlanningContext.model_validate_json(row["context"])
            plan, rejected = self.validator.validate(task, ReconPlanningDecision.model_validate_json(row["decision"]),
                self.limits.max_total_llm_actions - self.store.actions_used(task.id),
                (ref.knowledge_id for ref in context.knowledge_refs),
                may_stop=may_stop(context.checklist, context.residual_signals) if self.execution_mode == "llm" else None,
                stop_context=context if self.execution_mode == "llm" else None)
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
            if reason == "model_stop" or self.execution_mode == "deterministic_fallback":
                self.store.stop(plan.task_id, reason)
                return {"stop_reason": reason}
            return {}
        try:
            self.service.run(plan)
        except RuntimeError:
            if any(self.repository.get_tool_result(action.request.id) is None for action in plan.actions):
                return {"stop_reason": "execution_in_progress"}
            raise
        for action in plan.actions:
            project_action(self.repository, self.service, action.request)
            if self.execution_mode == "llm":
                from src.recon.loop_projection import normalize_action
                normalize_action(self.repository, self.service, action.request)
        return {}

    def _refresh(self, state):
        from src.recon.content_discovery import baseline_content
        task = self.repository.get_task(state["task_id"])
        if (self.execution_mode == "deterministic_fallback" and not state["stop_reason"]
                and Capability.HTTP_FETCH in task.scope.capabilities):
            BrowserBaselinePromotion(self.repository, self.engine.planner, self.service).run(task)
            baseline_content(self.repository, self.service, task)
        self.service.snapshot(state["task_id"])
        from src.recon.execution import ToolRunState
        if any(run.state in {ToolRunState.RUNNING, ToolRunState.QUEUED} for run in self.repository.list_tool_runs(task.id)):
            return {"stop_reason": "execution_in_progress"}
        if not state["stop_reason"]:
            self.store.executed(task.id, state["planning_round"])
        return {}
