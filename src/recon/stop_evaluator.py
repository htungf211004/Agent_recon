"""Deterministic checks for model-proposed terminal reasons."""

from datetime import UTC, datetime

from src.contracts.recon_planning import StopReason
from src.recon.residual_signals import may_stop


def assess_stop(reason: StopReason, task, context, remaining_actions: int, remaining_requests: int) -> str | None:
    """Return a rejection code, or None when the claimed stop condition is supported."""
    if reason == StopReason.COVERAGE_SUFFICIENT:
        return None if may_stop(context.checklist, context.residual_signals) else "inconsistent_stop_coverage"
    if reason == StopReason.BUDGET_EXHAUSTED:
        expired = task.expires_at <= datetime.now(UTC) if getattr(task, "expires_at", None) else False
        return None if remaining_actions <= 0 or remaining_requests <= 0 or expired else "inconsistent_stop_budget"

    if may_stop(context.checklist, context.residual_signals):
        return "inconsistent_stop_reason"
    if context.residual_signals:
        return "actionable_residual_signal"
    pending = tuple(row for row in context.checklist if row.status == "PENDING")
    in_scope = set(task.scope.capabilities)
    available = set(context.capabilities) & in_scope
    if any(set(row.recommended_capabilities) & available for row in pending):
        return "available_checklist_action"
    if reason == StopReason.SCOPE_BLOCKED:
        unresolved = tuple(row for row in context.checklist
                           if row.status not in {"COMPLETE", "NOT_APPLICABLE"})
        if not unresolved or any(set(row.recommended_capabilities) & in_scope for row in unresolved):
            return "inconsistent_stop_scope"
    return None
