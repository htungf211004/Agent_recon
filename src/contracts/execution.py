"""Shared execution vocabulary and canonical action authorization identity."""

import hashlib
import json
from enum import StrEnum


class Risk(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


def action_fingerprint(*, run_id: str, task_id: str, target: str, tool: str,
                       parameters: dict, scope_version: str, policy_version: str,
                       scope_fingerprint: str) -> str:
    """Keep request ID separate from the authorization binding."""
    canonical = json.dumps({
        "run_id": run_id, "task_id": task_id, "target": target, "tool": tool,
        "parameters": parameters, "scope_version": scope_version,
        "policy_version": policy_version, "scope_fingerprint": scope_fingerprint,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()
