"""SQLite is authoritative for planning rounds, frozen decisions and action budgets."""

import json
import sqlite3
from datetime import timedelta
from uuid import uuid4

from src.recon.policy import PolicyService


class ReconPlanningStore:
    def __init__(self, repository):
        self.repository = repository

    def _connect(self):
        connection = sqlite3.connect(self.repository.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def open_session(self, task, limits, planner_id, retriever_id="noop-v1", *, execution_mode="deterministic_fallback"):
        config = json.dumps({"limits": limits.model_dump(), "planner_id": planner_id,
                             "retriever_id": retriever_id, "execution_mode": execution_mode}, sort_keys=True)
        binding = PolicyService.scope_fingerprint(task)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT OR IGNORE INTO recon_planning_sessions VALUES (?, ?, ?, NULL)",
                               (task.id, binding, config))
            row = connection.execute("SELECT * FROM recon_planning_sessions WHERE task_id = ?", (task.id,)).fetchone()
            if row["config"] != config or row["binding"] != binding:
                raise ValueError("planning session configuration or trusted task changed")

    def status(self, task_id):
        with self._connect() as connection:
            row = connection.execute("SELECT stop_reason FROM recon_planning_sessions WHERE task_id = ?", (task_id,)).fetchone()
            return row[0] if row else None

    def stop(self, task_id, reason):
        with self._connect() as connection:
            connection.execute("UPDATE recon_planning_sessions SET stop_reason = COALESCE(stop_reason, ?) WHERE task_id = ?",
                               (reason, task_id))

    def rounds(self, task_id):
        with self._connect() as connection:
            return tuple(dict(row) for row in connection.execute(
                "SELECT * FROM recon_planning_rounds WHERE task_id = ? ORDER BY number", (task_id,)))

    def planning_rejections(self, task_id):
        return tuple(json.loads(row["rejections"]) for row in self.rounds(task_id) if row["rejections"])

    def get(self, task_id, number):
        return next((row for row in self.rounds(task_id) if row["number"] == number), None)

    def actions_used(self, task_id):
        return sum(row["action_count"] for row in self.rounds(task_id))

    def claim(self, task_id, number, context, limits):
        """One model call per round. Unknown outcomes are never retried after lease expiry."""
        now = self.repository.clock()
        owner = str(uuid4())
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            session = connection.execute("SELECT stop_reason FROM recon_planning_sessions WHERE task_id = ?", (task_id,)).fetchone()
            if session is None or session[0]:
                return None
            rows = list(connection.execute("SELECT * FROM recon_planning_rounds WHERE task_id = ? ORDER BY number", (task_id,)))
            if rows and rows[-1]["state"] != "EXECUTED":
                row = rows[-1]
                if row["state"] == "PLANNING" and row["expires_at"] <= now.isoformat():
                    connection.execute("UPDATE recon_planning_rounds SET state = 'FAILED' WHERE task_id = ? AND number = ?",
                                       (task_id, row["number"]))
                    connection.execute("UPDATE recon_planning_sessions SET stop_reason = 'model_outcome_unknown' WHERE task_id = ?",
                                       (task_id,))
                return None
            if (number > limits.max_llm_rounds or number != len(rows) + 1
                    or sum(row["action_count"] for row in rows) >= limits.max_total_llm_actions):
                return None
            connection.execute("""INSERT INTO recon_planning_rounds
                (task_id, number, state, owner, expires_at, context) VALUES (?, ?, 'PLANNING', ?, ?, ?)""",
                (task_id, number, owner, (now + timedelta(seconds=120)).isoformat(), context.model_dump_json()))
        return owner

    def decide(self, task_id, number, owner, decision):
        with self._connect() as connection:
            cursor = connection.execute("""UPDATE recon_planning_rounds SET state = 'DECIDED', decision = ?
                WHERE task_id = ? AND number = ? AND owner = ? AND state = 'PLANNING' AND expires_at > ?
                AND EXISTS (SELECT 1 FROM recon_planning_sessions WHERE task_id = ? AND stop_reason IS NULL)""",
                (decision.model_dump_json(), task_id, number, owner, self.repository.clock().isoformat(), task_id))
            return cursor.rowcount == 1

    def fail_model(self, task_id, number, owner, reason, error_code="MODEL_ERROR"):
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("UPDATE recon_planning_rounds SET state = 'FAILED', error_code = ? WHERE task_id = ? AND number = ? AND owner = ? AND state = 'PLANNING'",
                                        (error_code, task_id, number, owner))
            if cursor.rowcount:
                connection.execute("UPDATE recon_planning_sessions SET stop_reason = COALESCE(stop_reason, ?) WHERE task_id = ?",
                                   (reason, task_id))

    def validate(self, task_id, number, plan, rejections, limits):
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            used = connection.execute("SELECT COALESCE(SUM(action_count), 0) FROM recon_planning_rounds WHERE task_id = ?", (task_id,)).fetchone()[0]
            if used + len(plan.actions) > limits.max_total_llm_actions:
                return False
            cursor = connection.execute("""UPDATE recon_planning_rounds SET state = 'VALIDATED', plan = ?, rejections = ?, action_count = ?
                WHERE task_id = ? AND number = ? AND state = 'DECIDED'""",
                (plan.model_dump_json(), json.dumps(rejections), len(plan.actions), task_id, number))
            return cursor.rowcount == 1

    def executed(self, task_id, number):
        with self._connect() as connection:
            connection.execute("UPDATE recon_planning_rounds SET state = 'EXECUTED' WHERE task_id = ? AND number = ? AND state = 'VALIDATED'",
                               (task_id, number))
