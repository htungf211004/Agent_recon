"""Run a scoped literal-IP target with the configured real LLM and export evidence refs."""

import argparse
import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from src.config import get_settings
from src.contracts.recon_planning import ReconPlanningLimits
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.bootstrap import create_recon_agent
from src.recon.execution import ExecutionBudget
from src.recon.llm_planner import configured_planner
from src.recon.models import BrowserLimits, Capability, ReconTask, Scope
from src.recon.planner import scheme_for_port
from src.recon.urls import canonical_url, path_allowed, validate_path
from src.recon.web_models import DiscoveryLimits


def scoped_task(url: str, task_id: str, *, path_prefix: str | None = None, browser: bool = False) -> ReconTask:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id):
        raise ValueError("task-id must contain 1-64 letters, digits, hyphens or underscores")
    if urlsplit(url).fragment:
        raise ValueError("URL fragments are not supported")
    target = urlsplit(canonical_url(url))  # Reject hostname, credentials and ambiguous paths.
    if target.scheme != scheme_for_port(target.port):
        raise ValueError("this engine uses HTTPS on 443/8443/9443 and HTTP on other ports")
    prefix = validate_path(path_prefix if path_prefix is not None else target.path)
    if not path_allowed(target.path, (prefix,)):
        raise ValueError("target URL is outside the supplied path prefix")
    capabilities = (Capability.HTTP_FETCH,)
    if browser:
        capabilities += (Capability.BROWSER_EXPLORE, Capability.BROWSER_REQUEST)
    seed = target.path + ("?" + target.query if target.query else "")
    return ReconTask(
        id=task_id, run_id=task_id,
        scope=Scope(allowed_ips=(target.hostname,), allowed_ports=(target.port,),
                    allowed_paths=(prefix,), allowed_methods=("GET", "HEAD"), capabilities=capabilities),
        discovery_seeds=(seed,), expires_at=datetime.now(UTC) + timedelta(minutes=30),
        discovery_limits=DiscoveryLimits(max_rounds=2, max_requests=24, max_sources=16, max_endpoints=64, max_depth=2),
        execution_budget=ExecutionBudget(max_requests=40, max_body_bytes=65536, max_timeout_seconds=30),
    )


def export_run(agent, task_id, directory):
    result = agent.service.snapshot(task_id)
    (directory / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    (directory / "inventory.json").write_text(result.attack_surface_inventory.model_dump_json(indent=2), encoding="utf-8")
    rows = agent.store.rounds(task_id)
    manifests = [agent.repository.get_evidence(reference).model_dump(mode="json") for reference in result.evidence_ids]
    (directory / "evidence-index.json").write_text(json.dumps(manifests, indent=2), encoding="utf-8")
    planning = [{key: row[key] for key in ("number", "state", "action_count")} | {
        key: json.loads(row[key]) if row[key] else None for key in ("context", "decision", "plan", "rejections")
    } for row in rows]
    (directory / "planning.json").write_text(json.dumps(planning, indent=2, ensure_ascii=False), encoding="utf-8")
    verified = 0
    for reference in result.evidence_ids:
        try:
            verified += agent.service.gateway.evidence.read(reference) is not None
        except (ValueError, OSError):
            pass
    summary = {
        "task_id": task_id, "output_directory": str(directory.resolve()),
        "planner_id": agent.planner.planner_id,
        "tool_results": dict(Counter(item.status for item in result.tool_results)),
        "evidence_recorded": len(result.evidence_ids), "evidence_verified": verified,
        "routes": len(result.attack_surface_inventory.entries),
        "fuzz_ready": sum(item.status == "FUZZ_READY" for item in result.attack_surface_inventory.entries),
        "llm_rounds_recorded": len(rows), "llm_decisions_recorded": sum(bool(row["decision"]) for row in rows),
        "planning_stop_reason": agent.store.status(task_id),
    }
    (directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="authorized HTTP(S) URL with a literal IP")
    parser.add_argument("--task-id", default=None, help="reuse the same ID and arguments to resume")
    parser.add_argument("--path-prefix", help="allowed path prefix; defaults to the URL path")
    parser.add_argument("--browser", action="store_true", help="also allow bounded passive Chromium exploration")
    parser.add_argument("--provider", choices=("openai", "gemini"), default="openai")
    parser.add_argument("--model", help="override MODEL_NAME or GEMINI_MODEL for this run")
    parser.add_argument("--llm-rounds", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--output-root", type=Path, default=Path("data/live-recon"))
    args = parser.parse_args(argv)
    task_id = args.task_id or "live-" + uuid4().hex[:16]
    try:
        proposed = scoped_task(args.url, task_id, path_prefix=args.path_prefix, browser=args.browser)
    except ValueError as error:
        parser.error(str(error))
    settings = get_settings()
    if args.provider == "gemini":
        api_key, model_name = settings.google_api_key, args.model or settings.gemini_model
        base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
        key_name = "GOOGLE_API_KEY (or GEMINI_API_KEY)"
    else:
        api_key, model_name = settings.openai_api_key, args.model or settings.model_name
        base_url, key_name = settings.openai_base_url, "OPENAI_API_KEY"
    if not api_key:
        parser.error(f"{key_name} is missing; configure it locally in .env (never in command arguments)")
    directory = args.output_root / task_id
    repository, engine = create_recon_agent(directory / "recon.db", directory / "evidence")
    if args.browser and engine.service.gateway.registry.get(Capability.BROWSER_EXPLORE) is None:
        parser.error("Chromium unavailable: install and probe the runtime before using --browser")
    task = repository.get_task(task_id)
    if task is None:
        repository.save_task(proposed)
    elif task.scope != proposed.scope or task.discovery_seeds != proposed.discovery_seeds:
        parser.error("existing task scope/URL differs; use a new task-id")
    engine.browser_limits = BrowserLimits(max_pages=2, max_depth=1, max_requests=8,
        max_runtime_seconds=10, max_response_bytes=65536, max_total_bytes=131072)
    limits = ReconPlanningLimits(max_llm_rounds=args.llm_rounds)
    planner = configured_planner(model_name=model_name, api_key=api_key,
        base_url=base_url, timeout_seconds=limits.model_timeout_seconds)
    agent = AdaptiveReconAgent(engine, planner, limits)
    print(f"Running task {task_id}; provider={args.provider}; model={model_name}; GET/HEAD only", flush=True)
    try:
        agent.run(task_id)
    finally:
        summary = export_run(agent, task_id, directory)
    completed = summary["planning_stop_reason"] in {"model_stop", "no_valid_actions", "round_limit", "action_limit"}
    return 0 if completed and summary["llm_decisions_recorded"] and summary["evidence_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
