"""Run a scoped domain, IP or URL Recon mission with durable evidence."""

import argparse
import hashlib
import json
import platform
import re
import sqlite3
import subprocess
from collections import Counter
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from src.config import get_settings
from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.contracts.recon_manual_review import api_manual_review
from src.contracts.recon_planning import ReconPlanningLimits
from src.recon.adaptive_agent import AdaptiveReconAgent
from src.recon.bootstrap import create_recon_agent
from src.recon.checklist import project_checklist
from src.recon.checklist_v2 import VERSION as CHECKLIST_V2_VERSION
from src.recon.checklist_v2 import project_checklist_v2
from src.recon.completion import completion
from src.recon.llm_planner import DeterministicReconPlanner, configured_planner
from src.recon.models import BrowserLimits, Capability, ReconTask
from src.recon.planner import scheme_for_port
from src.recon.scope.admission import admit_target, parse_target
from src.recon.scope.legacy import resolve_pin
from src.recon.scope.legacy import scoped_task as _legacy_scoped_task
from src.recon.scope.models import AuthorizationBoundary


def scoped_task(url: str, task_id: str, *, path_prefix: str | None = None, browser: bool = False,
                ports: tuple[int, ...] | None = None, content_discovery: bool = False, full_profile: bool = False,
                pinned_ip: str | None = None) -> ReconTask:
    return _legacy_scoped_task(url, task_id, path_prefix=path_prefix, browser=browser, ports=ports,
                               content_discovery=content_discovery, full_profile=full_profile,
                               pinned_ip=pinned_ip, resolver=resolve_pin)


def export_run(agent, task_id, directory):
    result = agent.service.snapshot(task_id)
    state = completion(agent, task_id, result)
    result = result.model_copy(update={"worker_status": state["run_status"], "handoff_ready": state["handoff_ready"]})
    (directory / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    (directory / "inventory.json").write_text(result.attack_surface_inventory.model_dump_json(indent=2), encoding="utf-8")
    boundary = agent.repository.get_authorization(task_id)
    asset_inventory = agent.repository.asset_inventory(task_id)
    (directory / "asset-inventory.json").write_text(asset_inventory.model_dump_json(indent=2), encoding="utf-8")
    task = agent.repository.get_task(task_id)
    checklist = (project_checklist_v2(task, agent.repository, agent.service, finalize=state["terminal"])
                 if boundary else project_checklist(task, agent.repository, agent.service))
    (directory / "checklist.json").write_text(json.dumps({
        "version": CHECKLIST_V2_VERSION if boundary else "recon-checklist-v1",
        "items": [item.model_dump(mode="json") for item in checklist],
    }, indent=2), encoding="utf-8")
    (directory / "manual-review.json").write_text(json.dumps({
        "schema_version": "1.0", "items": [item.model_dump(mode="json") for item in api_manual_review(asset_inventory.assets)],
    }, indent=2), encoding="utf-8")
    rows = agent.store.rounds(task_id)
    manifests = [agent.repository.get_evidence(reference).model_dump(mode="json") for reference in result.evidence_ids]
    (directory / "evidence-index.json").write_text(json.dumps(manifests, indent=2), encoding="utf-8")
    planning = [{key: row[key] for key in ("number", "state", "action_count", "error_code")} | {
        key: json.loads(row[key]) if row[key] else None for key in ("context", "decision", "plan", "rejections")
    } for row in rows]
    for row in planning:
        if row["context"]:
            row["context"].pop("knowledge_excerpts", None)
    (directory / "planning.json").write_text(json.dumps(planning, indent=2, ensure_ascii=False), encoding="utf-8")
    verified = 0
    for reference in result.evidence_ids:
        try:
            verified += agent.service.gateway.evidence.read(reference) is not None
        except (ValueError, OSError):
            pass
    summary = {
        **state,
        "task_id": task_id, "output_directory": str(directory.resolve()),
        "planner_id": agent.planner.planner_id,
        "tool_results": dict(Counter(item.status for item in result.tool_results)),
        "evidence_recorded": len(result.evidence_ids), "evidence_verified": verified,
        "routes": len(result.attack_surface_inventory.entries),
        "assets": len(asset_inventory.assets),
        "verified_assets": sum(asset.verification_status == AssetVerificationStatus.VERIFIED
                               for asset in asset_inventory.assets),
        "external_references": sum(asset.scope_status == AssetScopeStatus.OUT_OF_SCOPE
                                   for asset in asset_inventory.assets),
        "manual_review_items": len(api_manual_review(asset_inventory.assets)),
        "limitations": list(result.coverage.limitations) if result.coverage else [],
        "fuzz_ready": sum(item.status == "FUZZ_READY" for item in result.attack_surface_inventory.entries),
        "llm_rounds_recorded": len(rows), "llm_decisions_recorded": sum(bool(row["decision"]) for row in rows),
        "planning_stop_reason": agent.store.status(task_id),
    }
    manifest_path = directory / "run-manifest.json"
    previous = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                timeout=2, check=True, shell=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        commit = "unavailable"
    with agent.repository._connect() as connection:
        schema = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
    now = datetime.now(UTC).isoformat()
    manifest = {"manifest_version": "1.0", "git_commit": commit, "python_version": platform.python_version(),
        "policy_version": task.policy_version, "database_schema_version": schema, "inventory_version": "1.0",
        "asset_schema_version": asset_inventory.schema_version,
        "checklist_version": CHECKLIST_V2_VERSION if boundary else "recon-checklist-v1",
        "scope_model_version": boundary.schema_version if boundary else "1.0",
        "authorized_root": boundary.root.model_dump(mode="json") if boundary else None,
        "derived_bindings": [binding.model_dump(mode="json") for binding in agent.repository.list_bindings(task_id)],
        "retriever_implementation_id": agent.retriever.implementation_id,
        **agent.planner.identity, "planner_fingerprint": agent.planner.planner_id,
        "proposal_schema_hash": agent.planner.identity["decision_schema_hash"],
        "planner_implementation_version": agent.planner.identity["implementation_version"],
        "trusted_scope": task.scope.model_dump(mode="json"), "scope_version": task.scope_version,
        "planning_limits": agent.limits.model_dump(),
        "runtime_capabilities": list(agent.service.gateway.registry.available_capabilities()),
        "started_at": previous.get("started_at", now),
        "finished_at": previous.get("finished_at") or (now if summary["terminal"] else None)}
    # The source digest identifies local edits as well as the last published commit.
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for folder in ("src", "scripts"):
        for path in sorted((root / folder).rglob("*")):
            if path.is_file() and path.suffix in {".py", ".rb", ".yaml", ".txt"}:
                digest.update(path.relative_to(root).as_posix().encode())
                digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    manifest["source_tree_sha256"] = digest.hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (directory / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", help="bare authorized domain, IPv4, or IPv6 (default Recon profile)")
    target_group.add_argument("--url", help="compatibility: authorized HTTP(S) URL")
    target_group.add_argument("--target-ip", help="compatibility: literal IP mission")
    parser.add_argument("--ports", help="explicit comma-separated authorized ports; required with --target-ip")
    parser.add_argument("--pinned-ip", help="trusted fixed IP for the URL hostname; otherwise resolve once at task creation")
    parser.add_argument("--content-discovery", action="store_true", help="authorize bounded packaged-wordlist HEAD discovery")
    parser.add_argument("--task-id", default=None, help="reuse the same ID and arguments to resume")
    parser.add_argument("--path-prefix", help="allowed path prefix; defaults to the URL path")
    parser.add_argument("--browser", action="store_true", help="also allow bounded passive Chromium exploration")
    parser.add_argument("--provider", choices=("openai", "gemini"), default="openai")
    parser.add_argument("--planner", choices=("auto", "deterministic", "llm"), default="auto")
    parser.add_argument("--model", help="override MODEL_NAME or GEMINI_MODEL for this run")
    parser.add_argument("--llm-rounds", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--output-root", type=Path, default=Path("data/live-recon"))
    args = parser.parse_args(argv)
    task_id = args.task_id or "live-" + uuid4().hex[:16]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", task_id):
        parser.error("invalid task-id")
    directory = args.output_root / task_id
    previous = None
    previous_boundary = None
    if (directory / "recon.db").exists():
        # Resume uses the frozen DNS pin, even if the resolver now returns another address.
        with closing(sqlite3.connect((directory / "recon.db").resolve().as_uri() + "?mode=ro", uri=True)) as db:
            row = db.execute("SELECT payload FROM recon_tasks WHERE id = ?", (task_id,)).fetchone()
            previous = ReconTask.model_validate_json(row[0]) if row else None
            if args.target:
                row = db.execute("SELECT payload FROM recon_authorizations WHERE task_id = ?", (task_id,)).fetchone()
                previous_boundary = AuthorizationBoundary.model_validate_json(row[0]) if row else None
    try:
        ports = tuple(int(port) for port in args.ports.split(",")) if args.ports else None
        if args.target:
            if ports or args.pinned_ip or args.path_prefix:
                raise ValueError("--ports, --pinned-ip and --path-prefix are legacy scope options; use a new target profile")
            if previous:
                if previous_boundary is None or previous_boundary.root != parse_target(args.target):
                    raise ValueError("existing task root authorization differs; use a new task-id")
                proposed, boundary = previous, previous_boundary
            else:
                proposed, boundary = admit_target(args.target, task_id)
        else:
            boundary = None
        if args.target_ip and not ports:
            raise ValueError("--target-ip requires --ports")
        if not args.target:
            host = f"[{args.target_ip}]" if args.target_ip and ":" in args.target_ip else args.target_ip
            url = args.url or f"{scheme_for_port(ports[0])}://{host}:{ports[0]}/"
            proposed = scoped_task(url, task_id, path_prefix=args.path_prefix, browser=args.browser,
                ports=ports, content_discovery=args.content_discovery, full_profile=args.target_ip is not None,
                pinned_ip=args.pinned_ip or (previous.scope.web_origin.pinned_ip if previous and previous.scope.web_origin else None))
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
    if args.planner == "llm" and not api_key:
        parser.error(f"{key_name} is missing; configure it locally in .env (never in command arguments)")
    repository, engine = create_recon_agent(directory / "recon.db", directory / "evidence")
    if args.browser and engine.service.gateway.registry.get(Capability.BROWSER_EXPLORE) is None:
        parser.error("Chromium unavailable: install and probe the runtime before using --browser")
    task = repository.get_task(task_id)
    if task is None:
        repository.save_task(proposed)
        if boundary:
            repository.save_authorization(boundary)
            repository.upsert_asset(DiscoveredAsset(
                run_id=proposed.run_id, task_id=proposed.id, root_target=boundary.root.value,
                asset_type=AssetType.HOST if boundary.root.kind == "DOMAIN" else AssetType.IP,
                canonical_value=boundary.root.value, relation=AssetRelation.ROOT,
                discovered_from="operator", scope_status=AssetScopeStatus.IN_SCOPE,
                verification_status=AssetVerificationStatus.CLASSIFIED,
            ))
    elif task.scope != proposed.scope or task.discovery_seeds != proposed.discovery_seeds:
        parser.error("existing task scope/URL differs; use a new task-id")
    engine.browser_limits = BrowserLimits(max_pages=2, max_depth=1, max_requests=8,
        max_runtime_seconds=10, max_response_bytes=65536, max_total_bytes=131072)
    limits = ReconPlanningLimits(max_llm_rounds=args.llm_rounds)
    planner = (configured_planner(model_name=model_name, api_key=api_key,
        base_url=base_url, timeout_seconds=limits.model_timeout_seconds)
        if args.planner == "llm" or args.planner == "auto" and api_key else DeterministicReconPlanner())
    agent = AdaptiveReconAgent(engine, planner, limits)
    export_run(agent, task_id, directory)
    print(f"Running task {task_id}; planner={planner.planner_id}; GET/HEAD only", flush=True)
    try:
        agent.run(task_id)
    finally:
        summary = export_run(agent, task_id, directory)
    completed = summary["terminal"]
    return 0 if completed and summary["llm_decisions_recorded"] and summary["evidence_verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
