"""Operator maintenance CLI. Sync never changes CURRENT; promotion requires a recorded diff."""

import argparse
import json
from pathlib import Path

import httpx

from src.recon.kb.coverage import audit_coverage
from src.recon.kb.export import export_artifacts
from src.recon.kb.pipeline import IngestionPipeline
from src.recon.kb.registry import load_registry


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("data/recon_kb"))
    parser.add_argument("--registry", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("sync", "normalize", "validate", "diff", "promote"):
        command = commands.add_parser(name)
        command.add_argument("source_id")
    commands.add_parser("sync-all")
    commands.add_parser("coverage-audit")
    commands.add_parser("export-artifacts")
    args = parser.parse_args(argv)
    pipeline = IngestionPipeline(args.root, registry=load_registry(args.registry) if args.registry else None)
    try:
        if args.command == "sync-all":
            result = pipeline.sync_all()
        elif args.command == "coverage-audit":
            result = audit_coverage()
        elif args.command == "export-artifacts":
            result = export_artifacts(kb_root=args.root)
        else:
            result = getattr(pipeline, args.command)(args.source_id)
        data = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        print(json.dumps(data, indent=2, ensure_ascii=True))
        if isinstance(data, dict) and (data.get("status") in {"QUARANTINED", "FAILED", "FAIL"} or
                                     (args.command == "sync-all" and any(str(value).startswith(("FAILED", "QUARANTINED")) for value in data.values()))):
            return 1
        return 0
    except (ValueError, OSError, RuntimeError, httpx.HTTPError) as error:
        print(json.dumps({"status": "FAILED", "error": type(error).__name__, "message": str(error)[:500]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
