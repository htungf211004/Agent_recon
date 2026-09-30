"""AST guardrails for the frozen Recon execution boundary (no browser required)."""

import ast
from importlib.metadata import version
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLAYWRIGHT_IMPORTS = {"src/recon/browser.py", "src/recon/browser_runtime.py"}
ADAPTER_IMPORTERS = {*PLAYWRIGHT_IMPORTS, "src/recon/bootstrap.py"}
PROCESS_RUNNERS = {"src/recon/adapters.py", "src/recon/browser_runtime.py"}
BROWSER_OPERATIONS = {"launch", "launch_persistent_context", "connect_over_cdp", "new_context", "new_page",
                      "goto", "route", "route_web_socket", "continue_", "connect_to_server"}


def boundary_violations(source: str, path: str) -> list[str]:
    """Resolve import aliases; reject imports, dynamic loaders and direct dispatch."""
    tree = ast.parse(source)
    aliases, errors = {}, []

    def qualified(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return qualified(node.value) + "." + node.attr
        return ""

    for node in ast.walk(tree):
        imports = []
        if isinstance(node, ast.Import):
            imports = [(item.name, item.asname or item.name.split(".")[0], item.name if item.asname else item.name.split(".")[0])
                       for item in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                package = path.removesuffix(".py").split("/")[:-node.level]
                module = ".".join([*package, module]).rstrip(".")
            imports = [(module + "." + item.name, item.asname or item.name, module + "." + item.name)
                       for item in node.names]
        for name, alias, target in imports:
            aliases[alias] = target
            if name.split(".")[0] == "playwright" and path not in PLAYWRIGHT_IMPORTS:
                errors.append("Playwright import outside trusted adapter/runtime")
            if (name == "src.recon.browser" or name.startswith("src.recon.browser.")
                    or name == "src.recon.browser_runtime" or name.startswith("src.recon.browser_runtime.")):
                if path not in ADAPTER_IMPORTERS:
                    errors.append("trusted browser implementation imported into business logic")
            if name.split(".")[0] in {"subprocess", "pty"} and path not in PROCESS_RUNNERS:
                errors.append("process module outside fixed runners")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        leaf = name.rsplit(".", 1)[-1]
        if leaf in {"__import__", "eval", "exec", "import_module"}:
            errors.append("dynamic import/code execution")
        if leaf in {"click", "dblclick", "submit", "requestSubmit", "evaluate", "evaluate_handle", "add_script_tag"}:
            errors.append("interactive or arbitrary browser execution")
        if leaf in BROWSER_OPERATIONS and path not in PLAYWRIGHT_IMPORTS:
            errors.append("browser operation outside trusted runtime")
        if leaf == "send" and path not in {"src/recon/browser_dom.py", "src/recon/browser_response.py"}:
            errors.append("CDP dispatch outside fixed DOM/response guards")
        if leaf == "extract_dom" and path != "src/recon/browser.py":
            errors.append("DOM execution outside browser adapter")
        if path == "src/recon/browser_runtime.py" and leaf in BROWSER_OPERATIONS - {"launch", "new_context"}:
            errors.append("runtime probe must not navigate")
        if name.startswith("subprocess.") and leaf in {"run", "Popen", "call", "check_call", "check_output"}:
            if path not in PROCESS_RUNNERS or leaf != "run":
                errors.append("unapproved process runner")
            shell = next((item.value for item in node.keywords if item.arg == "shell"), None)
            if not isinstance(shell, ast.Constant) or shell.value is not False:
                errors.append("process runner requires explicit shell=False")
        if name in {"os.system", "os.popen", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec"}:
            errors.append("unapproved shell/process execution")
        if name.startswith(("os.exec", "os.spawn")) or name in {"pty.spawn", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            errors.append("unapproved process execution")
    return errors


def test_source_tree_respects_browser_and_process_boundary():
    violations = {}
    for path in sorted((ROOT / "src").rglob("*.py")):
        name = path.relative_to(ROOT).as_posix()
        errors = boundary_violations(path.read_text(encoding="utf-8"), name)
        if errors:
            violations[name] = errors
    assert violations == {}


@pytest.mark.parametrize("path", ["src/recon/agent.py", "src/recon/planner.py", "src/recon/service.py",
                                  "src/recon/discovery.py", "src/recon/browser_discovery.py", "src/recon/policy.py",
                                  "src/contracts/attack_surface.py"])
@pytest.mark.parametrize("source", ["import playwright.sync_api as pw", "from playwright.async_api import async_playwright as start",
                                    "from src.recon.browser import BrowserExploreAdapter as Runner",
                                    "from .browser import BrowserExploreAdapter", "context.new_page().goto(url)",
                                    "session.send('Page.navigate', {'url': url})",
                                    "from src.recon.browser_dom import extract_dom\nextract_dom(session, 1000)",
                                    "import importlib as loader\nloader.import_module('playwright.sync_api')",
                                    "from subprocess import run as dispatch\ndispatch(command)"])
def test_guard_rejects_injected_boundary_bypasses(path, source):
    # Relative imports resolve in the source package; use Recon for the alias case.
    if path == "src/contracts/attack_surface.py" and source.startswith("from .browser"):
        source = "from ..recon.browser import BrowserExploreAdapter"
    assert boundary_violations(source, path)


def test_fixed_process_runners_cannot_enable_shell_or_add_popen():
    for path in PROCESS_RUNNERS:
        assert boundary_violations("import subprocess as sp\nsp.run(command, shell=True)", path)
        assert boundary_violations("from subprocess import Popen as p\np(command)", path)
    runners = []
    for path in PROCESS_RUNNERS:
        tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
        runners.extend(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                       and isinstance(node.func, ast.Attribute) and node.func.attr == "run")
    assert len(runners) == 3  # Fixed tool argv, bounded DNS resolver, and local Chromium probe.


def test_playwright_version_pin_matches_verified_runtime_and_docker():
    assert "playwright==1.63.0" in (ROOT / "requirements.txt").read_text()
    assert version("playwright") == "1.63.0"
    docker = (ROOT / "Dockerfile").read_text()
    assert "python:3.11-slim-bookworm" in docker
    assert "-r requirements.txt" in docker
    assert "python -m playwright install --with-deps chromium" in docker
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in docker
    assert "USER appuser" in docker and "/root/.local" not in docker
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert 'RECON_REQUIRE_CHROMIUM: "1"' in ci
    assert "python -m playwright install --with-deps chromium" in ci
    assert "docker build -t agent-recon-final ." in ci
    assert "docker run --rm agent-recon-final python -m src.recon.browser_runtime --probe" in ci
