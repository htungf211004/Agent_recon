"""Local UI boundary tests; no provider calls or external targets."""

import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from scripts import recon_ui as ui


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(ui, "OUTPUT", tmp_path)
    monkeypatch.setattr(ui, "chromium_available", lambda: False)
    monkeypatch.setattr(ui, "Settings", lambda **_: SimpleNamespace(
        google_api_key="test-secret-must-not-appear", openai_api_key="", gemini_model="test-model", model_name="test-openai"))
    app = ui.create_app()
    with TestClient(app, base_url="http://127.0.0.1") as connection:
        connection.headers["X-Recon-Token"] = app.state.ui_token
        yield connection


def test_local_ui_never_exposes_keys_and_rejects_untrusted_origin(client):
    page = client.get("/")
    assert page.status_code == 200 and "Local Console" in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    config = client.get("/api/config")
    assert config.json()["providers"]["gemini"]["configured"]
    assert "test-secret-must-not-appear" not in config.text
    assert client.post("/api/lab", headers={"Origin": "https://foreign.example"}).status_code == 403
    assert client.get("/api/config", headers={"X-Recon-Token": "wrong"}).status_code == 403
    assert client.get("/", headers={"Host": "foreign.example"}).status_code == 400


@pytest.mark.parametrize("target", ["ftp://example.com/", "http://127.0.0.1:8080/../secret", "http://user:pass@127.0.0.1/"])
def test_invalid_scope_never_launches_process(client, monkeypatch, target):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid scope reached process dispatch")
    monkeypatch.setattr(ui.subprocess, "Popen", forbidden)
    assert client.post("/api/runs", json={"target": target}).status_code == 422


def test_ui_launch_delegates_to_existing_cli_with_fixed_argv(client, monkeypatch):
    calls = []

    class Worker:
        def poll(self):
            return 0

        def wait(self):
            return 0

    def spawn(args, **kwargs):
        calls.append((args, kwargs))
        return Worker()

    monkeypatch.setattr(ui.subprocess, "Popen", spawn)
    response = client.post("/api/runs", json={"target": "http://127.0.0.1:8080/", "model": "test-model"})
    assert response.status_code == 200
    task_id = response.json()["task_id"]
    args, options = calls[0]
    assert args[:4] == [ui.sys.executable, "-u", "-m", "scripts.run_recon_live"]
    assert args[args.index("--target") + 1] == "http://127.0.0.1:8080/"
    assert "--model=test-model" in args and options["shell"] is False
    assert "test-secret" not in " ".join(args)
    assert client.get("/api/runs/" + task_id).json()["process_status"] == "FINISHED"
    assert client.get(f"/api/runs/{task_id}/files/runner.log").status_code == 404


def test_ui_missing_capability_never_dispatches(client, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("missing capability reached process dispatch")
    monkeypatch.setattr(ui.subprocess, "Popen", forbidden)
    client.app.state.capabilities["browser_explore"] = False
    assert client.post("/api/runs", json={"target": "http://127.0.0.1:8080/", "browser": True}).status_code == 422


def test_evidence_download_requires_matching_manifest_digest(client):
    directory = ui.OUTPUT / "test-run"
    (directory / "evidence").mkdir(parents=True)
    evidence_id = str(uuid4())
    raw = b'<script>alert("untrusted evidence")</script>'
    path = directory / "evidence" / (evidence_id + ".bin")
    path.write_bytes(raw)
    (directory / "evidence-index.json").write_text(json.dumps([
        {"id": evidence_id, "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}]))
    route = f"/api/runs/test-run/evidence/{evidence_id}"
    response = client.get(route)
    assert response.content == raw and response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith("attachment;")
    path.write_bytes(b"corrupt")
    assert client.get(route).status_code == 409
    assert client.get("/api/runs/test-run/files/.env").status_code == 404
    with pytest.raises(ui.HTTPException):
        ui.run_directory("../outside")


def test_embedded_lab_serves_fixed_sources_and_rejects_writes(client):
    url = client.post("/api/lab").json()["url"]
    assert url.startswith("http://127.0.0.1:")
    assert client.post("/api/lab").json()["url"] == url
    with httpx.Client(trust_env=False) as browser:
        for path in ("", "robots.txt", "sitemap.xml", "openapi.json", "app.js", "hidden", "dynamic"):
            assert browser.get(url + path).status_code == 200
        assert browser.head(url + "health").content == b""
        assert browser.post(url + "write").status_code == 501
        assert browser.get(url + ".env").status_code == 404


def test_full_profile_uses_explicit_ports_and_production_scope_validation():
    args = ui.runner_args(ui.Launch(profile="full", target="127.0.0.1", ports="8080,8081"), "test-run")
    assert args[args.index("--ports") + 1] == "8080,8081"
    with pytest.raises(ValueError):
        ui.runner_args(ui.Launch(profile="full", target="127.0.0.1", ports="0"), "test-run")


def test_primary_ui_target_uses_canonical_admission_without_tool_flags():
    args = ui.runner_args(ui.Launch(target="example.test"), "test-run")
    assert args[args.index("--target") + 1] == "example.test"
    assert "--ports" not in args and "--browser" not in args and "--content-discovery" not in args


@pytest.mark.parametrize("domain", [False, True])
def test_real_ui_cli_lab_and_evidence_with_local_provider(client, monkeypatch, domain):
    calls = []

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            state = json.loads(calls[-1]["messages"][-1]["content"])
            if len(calls) == 1:
                decision = {"proposals": [{"kind": "safe_http_probe", "asset_id": state["assets"][0]["asset_id"],
                    "port": state["scope"]["ports"][0], "scheme": "http", "path": "/health",
                    "method": "GET", "rationale": "read local health route", "priority": 1}]}
            else:
                decision = {"proposals": [{"kind": "stop", "reason_code": "NO_SAFE_SUPPORTED_ACTION",
                                          "rationale": "fixture has no further steps", "priority": 1}]}
            payload = json.dumps({"id": "local-completion", "object": "chat.completion", "created": 1,
                                  "model": "local-fixture", "choices": [{"index": 0, "finish_reason": "stop",
                                  "message": {"role": "assistant", "content": json.dumps(decision)}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OPENAI_API_KEY", "local-fixture-key")
    monkeypatch.setenv("OPENAI_BASE_URL", f"http://127.0.0.1:{provider.server_port}/v1")
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "false")
    monkeypatch.setenv("LANGSMITH_TRACING", "false")
    monkeypatch.setattr(ui, "Settings", lambda **_: SimpleNamespace(
        google_api_key="", openai_api_key="local-fixture-key", gemini_model="unused", model_name="local-fixture"))
    try:
        url = client.post("/api/lab").json()["url"]
        if domain:
            monkeypatch.setattr("scripts.run_recon_live.resolve_pin", lambda *_: "127.0.0.1")
            url = url.replace("127.0.0.1", "recon.test")
        response = client.post("/api/runs", json={"target": url, "provider": "openai", "model": "local-fixture"})
        assert response.status_code == 200
        task_id = response.json()["task_id"]
        snapshot = {}
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            snapshot = client.get("/api/runs/" + task_id).json()
            if snapshot["process_status"] == "FINISHED":
                break
            time.sleep(0.1)
        assert snapshot["process_status"] == "FINISHED", snapshot
        assert snapshot["exit_code"] == 0, (ui.OUTPUT / task_id / "runner.log").read_text(errors="replace")
        assert len(calls) == 2
        assert snapshot["summary"]["llm_decisions_recorded"] == 2
        assert snapshot["summary"]["evidence_verified"] > 0
        assert snapshot["summary"]["run_status"] == "COMPLETED"
        assert any(e["canonical_path"] == "/health" for e in snapshot["inventory"]["entries"])
        if domain:
            assert all(e["authority"].startswith("recon.test:") and e["resolved_ip"] == "127.0.0.1"
                       for e in snapshot["inventory"]["entries"])
            # recon.test has no public DNS: resume must recover the stored pin without resolving again.
            command = ui.runner_args(ui.Launch(target=url, provider="openai", model="local-fixture"), task_id)
            index = command.index("--pinned-ip")
            del command[index:index + 2]
            resumed = ui.subprocess.run(command, cwd=ui.ROOT, capture_output=True, timeout=30, shell=False)
            assert resumed.returncode == 0, resumed.stdout.decode(errors="replace")
            assert len(calls) == 2
        evidence_id = snapshot["evidence"][0]["id"]
        assert client.get(f"/api/runs/{task_id}/evidence/{evidence_id}").status_code == 200
        assert client.get(f"/api/runs/{task_id}/files/planning.json").status_code == 200
    finally:
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=2)
