"""Single-file localhost UI. Run: python -m scripts.recon_ui (from repository root)."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
from collections import Counter
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scripts.run_recon_live import scoped_task
from src.config import Settings
from src.recon.browser_runtime import chromium_available
from src.recon.planner import scheme_for_port
from src.recon.scope.admission import normalize_target_input

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "live-recon"
ARTIFACTS = {"summary.json", "inventory.json", "planning.json", "result.json", "recon-report.json",
             "attack-surface-candidates.json",
             "run-manifest.json", "evidence-index.json", "asset-inventory.json",
             "checklist.json", "manual-review.json"}


class Launch(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    profile: Literal["target", "url", "full"] = "target"
    target: str = Field(min_length=1, max_length=2048)
    ports: str = Field(default="8080", max_length=200)
    path_prefix: str = Field(default="/", min_length=1, max_length=1024)
    provider: Literal["gemini", "openai"] = "gemini"
    model: str = Field(default="", max_length=160, pattern=r"^[A-Za-z0-9._:/-]*$")
    browser: bool = False
    content_discovery: bool = False
    rounds: int = Field(default=32, ge=1, le=128)


def runner_args(spec: Launch, task_id: str) -> list[str]:
    """Validate with the production task builder before launching the existing CLI."""
    profile = spec.profile
    if profile == "target":
        normalized = normalize_target_input(spec.target)
        args = [sys.executable, "-u", "-m", "scripts.run_recon_live",
                "--task-id", task_id, "--output-root", str(OUTPUT),
                "--provider", spec.provider, "--llm-rounds", str(spec.rounds),
                "--target", spec.target]
        if spec.model:
            args.append("--model=" + spec.model)
        if normalized.explicit_origin and normalized.root.kind == "DOMAIN":
            task = scoped_task(spec.target if "://" in spec.target else f"{normalized.scheme}://{spec.target}", task_id)
            args += ["--pinned-ip", task.scope.web_origin.pinned_ip]
        return args
    ports = None
    if profile == "full":
        ip = str(ipaddress.ip_address(spec.target))
        ports = tuple(int(p.strip()) for p in spec.ports.split(","))
        host = f"[{ip}]" if ":" in ip else ip
        url = f"{scheme_for_port(ports[0])}://{host}:{ports[0]}/"
    else:
        url = spec.target
    task = scoped_task(url, task_id, path_prefix=spec.path_prefix, browser=spec.browser,
                       ports=ports, content_discovery=spec.content_discovery, full_profile=profile == "full")
    args = [sys.executable, "-u", "-m", "scripts.run_recon_live",
            "--task-id", task_id, "--output-root", str(OUTPUT),
            "--provider", spec.provider, "--llm-rounds", str(spec.rounds)]
    if ports:
        args += ["--target-ip", spec.target, "--ports", ",".join(map(str, ports)),
                 "--path-prefix", spec.path_prefix]
    else:
        args += ["--target", url]
    if task.scope.web_origin:
        args += ["--pinned-ip", task.scope.web_origin.pinned_ip]
    if spec.model:
        args.append("--model=" + spec.model)
    if spec.browser:
        args.append("--browser")
    if spec.content_discovery:
        args.append("--content-discovery")
    return args


def read_json(path: Path, fallback=None):
    try:
        if path.stat().st_size > 16 * 1024 * 1024:
            return fallback
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fallback  # Exports may be in progress while the worker is running.


def run_directory(task_id: str) -> Path:
    if not task_id or len(task_id) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in task_id):
        raise HTTPException(404, "Run không tồn tại")
    directory = (OUTPUT / task_id).resolve()
    if directory.parent != OUTPUT.resolve() or not directory.is_dir():
        raise HTTPException(404, "Run không tồn tại")
    return directory


def safe_file(directory: Path, name: str) -> Path:
    path = (directory / name).resolve()
    if path.parent != directory.resolve():
        raise HTTPException(404, "File không hợp lệ")
    return path


def progress(directory: Path) -> dict:
    data = {"tools": {}, "stages": [], "rounds": []}
    database = safe_file(directory, "recon.db")
    if not database.exists():
        return data
    try:
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=0.3)) as db:
            data["tools"] = dict(Counter(json.loads(row[0])["state"] for row in db.execute(
                "SELECT payload FROM tool_runs")))
            data["stages"] = [dict(name=name, state=state) for name, state in db.execute(
                "SELECT name, state FROM recon_stages")]
            data["rounds"] = [dict(number=n, state=s, error_code=e) for n, s, e in db.execute(
                "SELECT number, state, error_code FROM recon_planning_rounds ORDER BY number")]
    except (sqlite3.Error, ValueError, KeyError):
        pass
    return data


class LabHandler(BaseHTTPRequestHandler):
    """Only fixed demo content is served; no access to the repository or .env."""

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        pages = {
            "/": ("text/html", '<h1>Recon local lab</h1><a href="/about">About</a>'
                   '<script src="/app.js"></script><form method="post" action="/write"><input name="q"></form>'),
            "/about": ("text/html", '<h1>About</h1><a href="/health">Health</a>'),
            "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /hidden\nSitemap: /sitemap.xml\n"),
            "/sitemap.xml": ("application/xml", '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                             f'<url><loc>http://127.0.0.1:{self.server.server_port}/about</loc></url></urlset>'),
            "/openapi.json": ("application/json", json.dumps({"openapi": "3.0.0", "info": {"title": "Lab", "version": "1"},
                              "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}}})),
            "/app.js": ("text/javascript", "fetch('/health');const p=String.fromCharCode(47)+['dy','namic'].join('');fetch(p);"),
            "/health": ("application/json", '{"ok":true}'),
            "/dynamic": ("application/json", '{"source":"browser"}'),
            "/hidden": ("text/html", "<h1>Discovered path</h1>"),
        }
        mime, text = pages.get(urlsplit(self.path).path, ("text/plain", "Not found"))
        body = text.encode()
        self.send_response(404 if text == "Not found" else 200)
        self.send_header("Content-Type", mime + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, *_):
        pass


def create_app() -> FastAPI:
    token = secrets.token_urlsafe(32)
    processes = {}
    lock = threading.Lock()
    lab = None

    @asynccontextmanager
    async def lifespan(app):
        app.state.capabilities = {"http_probe": True, "http_fetch": True,
                                  "nmap_scan": bool(shutil.which("nmap")), "whatweb": bool(shutil.which("whatweb")),
                                  "content_discovery": bool(shutil.which("ffuf")), "browser_explore": None}
        async def probe():
            app.state.capabilities["browser_explore"] = await asyncio.to_thread(chromium_available)
        pending = asyncio.create_task(probe())
        yield
        await pending
        if lab:
            lab.shutdown()
            lab.server_close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])
    app.state.ui_token = token

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.url.path.startswith("/api/"):
            supplied = request.headers.get("X-Recon-Token", "")
            origin = request.headers.get("origin")
            if not secrets.compare_digest(supplied, token) or (origin and origin != str(request.base_url).rstrip("/")):
                return JSONResponse({"detail": "Local UI session required"}, status_code=403)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                                 "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                                 "Content-Security-Policy": "default-src 'self'; script-src 'nonce-" + token +
                                 "'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
        return response

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE.replace("__TOKEN__", token)

    @app.get("/api/config")
    def config():
        settings = Settings(_env_file=ROOT / ".env")
        return {"capabilities": app.state.capabilities,
                "providers": {"gemini": {"configured": bool(settings.google_api_key), "model": settings.gemini_model},
                              "openai": {"configured": bool(settings.openai_api_key), "model": settings.model_name}},
                "output": str(OUTPUT)}

    @app.post("/api/lab")
    def start_lab():
        nonlocal lab
        with lock:
            if lab is None:
                lab = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
                threading.Thread(target=lab.serve_forever, daemon=True).start()
        return {"url": f"http://127.0.0.1:{lab.server_port}/"}

    @app.post("/api/runs")
    def launch(spec: Launch):
        task_id = "ui-" + datetime.now(UTC).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(4)
        try:
            args = runner_args(spec, task_id)
        except (ValueError, IndexError):
            raise HTTPException(422, "Target không hợp lệ. Nhập domain hoặc địa chỉ IPv4/IPv6 được phép.") from None
        settings = Settings(_env_file=ROOT / ".env")
        if not (settings.google_api_key if spec.provider == "gemini" else settings.openai_api_key):
            raise HTTPException(422, "Thiếu API key của provider trong .env.")
        for enabled, name in ((spec.browser, "browser_explore"), (spec.content_discovery, "content_discovery")):
            if enabled and not app.state.capabilities.get(name):
                raise HTTPException(422, f"Capability chưa sẵn sàng: {name}")
        with lock:
            if any(p.poll() is None for p in processes.values()):
                raise HTTPException(409, "Đang có run hoạt động trong phiên UI này.")
            directory = OUTPUT / task_id
            directory.mkdir(parents=True, exist_ok=False)
            (directory / "ui-request.json").write_text(spec.model_dump_json(indent=2), encoding="utf-8")
            try:
                with (directory / "runner.log").open("wb") as log:
                    worker = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                              shell=False, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
            except OSError:
                (directory / "ui-exit.json").write_text('{"exit_code": -1}', encoding="utf-8")
                raise HTTPException(500, "Không khởi động được runner. Xem runner.log tại thư mục run.") from None
            processes[task_id] = worker

        def monitor():
            code = worker.wait()
            (directory / "ui-exit.json").write_text(json.dumps({"exit_code": code}), encoding="utf-8")
        threading.Thread(target=monitor, daemon=True).start()
        return {"task_id": task_id}

    @app.get("/api/runs")
    def history():
        if not OUTPUT.exists():
            return []
        return [p.name for p in sorted(OUTPUT.iterdir(), key=lambda p: p.name, reverse=True)
                if p.is_dir() and not p.is_symlink()][:50]

    @app.get("/api/runs/{task_id}")
    def snapshot(task_id: str):
        directory = run_directory(task_id)
        worker = processes.get(task_id)
        exit_info = read_json(safe_file(directory, "ui-exit.json"), {})
        code = worker.poll() if worker else exit_info.get("exit_code")
        summary = read_json(safe_file(directory, "summary.json"), {})
        phase = "RUNNING" if worker and code is None else "FINISHED" if code is not None else "UNTRACKED"
        return {"task_id": task_id, "process_status": phase, "exit_code": code,
                "summary": summary, "progress": progress(directory),
                "inventory": read_json(safe_file(directory, "inventory.json"), {}),
                "assets": read_json(safe_file(directory, "asset-inventory.json"), {}),
                "checklist": read_json(safe_file(directory, "checklist.json"), {}),
                "manual_review": read_json(safe_file(directory, "manual-review.json"), {}),
                "report": read_json(safe_file(directory, "recon-report.json"), {}),
                "manifest": read_json(safe_file(directory, "run-manifest.json"), {}),
                "planning": read_json(safe_file(directory, "planning.json"), []),
                "evidence": read_json(safe_file(directory, "evidence-index.json"), []),
                "files": sorted(n for n in ARTIFACTS if safe_file(directory, n).is_file()),
                "directory": str(directory)}

    @app.get("/api/runs/{task_id}/files/{name}")
    def artifact(task_id: str, name: str):
        if name not in ARTIFACTS:
            raise HTTPException(404)
        data = read_json(safe_file(run_directory(task_id), name))
        if data is None:
            raise HTTPException(404, "File chưa sẵn sàng")
        return Response(json.dumps(data, indent=2, ensure_ascii=False), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/runs/{task_id}/evidence/{evidence_id}")
    def evidence(task_id: str, evidence_id: str):
        directory = run_directory(task_id)
        records = read_json(safe_file(directory, "evidence-index.json"), [])
        record = next((r for r in records if r["id"] == evidence_id), None)
        if record is None or len(evidence_id) != 36 or any(c not in "0123456789abcdef-" for c in evidence_id):
            raise HTTPException(404)
        evidence_dir = (directory / "evidence").resolve()
        if evidence_dir.parent != directory:
            raise HTTPException(404)
        path = safe_file(evidence_dir, evidence_id + ".bin")
        try:
            if path.stat().st_size > 262144:
                raise ValueError
            raw = path.read_bytes()
            if len(raw) != record["size_bytes"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise ValueError
        except (OSError, ValueError):
            raise HTTPException(409, "Evidence thiếu hoặc kiểm tra SHA-256 thất bại") from None
        return Response(raw, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{evidence_id}.bin"'})

    return app


PAGE = r'''<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recon · Local Console</title><style>
:root{--ink:#183832;--green:#126d57;--muted:#687b74;--line:#dbe5df;--paper:#f4f7f3}*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--paper);font:14px/1.55 system-ui,sans-serif;color:var(--ink)}
header{background:#143c32;color:white;padding:25px 4%;display:flex;align-items:center;justify-content:space-between}
h1{font-size:25px;margin:0;letter-spacing:-1px}header p{margin:3px 0 0;color:#b7d0c3}.tag{font-size:11px;letter-spacing:2px;border:1px solid #688d7d;padding:7px 12px;border-radius:20px}
main{max-width:1440px;margin:auto;padding:28px 4%;display:grid;grid-template-columns:340px minmax(0,1fr);gap:24px}
.panel{background:white;border:1px solid var(--line);border-radius:14px;padding:23px;box-shadow:0 4px 16px #153e3205}
h2{font-size:17px;margin:0 0 6px}.muted{color:var(--muted);font-size:12px}.eyebrow{font-size:10px;letter-spacing:2px;color:var(--green);font-weight:700;margin-bottom:8px}
label.field{display:block;font-size:12px;font-weight:600;margin-top:17px}input,select,button{font:inherit}
input:not([type=checkbox]),select{width:100%;border:1px solid #ccd9d0;border-radius:7px;padding:10px;margin-top:5px;background:#fff;color:var(--ink)}
input:focus,select:focus,button:focus-visible{outline:2px solid #56aa88;outline-offset:2px}.row{display:flex;gap:12px}.row>*{flex:1;min-width:0}
button{cursor:pointer;border:1px solid var(--line);border-radius:7px;padding:10px 14px;background:white;color:var(--ink);font-weight:600}button:hover{background:#eef5ef}button:disabled{opacity:.5;cursor:not-allowed}
.primary{background:var(--green);color:white;border:0;width:100%;margin-top:20px;padding:13px}.primary:hover{background:#0c5947}.lab{width:100%;margin-top:15px;background:#eff7f0}
.check{display:block;margin-top:12px;font-size:13px}.check input{accent-color:var(--green)}.caps{display:flex;flex-wrap:wrap;gap:5px;margin-top:12px}.chip{border-radius:5px;background:#edf5ee;color:#23674a;padding:3px 7px;font-size:10px}.chip.off{background:#f3efea;color:#897762}
.notice{padding:11px;border-radius:7px;background:#fff5e3;color:#795818;font-size:12px;margin-top:14px;white-space:pre-wrap}.notice:empty{display:none}
.workspace{min-width:0}.topline{display:flex;gap:15px;align-items:center;justify-content:space-between;margin-bottom:18px}.topline select{max-width:310px;margin:0;font-size:12px}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:17px 0}.metric{background:white;border:1px solid var(--line);border-radius:10px;padding:16px}.metric strong{display:block;font-size:26px;font-weight:650;line-height:1.4}.metric span{font-size:11px;color:var(--muted)}
.state{background:#e4eee6;padding:5px 10px;border-radius:6px;font-size:11px;font-weight:700}.state.error{background:#fce9e3;color:#9a4230}
.tabs{display:flex;gap:5px;border-bottom:1px solid var(--line);padding-bottom:12px;margin:16px 0}.tabs button{border:0;font-size:12px}.tabs button.active{background:#e4f0e7;color:var(--green)}
.scroll{overflow:auto;max-height:470px}table{width:100%;border-collapse:collapse;text-align:left;font-size:12px}th{font-size:10px;color:var(--muted);letter-spacing:.6px}td,th{padding:12px 9px;border-bottom:1px solid #edf1ed;vertical-align:top}td.path{word-break:break-word;min-width:140px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 Consolas,monospace;background:#f5f8f4;padding:15px;border-radius:8px;max-height:470px;overflow:auto}
.empty{text-align:center;padding:55px 20px;color:var(--muted)}.empty b{display:block;font-size:17px;color:var(--ink);margin:12px}.downloads{display:flex;gap:7px;flex-wrap:wrap;margin-top:12px}.downloads button{font-size:11px;padding:7px 10px}footer{font-size:11px;color:var(--muted);margin-top:17px;overflow-wrap:anywhere}
@media(max-width:900px){main{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}header{padding:20px}.tag{display:none}.topline{flex-wrap:wrap}.panel{padding:18px}}
</style></head><body>
<header><div><h1>Recon<span style="color:#86c6a5">.</span> Local Console</h1><p>Khảo sát có giới hạn · Quyết định có bằng chứng</p></div><span class="tag">PENTESTSYNDICATE / LOCAL</span></header>
<main><aside class="panel"><div class="eyebrow">01 / MISSION</div><h2>Tạo lượt Recon</h2><div class="muted">Chọn target lab/staging được phép kiểm thử. API key được đọc từ .env trên máy.</div>
<button class="lab" id="lab">＋ Dùng lab localhost có sẵn</button>
<label class="field"><span id="targetLabel">Target</span><input id="target" value="example.test" placeholder="example.test or 10.10.10.5"></label>
<div class="muted">Enter an authorized domain or IP. Recon selects a bounded default profile.</div>
<details><summary>Advanced configuration</summary>
<label class="field">Profile<select id="profile"><option value="target" selected>Default Recon</option><option value="url">Legacy URL</option><option value="full">Legacy IP + ports</option></select></label>
<label class="field" id="portsField" hidden>Ports được phép<input id="ports" value="8080" placeholder="80,443,8080"></label>
<label class="field">Path prefix được phép<input id="path" value="/"></label>
<div class="row"><label class="field">Provider<select id="provider"><option value="gemini">Gemini</option><option value="openai">OpenAI compatible</option></select></label>
<label class="field">LLM rounds<select id="rounds"><option>8</option><option>16</option><option selected>32</option><option>64</option><option>128</option></select></label></div>
<label class="field">Model<input id="model" placeholder="Dùng cấu hình .env"></label><div class="muted" id="keyState"></div>
<label class="check"><input type="checkbox" id="browser" disabled> Cho phép Browser thụ động</label>
<label class="check"><input type="checkbox" id="content" disabled> Cho phép FFUF bounded</label>
</details>
<div class="caps" id="caps"></div><div id="message" class="notice" role="alert"></div>
<button id="start" class="primary" disabled>Start Recon</button>
<p class="muted">Gọi LLM thật, dùng quota của provider. Browser/FFUF chỉ chạy khi có đề xuất hợp lệ. Mỗi lần bấm tạo task mới.</p></aside>
<section class="workspace"><div class="topline"><div><div class="eyebrow">02 / OBSERVATIONS</div><h2>Kết quả & bằng chứng</h2></div><select id="history" aria-label="Lịch sử run"><option value="">Chọn lượt chạy…</option></select></div>
<div class="panel"><div class="topline" style="margin-bottom:0"><span id="runTitle">Chưa có lượt chạy</span><span id="state" class="state">READY</span></div>
<div class="muted" id="progress">Bắt đầu với lab localhost hoặc target IP của bạn.</div><div class="notice" id="runMessage"></div></div>
<div class="metrics"><div class="metric"><strong id="routes">—</strong><span>ENDPOINTS</span></div><div class="metric"><strong id="ready">—</strong><span>FUZZ_READY</span></div><div class="metric"><strong id="proof">—</strong><span>EVIDENCE VERIFIED</span></div><div class="metric"><strong id="decisions">—</strong><span>LLM DECISIONS</span></div><div class="metric"><strong id="score">—</strong><span>COVERAGE %</span></div></div>
<div class="panel"><nav class="tabs" aria-label="Kết quả"><button class="active" data-tab="inventory">Routes</button><button data-tab="assets">Assets</button><button data-tab="candidates">Candidates</button><button data-tab="checklist">Checklist</button><button data-tab="manual">Manual review</button><button data-tab="planning">Planning</button><button data-tab="evidence">Evidence</button><button data-tab="summary">Summary</button></nav>
<div id="view"><div class="empty">◎<b>Từ scope đến evidence</b>Endpoint, quyết định LLM và bằng chứng sẽ xuất hiện ở đây.</div></div>
<div id="downloads" class="downloads"></div></div><footer id="location">HTTP GET/HEAD · Policy/Gateway kiểm soát mọi execution · SQLite lưu lịch sử</footer>
<footer>Đóng tab không hủy run. Giữ cửa sổ terminal chạy đến khi hoàn tất.</footer></section></main>
<script nonce="__TOKEN__">
const token='__TOKEN__', el=id=>document.getElementById(id);let config=null,current='',snapshot=null,tab='inventory',busy=false,active='';
async function api(path,options={}){const r=await fetch('/api/'+path,{...options,headers:{'X-Recon-Token':token,'Content-Type':'application/json',...(options.headers||{})}});if(!r.ok){let d=await r.json().catch(()=>({}));throw Error(typeof d.detail==='string'?d.detail:'Yêu cầu không hợp lệ ('+r.status+')');}return r.json();}
function message(e){el('message').textContent=e.message||e;}
function sync(){if(!config)return;const p=config.providers[el('provider').value];el('keyState').textContent=p.configured?'✓ Đã cấu hình API key':'Thiếu API key trong .env';el('model').placeholder=p.model;el('start').disabled=busy||!!active||!p.configured;el('start').textContent=busy?'Đang chuẩn bị…':active?'Run đang thực thi…':'Start Recon';let domain=false;try{const raw=el('target').value,h=raw.includes('://')?new URL(raw).hostname:raw;domain=!h.includes(':')&&!/^\d{1,3}(\.\d{1,3}){3}$/.test(h);}catch{}el('content').disabled=domain||!config.capabilities.content_discovery;if(el('content').disabled)el('content').checked=false;}
async function refreshConfig(){config=await api('config');el('caps').replaceChildren();for(const [name,ok] of Object.entries(config.capabilities)){const s=document.createElement('span');s.className='chip'+(ok?'':' off');s.textContent=name+(ok===null?' · checking':ok?' ✓':' —');el('caps').append(s);}el('browser').disabled=!config.capabilities.browser_explore;el('content').disabled=!config.capabilities.content_discovery;sync();}
function profile(){const full=el('profile').value==='full';el('portsField').hidden=!full;el('targetLabel').textContent=full?'Authorized IP':el('profile').value==='url'?'Legacy URL':'Target';}
el('profile').onchange=()=>{try{if(el('profile').value==='full'){const u=new URL(el('target').value);el('target').value=u.hostname;el('ports').value=u.port||(u.protocol==='https:'?'443':'80');}else{el('target').value='http://'+el('target').value+':'+el('ports').value.split(',')[0]+'/';}}catch{}profile();sync();};
el('target').oninput=sync;
el('provider').onchange=()=>{el('model').value='';sync();};
el('lab').onclick=async()=>{try{const d=await api('lab',{method:'POST'});el('profile').value='url';el('target').value=d.url;el('path').value='/';profile();el('message').textContent='Lab sẵn sàng: HTML, robots, sitemap, OpenAPI, JS và hidden path.';}catch(e){message(e);}};
async function history(){const ids=await api('runs');el('history').replaceChildren(new Option('Chọn lượt chạy…',''));for(const id of ids)el('history').add(new Option(id,id));el('history').value=current;}
el('history').onchange=async()=>{current=el('history').value;snapshot=null;await poll();};
el('start').onclick=async()=>{busy=true;sync();el('message').textContent='';try{const d=await api('runs',{method:'POST',body:JSON.stringify({profile:el('profile').value,target:el('target').value.trim(),ports:el('ports').value,path_prefix:el('path').value,provider:el('provider').value,model:el('model').value.trim(),browser:el('browser').checked,content_discovery:el('content').checked,rounds:Number(el('rounds').value)})});current=d.task_id;active=current;await history();await poll();}catch(e){message(e);}finally{busy=false;sync();}};
function cell(row,text,cls=''){const td=document.createElement('td');td.className=cls;td.textContent=String(text??'');row.append(td);return td;}
function table(headers){const box=document.createElement('div');box.className='scroll';const t=document.createElement('table'),head=document.createElement('tr');for(const name of headers){const th=document.createElement('th');th.textContent=name;head.append(th);}t.append(head);box.append(t);el('view').replaceChildren(box);return t;}
function jsonView(data){const pre=document.createElement('pre');pre.textContent=JSON.stringify(data,null,2);el('view').replaceChildren(pre);}
async function download(path,name){try{const r=await fetch('/api/runs/'+encodeURIComponent(current)+'/'+path,{headers:{'X-Recon-Token':token}});if(!r.ok){const d=await r.json();throw Error(d.detail||'Không tải được file');}const u=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);}catch(e){message(e);}}
function render(){if(!snapshot)return;const d=snapshot,s=d.summary;el('runTitle').textContent=current;el('state').textContent=d.process_status==='RUNNING'?'RUNNING':d.process_status==='UNTRACKED'?'UNTRACKED':d.exit_code===0?'FINISHED'+(s.coverage_outcome?' · COVERAGE '+s.coverage_outcome:''):'CHECK RESULT';el('state').className='state'+(d.exit_code!==null&&d.exit_code!==0?' error':'');
el('progress').textContent=d.progress.stages.map(x=>x.name+': '+x.state).join(' · ')+' | Tools: '+JSON.stringify(d.progress.tools);
if(d.manifest.authorized_root)el('progress').textContent='Authorized root: '+d.manifest.authorized_root.value+' | '+el('progress').textContent;
el('runMessage').textContent=d.process_status==='UNTRACKED'?'Đây là run lưu trên đĩa; phiên UI này không theo dõi tiến trình của nó. Xem summary và planning.':d.exit_code!==null&&d.exit_code!==0?'Runner kết thúc với mã '+d.exit_code+'. Xem LLM planning/error_code; runner.log nằm trong thư mục run.':'';
for(const [id,key] of [['routes','routes'],['ready','fuzz_ready'],['proof','evidence_verified'],['decisions','llm_decisions_recorded'],['score','coverage_score']])el(id).textContent=s[key]??'—';el('location').textContent=d.directory;
if(tab==='inventory'){const rows=d.inventory.entries||[];if(!rows.length){const p=document.createElement('p');p.className='empty';p.textContent=d.process_status==='RUNNING'?'Đang chạy. Inventory đầy đủ được export khi kết thúc.':'Chưa có endpoint được export.';el('view').replaceChildren(p);}else{const t=table(['METHOD','ROUTE','LIFECYCLE','EVIDENCE']);for(const x of rows){const r=document.createElement('tr');cell(r,x.method);cell(r,x.authority+x.canonical_path,'path');cell(r,x.status);cell(r,x.evidence_refs.length);t.append(r);}}}
else if(tab==='assets'){const t=table(['TYPE','VALUE','SCOPE','VERIFICATION','EVIDENCE']);for(const x of d.assets.assets||[]){const r=document.createElement('tr');cell(r,x.asset_type);cell(r,x.canonical_value,'path');cell(r,x.scope_status);cell(r,x.verification_status);cell(r,(x.discovery_evidence_refs||[]).concat(x.verification_evidence_refs||[]).join(', '),'path');t.append(r);}}
else if(tab==='candidates')jsonView(d.report.candidates||[]);
else if(tab==='checklist'){const t=table(['ITEM','STATUS','FINDING','REASON']);for(const x of d.checklist.items||[]){const r=document.createElement('tr');cell(r,x.id);cell(r,x.status);cell(r,x.finding);cell(r,x.reason);t.append(r);}}
else if(tab==='manual')jsonView(d.manual_review.items||[]);
else if(tab==='planning')jsonView(d.planning.length?d.planning:d.progress.rounds);
else if(tab==='summary')jsonView(s);
else{const t=table(['KIND / ID','BYTES','SHA-256','']);for(const x of d.evidence){const r=document.createElement('tr');cell(r,x.kind+' / '+x.id,'path');cell(r,x.size_bytes);cell(r,x.sha256,'path');const b=document.createElement('button');b.textContent='Tải .bin';b.onclick=()=>download('evidence/'+encodeURIComponent(x.id),x.id+'.bin');cell(r,'').append(b);t.append(r);}}
el('downloads').replaceChildren();for(const name of d.files){const b=document.createElement('button');b.textContent='↓ '+name;b.onclick=()=>download('files/'+name,name);el('downloads').append(b);}}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;document.querySelectorAll('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));render();});
async function poll(){try{if(active&&active!==current){const a=await api('runs/'+active);if(a.process_status!=='RUNNING')active='';}if(current){snapshot=await api('runs/'+encodeURIComponent(current));if(current===active&&snapshot.process_status!=='RUNNING')active='';render();}sync();}catch(e){message(e);}}
async function tick(){await poll();try{await refreshConfig();}catch(e){message(e);}setTimeout(tick,2000);}
(async()=>{try{await refreshConfig();await history();}catch(e){message(e);}tick();})();
</script></body></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    import uvicorn
    print(f"Recon UI: http://127.0.0.1:{args.port} -- keys are read from the repository .env", flush=True)
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port, access_log=False)


if __name__ == "__main__":
    main()
