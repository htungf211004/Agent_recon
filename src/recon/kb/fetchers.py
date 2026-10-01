"""Bounded maintenance fetchers. Fixed Git argv and approved HTTPS metadata only."""

import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin

import httpx

from src.recon.kb.registry import SourceSpec, validate_url
from src.recon.kb.utils import atomic_write, contained, sha256_file


class HTTPDownloader:
    def __init__(self, *, client=None, timeout=30.0, redirect_limit=3):
        self.timeout = timeout
        self.redirect_limit = redirect_limit
        self.client = client

    def download(self, spec: SourceSpec, destination: Path, *, trusted_url=None, payload=None, params=None):
        # Secondary URLs are selected by the Assetnote manifest adapter, never a CLI URL option.
        url = validate_url(trusted_url or spec.source_url, spec.approved_hosts)
        context = ssl.create_default_context()
        context.load_default_certs()
        client = self.client or httpx.Client(timeout=self.timeout, follow_redirects=False, verify=context)
        temporary = destination.with_name(destination.name + ".download")
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            for redirect in range(self.redirect_limit + 1):
                with client.stream("POST" if payload is not None else "GET", url, json=payload, params=params,
                                   timeout=self.timeout, follow_redirects=False) as response:
                    if response.is_redirect:
                        if payload is not None or redirect == self.redirect_limit:
                            raise ValueError("redirect limit or API redirect rejected")
                        url = validate_url(urljoin(url, response.headers["location"]), spec.approved_hosts)
                        params = None
                        continue
                    response.raise_for_status()
                    if int(response.headers.get("content-length", "0")) > spec.max_response_bytes:
                        raise ValueError("response too large")
                    size = 0
                    with temporary.open("xb") as stream:
                        for chunk in response.iter_bytes(65536):
                            size += len(chunk)
                            if size > spec.max_response_bytes:
                                raise ValueError("response exceeds size limit")
                            stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, destination)
                    return sha256_file(destination)
            raise ValueError("redirect limit")
        finally:
            temporary.unlink(missing_ok=True)
            if self.client is None:
                client.close()


class GitFetcher:
    def _git(self, destination, *arguments, input_text=None):
        environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
                       "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        tls_options = []
        if os.name == "nt":
            # Windows sandbox tokens can lack Schannel credentials. Use the same trusted Windows CA roots
            # with Git's OpenSSL backend; certificate and hostname verification stay enabled.
            bundle = Path(destination) / ".maintenance-trusted-ca.pem"
            if not bundle.exists():
                certificates = [ssl.DER_cert_to_PEM_cert(item[0]) for store in ("ROOT", "CA")
                                for item in ssl.enum_certificates(store) if item[1] == "x509_asn"]
                atomic_write(bundle, "".join(certificates).encode("ascii"))
            tls_options = ["-c", "http.sslBackend=openssl", "-c", "http.sslCAInfo=" + str(bundle)]
        command = ["git", "-c", "core.hooksPath=", "-c", "protocol.file.allow=never",
                   "-c", "protocol.ext.allow=never", "-c", "core.autocrlf=false",
                   "-c", "core.symlinks=false", "-c", "http.sslVerify=true", *tls_options,
                   "-C", str(destination), *arguments]
        try:
            result = subprocess.run(command, shell=False, check=True, capture_output=True, text=True,
                                    input=input_text, timeout=180, env=environment)
        except (subprocess.SubprocessError, OSError) as error:
            raise RuntimeError("bounded Git metadata fetch failed: " + type(error).__name__) from None
        return result.stdout.strip()

    def fetch(self, spec: SourceSpec, destination: Path):
        spec.require_enabled()
        validate_url(spec.repository, spec.approved_hosts)
        if not spec.paths:
            raise ValueError("Git requires sparse paths")
        reports = []
        with tempfile.TemporaryDirectory(prefix="recon-kb-git-") as checkout:
            root = Path(checkout)
            self._git(root, "init", "--quiet")
            self._git(root, "remote", "add", "origin", spec.repository)
            self._git(root, "sparse-checkout", "init", "--no-cone")
            patterns = "\n".join("/" + path for path in spec.paths) + "\n"
            self._git(root, "sparse-checkout", "set", "--no-cone", "--stdin", input_text=patterns)
            self._git(root, "fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin", spec.ref)
            self._git(root, "checkout", "--detach", "--quiet", "FETCH_HEAD")
            commit = self._git(root, "rev-parse", "HEAD")
            if not re.fullmatch(r"[a-f0-9]{40,64}", commit):
                raise ValueError("invalid upstream commit")
            total = 0
            for name in spec.paths:
                selected = contained(root, name)
                if not selected.exists():
                    reports.append("missing upstream path: " + name)
                    continue
                files = sorted(selected.rglob("*")) if selected.is_dir() else [selected]
                for path in files:
                    if not path.is_file():
                        continue
                    relative = path.relative_to(root).as_posix()
                    path = contained(root, relative)
                    total += path.stat().st_size
                    if total > spec.max_snapshot_bytes or path.stat().st_size > spec.max_response_bytes:
                        raise ValueError("Git snapshot exceeds size bound")
                    output = contained(destination, relative)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, output)
        return commit, reports


def package_query(query: dict) -> dict:
    allowed = {"name", "ecosystem", "purl", "version", "evidence_ref"}
    if set(query) - allowed or not query.get("evidence_ref") or not query.get("version"):
        raise ValueError("OSV requires versioned package/dependency evidence")
    if query.get("purl"):
        if not query["purl"].startswith("pkg:"):
            raise ValueError("invalid PURL")
        package = {"purl": query["purl"]}
    elif query.get("name") and query.get("ecosystem") in {"PyPI", "npm", "Maven", "Go", "NuGet", "crates.io",
                                                         "Packagist", "RubyGems", "Hex", "Pub", "SwiftURL"}:
        package = {"name": query["name"], "ecosystem": query["ecosystem"]}
    else:
        raise ValueError("OSV requires supported package identity; service banners are not packages")
    return {"package": package, "version": query["version"]}


def fetch_nvd(spec, destination, downloader, *, watermark=None, clock=None, pause=time.sleep):
    started = time.monotonic()
    checkpoint_path = destination / ".checkpoint.json"
    if checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if checkpoint.get("watermark") != watermark:
            raise ValueError("NVD checkpoint watermark mismatch")
        end = datetime.fromisoformat(checkpoint["end"])
        windows = [(datetime.fromisoformat(begin) if begin else None,
                    datetime.fromisoformat(finish) if finish else None)
                   for begin, finish in checkpoint["windows"]]
        window_number = checkpoint["window_number"]
        index = checkpoint["index"]
        page_number = checkpoint["page_number"]
        total_bytes = checkpoint["total_bytes"]
    else:
        end = (clock or (lambda: datetime.now(UTC)))()
        start = datetime.fromisoformat(watermark) if watermark else None
        # NVD limits a modified-date window to 120 days. Overlap avoids boundary loss.
        if start:
            start -= timedelta(seconds=1)
        windows = []
        while start and start < end:
            finish = min(start + timedelta(days=120), end)
            windows.append((start, finish))
            start = finish
        if not windows:
            windows = [(None, None)] if watermark is None else []
        total_bytes, page_number, window_number, index = 0, 0, 0, 0

    def save_checkpoint():
        atomic_write(checkpoint_path, json.dumps({
            "watermark": watermark, "end": end.isoformat(),
            "windows": [[begin.isoformat() if begin else None, finish.isoformat() if finish else None]
                        for begin, finish in windows],
            "window_number": window_number, "index": index,
            "page_number": page_number, "total_bytes": total_bytes,
        }, sort_keys=True).encode())

    while window_number < len(windows):
        begin, finish = windows[window_number]
        while True:
            if page_number >= spec.max_pages:
                raise ValueError("NVD page bound reached; watermark was not advanced")
            if page_number and time.monotonic() - started >= spec.max_sync_seconds:
                save_checkpoint()
                raise RuntimeError(f"NVD PARTIAL_SYNC checkpoint at page {page_number}, cursor {index}; "
                                   "rerun sync NVD_CPE to resume")
            params = {"resultsPerPage": 2000, "startIndex": index}
            if begin:
                params.update(lastModStartDate=begin.isoformat(), lastModEndDate=finish.isoformat())
            if page_number:
                pause(spec.request_delay_seconds)
            path = destination / f"page-{page_number:05d}.json"
            for attempt in range(spec.max_retries):
                try:
                    downloader.download(spec, path, params=params)
                    break
                except (httpx.HTTPError, OSError):
                    if attempt + 1 == spec.max_retries:
                        save_checkpoint()
                        raise
                    pause(min(spec.request_delay_seconds * (attempt + 1), 30))
            total_bytes += path.stat().st_size
            if total_bytes > spec.max_snapshot_bytes:
                raise ValueError("NVD snapshot size bound reached")
            value = json.loads(path.read_text(encoding="utf-8"))
            count = len(value["products"])
            if value["startIndex"] != index or not isinstance(value["totalResults"], int):
                raise ValueError("NVD pagination mismatch")
            page_number += 1
            index += count
            save_checkpoint()
            if index >= value["totalResults"]:
                break
            if not count:
                raise ValueError("NVD empty incomplete page")
        window_number += 1
        index = 0
        save_checkpoint()
    if not page_number:
        atomic_write(destination / "page-00000.json", b'{"products": [], "totalResults": 0, "startIndex": 0}')
    checkpoint_path.unlink(missing_ok=True)
    return end.isoformat()


def fetch_osv(spec, destination, downloader):
    if not spec.package_queries:
        raise ValueError("OSV has no operator-approved package evidence queries")
    total_bytes = 0
    for query_index, query in enumerate(spec.package_queries):
        request = package_query(query)
        token, seen = None, set()
        for page in range(spec.max_pages):
            path = destination / f"query-{query_index:04d}-page-{page:04d}.json"
            downloader.download(spec, path, payload=request | ({"page_token": token} if token else {}))
            total_bytes += path.stat().st_size
            if total_bytes > spec.max_snapshot_bytes:
                raise ValueError("OSV snapshot too large")
            response = json.loads(path.read_text(encoding="utf-8"))
            # Retain exact response bytes; context lives in a separate raw artifact.
            atomic_write(path.with_suffix(".context.json"), json.dumps(query).encode())
            token = response.get("next_page_token")
            if not token:
                break
            if token in seen:
                raise ValueError("OSV repeated page token")
            seen.add(token)
        else:
            raise ValueError("OSV pagination incomplete")
