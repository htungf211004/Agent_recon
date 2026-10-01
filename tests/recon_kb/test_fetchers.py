import json
from datetime import UTC, datetime

import httpx
import pytest

from src.recon.kb.fetchers import GitFetcher, HTTPDownloader, fetch_osv
from src.recon.kb.utils import sha256_file


def test_http_atomic_download_hash_timeout_and_approved_source(registry, tmp_path):
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, content=b"fixture")
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        downloader = HTTPDownloader(client=client)
        path = tmp_path / "artifact"
        assert downloader.download(registry["PSL"], path) == sha256_file(path)
        assert calls[0].url.host == "publicsuffix.org" and calls[0].extensions["timeout"]["read"] == 30.0
        with pytest.raises(ValueError, match="HTTPS"):
            downloader.download(registry["PSL"], path, trusted_url="https://evil.test")


@pytest.mark.parametrize("mode", ["redirect", "size", "cycle", "error"])
def test_http_bad_redirect_size_and_error_cannot_overwrite_existing(mode, registry, tmp_path):
    def handle(request):
        if mode == "redirect":
            return httpx.Response(302, headers={"location": "https://evil.test/data"})
        if mode == "cycle":
            return httpx.Response(302, headers={"location": str(request.url)})
        if mode == "size":
            return httpx.Response(200, content=b"x" * 20)
        return httpx.Response(500)
    path = tmp_path / "artifact"
    path.write_bytes(b"old")
    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises((ValueError, httpx.HTTPError)):
            HTTPDownloader(client=client).download(registry["PSL"].model_copy(update={"max_response_bytes": 10}), path)
    assert path.read_bytes() == b"old" and not path.with_name("artifact.download").exists()


def test_git_fetch_uses_registry_ref_shallow_sparse_and_captured_sha(monkeypatch, registry, tmp_path):
    commands = []
    def fake(self, destination, *args, input_text=None):
        commands.append((args, input_text))
        if args[0] == "checkout":
            path = destination / "LICENSE"
            path.write_text("fixture")
        return "a" * 40 if args[0] == "rev-parse" else ""
    monkeypatch.setattr(GitFetcher, "_git", fake)
    commit, reports = GitFetcher().fetch(registry["WSTG"], tmp_path)
    assert commit == "a" * 40
    assert any(args == ("fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin", "v4.2") for args, _ in commands)
    assert any("01-Information_Gathering" in text for _, text in commands if text)
    assert reports and (tmp_path / "LICENSE").exists()


def test_osv_pagination_preserves_raw_context_and_requires_identity(registry, tmp_path):
    spec = registry["OSV"].model_copy(update={"package_queries": ({"name": "example", "ecosystem": "npm", "version": "1", "evidence_ref": "ev"},)})
    calls = []
    class Pages:
        def download(self, spec, path, *, payload):
            calls.append(payload)
            path.write_text(json.dumps({"vulns": [], **({"next_page_token": "next"} if len(calls) == 1 else {})}))
    fetch_osv(spec, tmp_path, Pages())
    assert len(calls) == 2 and calls[1]["page_token"] == "next"
    assert len(list(tmp_path.glob("*.context.json"))) == 2
    with pytest.raises(ValueError, match="no operator"):
        fetch_osv(registry["OSV"], tmp_path, Pages())


def test_nvd_pipeline_merges_delta_and_does_not_advance_current_watermark(tmp_path, registry):
    from src.recon.kb.pipeline import IngestionPipeline
    from tests.recon_kb.conftest import FIXTURES

    fixture = json.loads((FIXTURES / "nvd.json").read_text())
    class Pages:
        count = 0
        def download(self, spec, path, *, params):
            self.count += 1
            response = json.loads(json.dumps(fixture))
            response["products"][0]["cpe"]["cpeNameId"] = str(self.count)
            path.write_text(json.dumps(response))
    now = [datetime(2026, 9, 1, tzinfo=UTC)]
    pipeline = IngestionPipeline(tmp_path, registry=registry, http=Pages(), clock=lambda: now[0])
    pipeline.sync("NVD_CPE")
    pipeline.normalize("NVD_CPE")
    pipeline.validate("NVD_CPE")
    pipeline.diff("NVD_CPE")
    original = pipeline.promote("NVD_CPE")
    now[0] = datetime(2026, 10, 1, tzinfo=UTC)
    staged = pipeline.sync("NVD_CPE")
    assert pipeline.store.manifest("NVD_CPE", original.snapshot_id).sync_watermark == original.sync_watermark
    pipeline.normalize("NVD_CPE")
    assert pipeline.validate("NVD_CPE").status == "READY"
    assert len(pipeline.store.records("NVD_CPE", staged.snapshot_id)) == 2
    assert pipeline.store.pointer("NVD_CPE", "CURRENT") == original.snapshot_id
