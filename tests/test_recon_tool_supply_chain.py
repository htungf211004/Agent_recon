"""Installation rejects partial locks and execution rejects modified templates."""

import json
from pathlib import Path

import pytest

from scripts.install_recon_tools import install
from src.recon.models import Capability, CapabilityRequest, TechnologyScanParams
from src.recon.web_tools import NucleiTechnologyAdapter


def test_install_rejects_partial_lock_before_download(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"tools": {"katana": {}}}))
    with pytest.raises(ValueError, match="incomplete Recon"):
        install(lock, tmp_path / "install")
    assert not (tmp_path / "install").exists()


def test_nuclei_rejects_template_modified_after_review(tmp_path, monkeypatch):
    from src.recon.web_tools import TEMPLATES

    manifest = json.loads((TEMPLATES / "manifest.json").read_text())
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    for filename in manifest["templates"]:
        (tmp_path / filename).write_bytes((TEMPLATES / filename).read_bytes() + b"\n# modified\n")
    monkeypatch.setattr("src.recon.web_tools.TEMPLATES", tmp_path)
    request = CapabilityRequest(id="technology", task_id="task", target_ip="127.0.0.1",
        capability=Capability.TECHNOLOGY_SCAN, parameters=TechnologyScanParams(port=80))
    with pytest.raises(ValueError, match="integrity mismatch"):
        NucleiTechnologyAdapter(None).command(request, "http://127.0.0.1:9999/", "http://127.0.0.1:9999", Path("result.json"))
