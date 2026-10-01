import json

import pytest

from src.recon.kb.adapters import assetnote_downloads, normalize


def test_assetnote_manifest_cdn_selection_technology_and_api_gates(staged, tmp_path):
    raw, manifest, spec = staged("ASSETNOTE")
    selected = assetnote_downloads(raw, spec)
    assert selected[0]["url"] == "https://wordlists-cdn.assetnote.io/data/technologies/flask.txt"
    record = normalize(raw, manifest, spec, tmp_path, [])[0]
    assert record.constraints.technology_required == "Flask"
    assert not record.constraints.automatic_execution
    data = json.loads((raw / "data/technologies.json").read_text())
    data["data"][0]["Download"] = "<a href='https://wordlists-cdn.assetnote.io.evil.test/flask.txt'>Download</a>"
    (raw / "data/technologies.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="HTTPS"):
        assetnote_downloads(raw, spec)


def test_assetnote_does_not_guess_missing_selection(staged):
    raw, _, spec = staged("ASSETNOTE")
    changed = spec.model_copy(update={"assetnote_selections": ({"manifest": "data/manual.json", "filename": "missing.txt",
                                                             "technology": None, "api_related": False},)})
    with pytest.raises(ValueError, match="missing"):
        assetnote_downloads(raw, changed)
