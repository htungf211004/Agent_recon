import json
from datetime import UTC, datetime

import pytest

from src.recon.kb.adapters import normalize, parse_cpe23
from src.recon.kb.fetchers import fetch_nvd
from src.recon.kb.lookups import cpe_candidates
from src.recon.models import Capability, TechnologyObservation


def test_nvd_cpe_escape_parser_and_uncertain_matches_are_candidates(staged, tmp_path):
    raw, manifest, spec = staged("NVD_CPE")
    records = normalize(raw, manifest, spec, tmp_path, [])
    observation = TechnologyObservation(target_ip="127.0.0.1", name="Example Product", source=Capability.WHATWEB, evidence_id="ev")
    assert cpe_candidates(observation, records)[0]["match_status"] == "CANDIDATE"
    assert parse_cpe23(r"cpe:2.3:a:vendor:foo\:bar:1.0:*:*:*:*:*:*:*")["product"] == "foo:bar"
    with pytest.raises(ValueError):
        parse_cpe23("cpe:bad")


def test_nvd_pagination_and_incremental_watermark_only_after_complete(registry, tmp_path):
    calls = []
    class Pages:
        def download(self, spec, path, *, params):
            calls.append(params)
            path.write_text(json.dumps({"startIndex": params["startIndex"], "totalResults": 2, "products": [{"cpe": {}}]}))
    mark = fetch_nvd(registry["NVD_CPE"], tmp_path, Pages(), watermark="2026-09-01T00:00:00+00:00",
                     clock=lambda: datetime(2026, 10, 1, tzinfo=UTC), pause=lambda _: None)
    assert len(calls) == 2 and calls[1]["startIndex"] == 1
    assert "lastModStartDate" in calls[0] and mark == "2026-10-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="page bound"):
        fetch_nvd(registry["NVD_CPE"].model_copy(update={"max_pages": 1}), tmp_path, Pages(), pause=lambda _: None)
