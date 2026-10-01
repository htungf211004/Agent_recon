import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.contracts.recon_kb import IngestionStatus, SourceManifest
from src.recon.kb.adapters import ADAPTER_VERSION, SECLISTS_PATHS, WSTG_ROOT
from src.recon.kb.pipeline import IngestionPipeline
from src.recon.kb.registry import load_registry
from src.recon.kb.utils import artifact_hashes, tree_hash

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "recon_kb"


def copy_fixture(source_id, destination):
    mappings = {
        "WSTG": {f"{WSTG_ROOT}/{number:02d}-scenario.md": f"wstg-{number:02d}.md" for number in range(1, 11)},
        "SECLISTS": {name: "seclists.txt" for name in SECLISTS_PATHS},
        "CISA_KEV": {"known_exploited_vulnerabilities.json": "kev.json",
                     "known_exploited_vulnerabilities_schema.json": "kev.schema.json"},
        "NUCLEI_META": {"http/cves/example.yaml": "nuclei.yaml"},
        "PSL": {"public_suffix_list.dat": "psl.dat"},
        "IANA_WELL_KNOWN": {"well-known-uris.csv": "well-known.csv"},
        "IANA_PORTS": {"service-names-port-numbers.csv": "ports.csv"},
        "NVD_CPE": {"page-00000.json": "nvd.json"},
        "CWE": {"cwec_latest.xml.zip": "cwe.xml.zip"},
        "OSV": {"query-0000-page-0000.json": "osv.json", "query-0000-page-0000.context.json": "osv.context.json"},
        "ASSETNOTE": {"data/technologies.json": "assetnote.json", "data/manual.json": "assetnote.manual.json",
                      "downloads/flask.txt": "seclists.txt"},
        "KATANA": {"README.md": "tool.md"}, "AMASS_OAM": {"docs/README.md": "tool.md"},
    }
    for output, input_name in mappings[source_id].items():
        path = destination / output
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / input_name, path)


class FixtureGit:
    def __init__(self):
        self.commit = "a" * 40
        self.mutate = None

    def fetch(self, spec, destination):
        copy_fixture(spec.source_id, destination)
        if self.mutate:
            self.mutate(destination)
        return self.commit, []


@pytest.fixture
def registry():
    specs = load_registry()
    specs["ASSETNOTE"] = specs["ASSETNOTE"].model_copy(update={"assetnote_selections": (
        {"manifest": "data/technologies.json", "filename": "flask.txt", "technology": "Flask", "api_related": False},)})
    return specs


@pytest.fixture
def pipeline(tmp_path, registry):
    return IngestionPipeline(tmp_path / "kb", registry=registry, git=FixtureGit(),
                             clock=lambda: datetime(2026, 10, 1, tzinfo=UTC))


@pytest.fixture
def staged(tmp_path, registry):
    def build(source_id):
        root = tmp_path / source_id
        root.mkdir(exist_ok=True)
        copy_fixture(source_id, root)
        spec = registry[source_id]
        hashes = artifact_hashes(root)
        manifest = SourceManifest(source_id=source_id, source_url=spec.source_url,
            source_version=spec.ref or "fixture-1", source_commit="a" * 40 if spec.fetch_type == "git" else None,
            retrieved_at=datetime(2026, 10, 1, tzinfo=UTC), snapshot_id="a" * 40, source_record=".",
            license=spec.license, license_status="DECLARED", adapter_version=ADAPTER_VERSION,
            storage_class=spec.storage_class, namespace=spec.namespace, record_count=0,
            content_sha256=tree_hash(hashes), artifact_sha256=hashes, status=IngestionStatus.STAGED)
        return root, manifest, spec
    return build


def promote_fixture(pipeline, source_id):
    pipeline.sync(source_id)
    assert pipeline.normalize(source_id).status == IngestionStatus.STAGED
    assert pipeline.validate(source_id).status == IngestionStatus.READY
    pipeline.diff(source_id)
    return pipeline.promote(source_id)


def replace_json(path, **changes):
    value = json.loads(path.read_text())
    value.update(changes)
    path.write_text(json.dumps(value))
