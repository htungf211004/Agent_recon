from types import SimpleNamespace

from src.contracts.recon_manual_review import api_manual_review
from src.recon.checklist_v2 import ITEMS, VERSION, project_checklist_v2
from src.recon.models import Capability
from src.recon.scope.admission import admit_target
from src.recon.storage import ReconRepository


def test_all_pt01_items_have_honest_initial_status(tmp_path):
    task, boundary = admit_target("127.0.0.1", "checklist")
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    service = type("Service", (), {"gateway": None})()
    assert VERSION == "recon-checklist-v2"
    assert tuple(item.stt for item in ITEMS) == tuple(range(1, 17))
    projected = project_checklist_v2(task, repository, service)
    assert len(projected) == 16
    assert all(item.status != "COMPLETE" for item in projected)
    assert projected[0].status == "UNSUPPORTED"
    assert projected[7].status == projected[8].status == "PENDING"
    assert all(projected[i - 1].status == "UNSUPPORTED" for i in (14, 15, 16))


def test_404_candidates_record_coverage_without_findings_or_manual_handoff():
    task, _ = admit_target("127.0.0.1", "negative-coverage")
    paths = ("/openapi.json", "/swagger.json", "/graphql", "/service.wsdl",
             "/backup.zip", "/.git/HEAD", "/app.js.map")
    sources = tuple(SimpleNamespace(url="http://127.0.0.1:80" + path, evidence_id="verified",
                                    status="UNAVAILABLE", kind="HTML") for path in paths)
    assets = tuple(SimpleNamespace(asset_type="API" if path == "/graphql" else "DOCUMENT",
                                   canonical_value="http://127.0.0.1:80" + path,
                                   scope_status="IN_SCOPE", verification_status="UNREACHABLE",
                                   discovery_evidence_refs=("verified",), verification_evidence_refs=("verified",))
                   for path in ("/graphql", "/service.wsdl", "/openapi.json"))
    repository = SimpleNamespace(list_sources=lambda _: sources, list_assets=lambda _: assets,
                                 list_tool_results=lambda _: (SimpleNamespace(
                                     status="success", evidence_id="verified", capability=Capability.HTTP_FETCH),))
    service = SimpleNamespace(gateway=SimpleNamespace(
        evidence=SimpleNamespace(read=lambda _: b"404"),
        registry=SimpleNamespace(get=lambda _: SimpleNamespace(ip_available=True))))
    projected = {item.id: item for item in project_checklist_v2(task, repository, service, finalize=True)}
    for number in (7, 10, 12, 13):
        item = projected[f"PT_01-STT-{number:02d}"]
        assert item.status == "COMPLETE" and item.finding == "NOT_FOUND"
    for number in (8, 9):
        item = projected[f"PT_01-STT-{number:02d}"]
        assert item.status == "NOT_APPLICABLE" and item.finding == "NOT_FOUND"
    assert api_manual_review(assets) == ()
