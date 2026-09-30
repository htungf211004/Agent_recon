from src.recon.checklist_v2 import ITEMS, VERSION, project_checklist_v2
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
    assert projected[7].status == projected[8].status == "MANUAL_REVIEW"
    assert all(projected[i - 1].status == "UNSUPPORTED" for i in (14, 15, 16))
