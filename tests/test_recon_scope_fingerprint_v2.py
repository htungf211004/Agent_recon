from src.recon.models import Capability, HttpFetchParams
from src.recon.planner import ReconPlanner
from src.recon.scope.admission import admit_target


def test_v2_action_fingerprint_binds_parameters_target_and_scope_version():
    task, _ = admit_target("127.0.0.1", "fingerprint")
    def action(current, ip="127.0.0.1", path="/"):
        return ReconPlanner._action(current, ip, Capability.HTTP_FETCH,
                                    HttpFetchParams(port=80, scheme="http", path=path)).request
    first = action(task)
    assert action(task).action_fingerprint == first.action_fingerprint
    assert action(task, path="/other").action_fingerprint != first.action_fingerprint
    assert action(task, ip="127.0.0.2").action_fingerprint != first.action_fingerprint
    changed = task.model_copy(update={"scope_version": "v2-derived"})
    assert action(changed).action_fingerprint != first.action_fingerprint
    assert action(changed).id != first.id
