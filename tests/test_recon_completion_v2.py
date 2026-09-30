from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.completion import completion
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget
from tests.test_recon_adaptive_planning import STOP, adaptive


def test_model_stop_cannot_terminalize_pending_in_scope_asset(tmp_path):
    agent, _, task, _ = adaptive(tmp_path, [STOP])
    boundary = AuthorizationBoundary(task_id=task.id, root=AuthorizedTarget(kind="IP", value="127.0.0.1"))
    agent.repository.save_authorization(boundary)
    result = agent.run(task.id)
    agent.repository.upsert_asset(DiscoveredAsset(
        run_id=task.run_id, task_id=task.id, root_target="127.0.0.1", asset_type=AssetType.PATH,
        canonical_value="http://127.0.0.1:8000/pending", relation=AssetRelation.HTML_REFERENCE,
        discovered_from="root", discovery_evidence_refs=("evidence",), scope_status=AssetScopeStatus.IN_SCOPE,
        verification_status=AssetVerificationStatus.CLASSIFIED,
    ))
    state = completion(agent, task.id, result)
    assert state["terminal"] is False and state["run_status"] == "RUNNING"
    assert state["handoff_ready"] == result.handoff_ready
