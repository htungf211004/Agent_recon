import hashlib

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.asset_verification import AssetVerifier
from src.recon.gateway import AdapterOutput, CapabilityRegistry, ToolExecutionGateway
from src.recon.models import Capability
from src.recon.policy import PolicyService
from src.recon.scope.admission import admit_target
from src.recon.service import ReconService
from src.recon.storage import EvidenceStore, ReconRepository
from src.recon.web_models import HttpResponseMetadata


def test_verification_uses_gateway_and_external_asset_has_zero_dispatch(tmp_path):
    calls = []
    class Adapter:
        def execute(self, request):
            calls.append(request.parameters.path)
            body = b"ok"
            return AdapterOutput(status="success", raw_output=body,
                                 http_response=HttpResponseMetadata(status_code=200, content_type="text/plain",
                                     body_size=2, body_sha256=hashlib.sha256(body).hexdigest(), truncated=False))
    task, boundary = admit_target("127.0.0.1", "verify")
    repository = ReconRepository(tmp_path / "recon.db")
    repository.save_task(task)
    repository.save_authorization(boundary)
    registry = CapabilityRegistry()
    registry.register(Capability.HTTP_FETCH, Adapter())
    gateway = ToolExecutionGateway(policy=PolicyService(repository), registry=registry,
                                   evidence=EvidenceStore(tmp_path / "evidence", repository), results=repository)
    service = ReconService(repository, gateway)
    values = (("http://127.0.0.1/admin", AssetScopeStatus.IN_SCOPE),
              ("http://192.0.2.77/external", AssetScopeStatus.OUT_OF_SCOPE))
    for url, scope in values:
        repository.upsert_asset(DiscoveredAsset(
            run_id=task.run_id, task_id=task.id, root_target="127.0.0.1", asset_type=AssetType.PATH,
            canonical_value=url, relation=AssetRelation.HTML_REFERENCE, discovered_from="root",
            discovery_evidence_refs=("source-evidence",), scope_status=scope,
            verification_status=AssetVerificationStatus.CLASSIFIED if scope == AssetScopeStatus.IN_SCOPE
            else AssetVerificationStatus.BLOCKED,
        ))
    AssetVerifier(repository, service).verify(task)
    assert sorted(calls) == ["/admin", "/backup.zip"]
    verified = repository.list_assets(task.id, status=AssetVerificationStatus.VERIFIED)
    assert len(verified) == 2 and all(a.verification_evidence_refs for a in verified), [
        (a.canonical_value, a.verification_status) for a in repository.list_assets(task.id)]
    assert gateway.evidence.read(verified[0].verification_evidence_refs[0])
    assert repository.pending_verification_assets(task.id) == ()
    AssetVerifier(repository, service).verify(task)
    assert sorted(calls) == ["/admin", "/backup.zip"]
