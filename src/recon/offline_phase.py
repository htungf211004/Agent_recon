"""Run safe parsers on successfully fetched protocol and source-map evidence."""

import hashlib

from src.recon.models import Capability, EvidenceCapabilityRequest, EvidenceParams, parse_target_request


class OfflineAnalysisExecutor:
    def __init__(self, repository, gateway):
        self.repository, self.gateway = repository, gateway

    def run(self, task):
        if task.execution_budget.max_offline_bytes == 0:
            return
        for run in self.repository.list_tool_runs(task.id):
            if not run.request_payload:
                continue
            source = parse_target_request(run.request_payload)
            if source is None or source.capability != Capability.HTTP_FETCH:
                continue
            result = self.repository.get_tool_result(run.request_id)
            if (result is None or result.status != "success" or not result.evidence_id
                    or result.http_response is None or result.http_response.status_code != 200):
                continue
            path = source.parameters.path.lower()
            if path.endswith(".map"):
                capability, profile = Capability.SOURCEMAP_ANALYZE, "sourcemap_metadata"
            elif path.endswith(".wsdl") or source.parameters.query.lower() == "wsdl":
                capability, profile = Capability.WSDL_DISCOVERY, "wsdl_metadata"
            else:
                continue
            if capability not in task.scope.capabilities:
                continue
            if self.gateway.registry.availability(capability) != "AVAILABLE":
                continue
            identity = hashlib.sha256(f"{task.id}\0{capability.value}\0{result.evidence_id}".encode()).hexdigest()[:24]
            request = EvidenceCapabilityRequest(id=f"offline-{identity}", task_id=task.id,
                capability=capability, evidence_ref=result.evidence_id,
                parameters=EvidenceParams(profile=profile,
                    max_input_bytes=min(131072, task.execution_budget.max_offline_bytes)))
            analyzed = self.gateway.execute(request)
            if analyzed.status != "success":
                self.repository.add_limitation(task.id, f"offline:{capability.value}:failed")
