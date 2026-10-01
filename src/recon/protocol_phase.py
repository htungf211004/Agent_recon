"""Bounded GraphQL endpoint discovery; introspection requires explicit R2 scope."""

from src.recon.models import (
    Capability,
    GraphqlDiscoveryParams,
    GraphqlIntrospectionParams,
    ReconPlan,
)
from src.recon.planner import ReconPlanner
from src.recon.urls import request_url

PATHS = ("/graphql", "/gql", "/graphiql", "/v1/graphql")


class ProtocolCoverageExecutor:
    def __init__(self, repository, service, engine):
        self.repository, self.service, self.engine = repository, service, engine

    def run(self, task):
        if Capability.GRAPHQL_DISCOVERY not in task.scope.capabilities:
            return
        if self.service.gateway.registry.availability(Capability.GRAPHQL_DISCOVERY) != "AVAILABLE":
            return
        from src.recon.deterministic_coverage import DeterministicCoverageExecutor

        origins = DeterministicCoverageExecutor(self.engine)._verified_origins(task)
        for _, target_ip, host, scheme, port in origins[:4]:
            for path in PATHS:
                action = ReconPlanner._action(task, target_ip, Capability.GRAPHQL_DISCOVERY,
                    GraphqlDiscoveryParams(port=port, scheme=scheme, path=path,
                        max_body_bytes=min(8192, task.execution_budget.max_body_bytes)), target_host=host)
                result = self.service.gateway.execute(action.request)
                if result.status == "denied":
                    self.repository.add_limitation(task.id, "protocol:graphql_policy_or_budget")
                    return
                if result.status != "success" or not result.evidence_id or not result.observations:
                    continue
                if (Capability.GRAPHQL_INTROSPECTION not in task.scope.capabilities
                        or self.service.gateway.registry.availability(Capability.GRAPHQL_INTROSPECTION) != "AVAILABLE"
                        or path == "/graphiql"):
                    continue
                expected = request_url(target_ip, scheme, port, path, target_host=host)
                if not any(row.kind == "PROTOCOL" and row.value == expected for row in result.observations):
                    continue
                introspection = ReconPlanner._action(task, target_ip, Capability.GRAPHQL_INTROSPECTION,
                    GraphqlIntrospectionParams(port=port, scheme=scheme, path=path,
                        discovery_evidence_ref=result.evidence_id,
                        max_body_bytes=min(32768, task.execution_budget.max_body_bytes)), target_host=host)
                self.service.run(ReconPlan(task_id=task.id, actions=(introspection,)))
