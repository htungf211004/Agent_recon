"""Evidence-only checklist scoring; no tool dispatch."""

from pydantic import BaseModel, ConfigDict, Field

from src.contracts.recon_planning import ChecklistSummary
from src.recon.checklist import load_checklist, project_checklist
from src.recon.checklist_v3 import ITEMS, project_checklist_v3


class CoverageScore(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    score: float = Field(ge=0, le=100)
    mandatory_resolved: bool
    applicable_items: int
    complete_items: int


PATHS = {
    "PT_01-STT-04": ("/robots.txt",),
    "PT_01-STT-05": ("/sitemap.xml",),
    "PT_01-STT-06": ("/.well-known/security.txt", "/.well-known/openid-configuration", "/.well-known/jwks.json"),
    "PT_01-STT-07": ("/openapi.json", "/swagger.json"),
    "PT_01-STT-08": ("/graphql", "/gql", "/graphiql", "/v1/graphql"),
    "PT_01-STT-09": ("/service.wsdl",),
    "PT_01-STT-10": ("/backup.zip",),
    "PT_01-STT-12": ("/.git/HEAD",),
}
MANDATORY = {"PT_01-STT-01", "PT_01-STT-02", "PT_01-STT-03", "PT_01-STT-04",
             "PT_01-STT-05", "PT_01-STT-06", "PT_01-STT-07", "PT_01-STT-11"}
WEIGHTS = {"PT_01-STT-01": 2, "PT_01-STT-02": 3, "PT_01-STT-03": 2,
           "PT_01-STT-07": 2, "PT_01-STT-11": 3}
RESOLUTION = {"COMPLETE": 1.0, "NOT_APPLICABLE": 1.0, "MANUAL_REVIEW": 0.5,
              "BLOCKED": 0.5, "UNSUPPORTED": 0.0, "PENDING": 0.0}


def score_coverage(rows: tuple[ChecklistSummary, ...]) -> CoverageScore:
    if not rows:
        return CoverageScore(score=0, mandatory_resolved=False, applicable_items=0, complete_items=0)
    total = sum(WEIGHTS.get(row.id, 1) for row in rows)
    achieved = sum(WEIGHTS.get(row.id, 1) * RESOLUTION[row.status] for row in rows)
    return CoverageScore(score=round(100 * achieved / total, 2),
        mandatory_resolved=all(row.id not in MANDATORY or row.status in {"COMPLETE", "NOT_APPLICABLE"} for row in rows),
        applicable_items=sum(row.status != "NOT_APPLICABLE" for row in rows),
        complete_items=sum(row.status == "COMPLETE" for row in rows))


class CoverageEvaluator:
    def __init__(self, repository, service):
        self.repository, self.service = repository, service

    def project(self, task, *, finalize=False) -> tuple[ChecklistSummary, ...]:
        if self.repository.get_authorization(task.id):
            rows = project_checklist_v3(task, self.repository, self.service, finalize=finalize)
            goals = {item.id: tuple(cap.value for cap in item.capabilities) for item in ITEMS}
            paths = PATHS
        else:
            rows = project_checklist(task, self.repository, self.service)
            goals = {item.id: tuple(cap.value for cap in item.recommended_capabilities)
                     for item in load_checklist().items}
            paths = {item.id: item.paths for item in load_checklist().items}
        return tuple(row.model_copy(update={"recommended_capabilities": goals.get(row.id, ()),
            "suggested_paths": paths.get(row.id, ())}) for row in rows)
