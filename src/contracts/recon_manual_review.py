"""Typed handoff markers for API work Recon does not execute."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ManualReviewRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    task_id: str
    asset_id: str
    category: Literal["GRAPHQL_ACTIVE_TESTING", "SOAP_ACTIVE_TESTING", "OPENAPI_ACTIVE_TESTING"]
    reason: str
    evidence_refs: tuple[str, ...]


def api_manual_review(assets) -> tuple[ManualReviewRecord, ...]:
    rows = []
    for asset in assets:
        path = asset.canonical_value.lower().split("?", 1)[0]
        if (asset.asset_type not in {"API", "DOCUMENT"} or asset.scope_status != "IN_SCOPE"
                or asset.verification_status != "VERIFIED" or not asset.verification_evidence_refs):
            continue
        category = ("GRAPHQL_ACTIVE_TESTING" if path.endswith("/graphql") else
                    "SOAP_ACTIVE_TESTING" if path.endswith(".wsdl") else
                    "OPENAPI_ACTIVE_TESTING" if path.endswith(("openapi.json", "swagger.json")) else None)
        if category:
            rows.append(ManualReviewRecord(
                task_id=asset.task_id, asset_id=asset.id, category=category,
                reason="active API security testing requires Operator/Approver review",
                evidence_refs=tuple(dict.fromkeys((*asset.discovery_evidence_refs,
                                                    *asset.verification_evidence_refs))),
            ))
    return tuple(rows)
