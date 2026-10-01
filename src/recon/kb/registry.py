"""Validated operator registry; URLs and dataset selections never come from the planner."""

import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from pydantic import Field, model_validator

from src.contracts.recon_kb import KBModel, StorageClass
from src.recon.kb.utils import contained

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "data" / "recon_kb_sources.yaml"


class SourceSpec(KBModel):
    source_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$")
    enabled: bool
    fetch_type: str
    source_url: str
    repository: str | None
    ref: str | None
    canonical_url: str
    storage_class: StorageClass
    namespace: str
    license: str | None
    license_review_required: bool
    license_status: str = "DECLARED"
    refresh_policy: str
    paths: tuple[str, ...] = ()
    approved_hosts: tuple[str, ...]
    max_response_bytes: int = Field(default=32_000_000, ge=1, le=128_000_000)
    max_snapshot_bytes: int = Field(default=128_000_000, ge=1, le=512_000_000)
    max_pages: int = Field(default=2000, ge=1, le=10000)
    request_delay_seconds: float = Field(default=6.0, ge=0, le=30)
    assetnote_selections: tuple[dict, ...] = ()
    package_queries: tuple[dict, ...] = ()

    @model_validator(mode="after")
    def trusted(self):
        validate_url(self.source_url, self.approved_hosts)
        if self.fetch_type not in {"git", "http", "nvd_api", "osv_api"}:
            raise ValueError("unsupported fetch type")
        if self.fetch_type == "git":
            if self.repository != self.source_url or not self.ref:
                raise ValueError("git requires registry repository and explicit ref")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]*", self.ref) or ".." in self.ref:
                raise ValueError("invalid git ref")
        for path in self.paths:
            contained(Path.cwd(), path)
            if any(char in path for char in "*?[]\n\r"):
                raise ValueError("sparse paths must be literal")
        return self

    def require_enabled(self):
        if self.source_id == "ARJUN" or not self.enabled:
            raise ValueError(f"{self.source_id} is disabled")
        if self.license_review_required and self.license_status != "APPROVED":
            raise ValueError(f"{self.source_id} license review required")


def validate_url(url: str, hosts: tuple[str, ...]):
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname not in hosts or parts.username or parts.password
            or parts.port not in {None, 443} or parts.fragment or "\\" in url
            or any(ord(char) < 32 for char in url)):
        raise ValueError("unapproved HTTPS source")
    return url


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, SourceSpec]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    specs = [SourceSpec.model_validate(item) for item in value["sources"]]
    if len({item.source_id for item in specs}) != len(specs):
        raise ValueError("duplicate source ID")
    return {item.source_id: item for item in specs}
