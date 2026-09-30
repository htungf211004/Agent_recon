"""Versioned, evidence-linked observations beside AttackSurfaceInventory v1.0."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.recon.urls import canonical_host, route_url


class AssetType(StrEnum):
    PATH = "PATH"
    HOST = "HOST"
    IP = "IP"
    SERVICE = "SERVICE"
    API = "API"
    DOCUMENT = "DOCUMENT"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"


class AssetRelation(StrEnum):
    ROOT = "ROOT"
    SAME_ORIGIN = "SAME_ORIGIN"
    SUBDOMAIN = "SUBDOMAIN"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    REDIRECT = "REDIRECT"
    ROBOTS = "ROBOTS"
    SITEMAP = "SITEMAP"
    HTML_REFERENCE = "HTML_REFERENCE"
    JS_REFERENCE = "JS_REFERENCE"
    BROWSER_REFERENCE = "BROWSER_REFERENCE"
    OPENAPI = "OPENAPI"
    CONTENT_DISCOVERY = "CONTENT_DISCOVERY"
    OTHER_REFERENCE = "OTHER_REFERENCE"


class AssetScopeStatus(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class AssetVerificationStatus(StrEnum):
    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    QUEUED = "QUEUED"
    VERIFIED = "VERIFIED"
    UNREACHABLE = "UNREACHABLE"
    BLOCKED = "BLOCKED"
    MANUAL_REVIEW = "MANUAL_REVIEW"


def asset_id(task_id: str, asset_type: AssetType, canonical_value: str) -> str:
    material = f"{task_id}\0{asset_type.value}\0{canonical_value}".encode()
    return "asset-" + hashlib.sha256(material).hexdigest()[:32]


class DiscoveredAsset(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = ""
    run_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    root_target: str = Field(min_length=1, max_length=253)
    asset_type: AssetType
    canonical_value: str = Field(min_length=1, max_length=2048)
    relation: AssetRelation
    discovered_from: str = Field(max_length=2048)
    discovery_evidence_refs: tuple[str, ...] = Field(default=(), max_length=16)
    scope_status: AssetScopeStatus = AssetScopeStatus.MANUAL_REVIEW
    verification_status: AssetVerificationStatus = AssetVerificationStatus.DISCOVERED
    verification_evidence_refs: tuple[str, ...] = Field(default=(), max_length=16)
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("canonical_value")
    @classmethod
    def safe_value(cls, value: str, info) -> str:
        kind = info.data.get("asset_type")
        if kind == AssetType.IP:
            return str(ipaddress.ip_address(value))
        if kind == AssetType.HOST:
            return canonical_host(value)
        if kind in {AssetType.PATH, AssetType.API, AssetType.DOCUMENT, AssetType.EXTERNAL_REFERENCE}:
            return route_url(value)
        if any(char in value for char in "@?#\r\n"):
            raise ValueError("asset value may contain credentials or query data")
        return value

    @field_validator("discovered_from")
    @classmethod
    def safe_source(cls, value: str) -> str:
        if "://" in value:
            return route_url(value)
        if any(char in value for char in "@?#\r\n"):
            raise ValueError("discovery source may contain credentials or query data")
        return value

    @model_validator(mode="after")
    def stable_identity(self):
        expected = asset_id(self.task_id, self.asset_type, self.canonical_value)
        if self.id and self.id != expected:
            raise ValueError("asset ID does not match canonical identity")
        object.__setattr__(self, "id", expected)
        return self


class ReconAssetInventory(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = "2.0"
    task_id: str
    assets: tuple[DiscoveredAsset, ...]
