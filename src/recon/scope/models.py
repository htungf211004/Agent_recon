"""Trusted authorization identity is separate from observed transport addresses."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.recon.urls import canonical_host


class ScopeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizedTarget(ScopeModel):
    kind: Literal["DOMAIN", "IP"]
    value: str
    include_subdomains: bool = False

    @model_validator(mode="after")
    def canonical_identity(self):
        if self.kind == "IP":
            value = str(ipaddress.ip_address(self.value))
            if self.include_subdomains:
                raise ValueError("IP roots cannot include subdomains")
        else:
            value = canonical_host(self.value)
            if "." not in value or value.startswith("["):
                raise ValueError("a DNS domain is required")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                pass
            else:
                raise ValueError("DOMAIN root cannot be an IP")
        object.__setattr__(self, "value", value)
        return self


class DnsObservation(ScopeModel):
    host: str
    addresses: tuple[str, ...] = Field(min_length=1, max_length=8)
    evidence_ref: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    _host = field_validator("host")(canonical_host)

    @field_validator("addresses")
    @classmethod
    def canonical_addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        addresses = tuple(sorted({str(ipaddress.ip_address(value)) for value in values}))
        if any(ipaddress.ip_address(value).is_unspecified or ipaddress.ip_address(value).is_multicast
               for value in addresses):
            raise ValueError("DNS observation requires concrete unicast addresses")
        return addresses


class AuthorizationBoundary(ScopeModel):
    schema_version: Literal["2.0"] = "2.0"
    task_id: str
    root: AuthorizedTarget
    dns_observations: tuple[DnsObservation, ...] = ()
    max_discovered_assets: int = Field(default=256, ge=1, le=4096)
    max_verified_assets: int = Field(default=64, ge=1, le=1024)
    max_derived_hosts: int = Field(default=8, ge=0, le=64)
    max_host_depth: int = Field(default=2, ge=0, le=8)
    max_new_origins: int = Field(default=8, ge=0, le=64)
    max_dns_addresses_per_host: int = Field(default=8, ge=1, le=8)
    max_verification_requests: int = Field(default=32, ge=0, le=512)


class DerivedBinding(ScopeModel):
    task_id: str
    host: str
    address: str
    scheme: Literal["http", "https"]
    port: int = Field(ge=1, le=65535)
    dns_evidence_ref: str

    _host = field_validator("host")(canonical_host)

    @field_validator("address")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))
