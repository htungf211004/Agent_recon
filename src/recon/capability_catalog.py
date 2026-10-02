"""Authoritative intent taxonomy for policy, availability and checklist mapping."""

from dataclasses import dataclass
from typing import Literal

from src.contracts.execution import Risk
from src.recon.models import Capability


@dataclass(frozen=True)
class CapabilityDefinition:
    id: Capability
    risk: Risk
    execution_kind: Literal["target", "provider", "local_osint", "evidence"]
    required_runtime: str
    default_enabled: bool
    evidence_kind: str
    checklist_ids: tuple[str, ...]


_TARGET = {
    Capability.DNS_RESOLVE: (Risk.R0, "python", (1,)),
    Capability.HTTP_PROBE: (Risk.R0, "python", (2, 3)),
    Capability.HTTP_FETCH: (Risk.R0, "python", (4, 5, 6, 7, 8, 9, 10, 12, 13)),
    Capability.NMAP_SCAN: (Risk.R1, "nmap", (2,)),
    Capability.WHATWEB: (Risk.R0, "whatweb", (3,)),
    Capability.CONTENT_DISCOVERY: (Risk.R1, "ffuf", (2, 7, 10, 11, 12)),
    Capability.BROWSER_EXPLORE: (Risk.R0, "chromium", (11,)),
    Capability.BROWSER_REQUEST: (Risk.R0, "chromium", (11,)),
    Capability.WEB_CRAWL: (Risk.R1, "katana", (2, 11)),
    Capability.VHOST_DISCOVERY: (Risk.R1, "ffuf", (2,)),
    Capability.PARAMETER_DISCOVERY: (Risk.R2, "arjun", (2, 11)),
    Capability.TECHNOLOGY_SCAN: (Risk.R1, "nuclei", (3,)),
    Capability.GRAPHQL_DISCOVERY: (Risk.R1, "python", (8,)),
    Capability.GRAPHQL_INTROSPECTION: (Risk.R2, "python", (8,)),
    Capability.EXPOSURE_DISCOVERY: (Risk.R1, "ffuf", (10, 12)),
}
_LOCAL_OSINT = {
    Capability.PASSIVE_SUBDOMAIN_ENUM: ("subfinder/amass", (1,)),
    Capability.PASSIVE_INFRA_ENUM: ("amass", (1,)),
    Capability.HISTORICAL_URL_DISCOVERY: ("gau", (1, 4, 5)),
}
_PROVIDER = {
    Capability.WHOIS_RDAP_LOOKUP: ("rdap", (1,)),
    Capability.EXTERNAL_ASSET_SEARCH: ("shodan/censys/fofa", (14,)),
    Capability.PUBLIC_CODE_SEARCH: ("github/gitlab", (15,)),
    Capability.SEARCH_ENGINE_OSINT: ("brave", (16,)),
}
_EVIDENCE = {
    Capability.WSDL_DISCOVERY: ("python", (9,)),
    Capability.SOURCEMAP_ANALYZE: ("python", (13,)),
}

DEFINITIONS = {
    **{cap: CapabilityDefinition(cap, risk, "target", runtime, True,
                                 "tool_output", tuple(f"PT_01-STT-{n:02d}" for n in checks))
       for cap, (risk, runtime, checks) in _TARGET.items()},
    **{cap: CapabilityDefinition(cap, Risk.R0, "provider", runtime, True,
                                 "normalized_observation", tuple(f"PT_01-STT-{n:02d}" for n in checks))
       for cap, (runtime, checks) in _PROVIDER.items()},
    **{cap: CapabilityDefinition(cap, Risk.R0, "local_osint", runtime, True,
                                 "normalized_observation", tuple(f"PT_01-STT-{n:02d}" for n in checks))
       for cap, (runtime, checks) in _LOCAL_OSINT.items()},
    **{cap: CapabilityDefinition(cap, Risk.R0, "evidence", runtime, True,
                                 "analysis_summary", tuple(f"PT_01-STT-{n:02d}" for n in checks))
       for cap, (runtime, checks) in _EVIDENCE.items()},
}
RISK = {cap: definition.risk for cap, definition in DEFINITIONS.items()}

assert set(DEFINITIONS) == set(Capability)
