"""Bounded references from verified target content, including external observations."""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from src.contracts.recon_assets import (
    AssetRelation,
    AssetScopeStatus,
    AssetType,
    AssetVerificationStatus,
    DiscoveredAsset,
)
from src.recon.scope.deriver import ScopeDeriver
from src.recon.urls import canonical_url, route_url, validate_path

MAX_REFERENCES = 128


class _References(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.values = []

    def handle_starttag(self, tag, attrs):
        if tag not in {"a", "area", "link", "script", "form", "img"}:
            return
        fields = dict(attrs)
        for key in ("href", "src", "action"):
            if fields.get(key):
                self.values.append((fields[key], AssetRelation.HTML_REFERENCE))


def _canonical_reference(value: str, base_url: str) -> str | None:
    if (not value or len(value) > 2048 or "\\" in value or any(ord(char) <= 32 for char in value)
            or value.startswith(("#", "javascript:", "data:"))):
        return None
    try:
        path = urlsplit(value).path
        if path:
            validate_path(path if path.startswith("/") else "/" + path)
        return route_url(canonical_url(urljoin(base_url, value)))
    except (ValueError, UnicodeError):
        return None


def extract_references(text: str, base_url: str, content_type: str = "") -> tuple[tuple[str, AssetRelation], ...]:
    """Extract literal URLs only; never evaluate JavaScript or follow links."""
    if len(text.encode("utf-8")) > 524288:
        raise ValueError("candidate source exceeds parser limit")
    values = []
    if "html" in content_type or text.lstrip().lower().startswith(("<html", "<!doctype html")):
        parser = _References()
        parser.feed(text)
        values.extend(parser.values)
    path = urlsplit(base_url).path.lower()
    if path.endswith("/robots.txt"):
        values.extend((match[1].strip(), AssetRelation.ROBOTS) for match in
                      re.finditer(r"(?im)^\s*(?:Allow|Disallow|Sitemap)\s*:\s*([^#\r\n]+)", text))
    if "xml" in content_type or path.endswith(("sitemap.xml", ".xml")):
        values.extend((match[1].strip(), AssetRelation.SITEMAP) for match in
                      re.finditer(r"(?is)<loc>\s*([^<]{1,2048})\s*</loc>", text))
    if "javascript" in content_type or path.endswith(".js") or "html" in content_type:
        values.extend((match[2], AssetRelation.JS_REFERENCE) for match in
                      re.finditer(r"\b(?:fetch|import)\s*\(\s*(['\"])([^'\"\r\n]{1,2048})\1", text))
        values.extend((match[1], AssetRelation.JS_REFERENCE) for match in
                      re.finditer(r"(?im)[#@]\s*sourceMappingURL\s*=\s*([^\s]+)", text))
    if path.endswith(("openapi.json", "swagger.json", ".yaml", ".yml")):
        values.extend((match[1], AssetRelation.OPENAPI) for match in
                      re.finditer(r"(?im)[\"']?url[\"']?\s*:\s*[\"'](https?://[^\"']{1,2048})[\"']", text))
        values.extend((match[1].strip(), AssetRelation.OPENAPI) for match in
                      re.finditer(r"(?im)^\s*-?\s*url\s*:\s*(https?://[^\s#]{1,2048})", text))
    found = {}
    for value, relation in values[:MAX_REFERENCES]:
        canonical = _canonical_reference(value, base_url)
        if canonical:
            found.setdefault((canonical, relation), None)
    return tuple(found)


def record_candidate(repository, task, boundary, base_url: str, evidence_ref: str,
                     value: str, relation: AssetRelation) -> DiscoveredAsset | None:
    deriver = ScopeDeriver(boundary)
    url = _canonical_reference(value, base_url)
    if not url:
        return None
    if len(repository.list_assets(task.id)) >= boundary.max_discovered_assets:
        repository.add_limitation(task.id, "assets:max_discovered_assets")
        return None
    scope = deriver.classify_url(url)
    path = urlsplit(url).path.lower()
    kind = (AssetType.EXTERNAL_REFERENCE if scope == AssetScopeStatus.OUT_OF_SCOPE else
            AssetType.API if path.endswith(("/graphql", ".wsdl")) else
            AssetType.DOCUMENT if path.endswith(("openapi.json", "swagger.json")) else AssetType.PATH)
    status = (AssetVerificationStatus.CLASSIFIED if scope == AssetScopeStatus.IN_SCOPE
              else AssetVerificationStatus.MANUAL_REVIEW if scope == AssetScopeStatus.MANUAL_REVIEW
              else AssetVerificationStatus.BLOCKED)
    recorded = repository.upsert_asset(DiscoveredAsset(
            run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
            asset_type=kind, canonical_value=url, relation=relation, discovered_from=route_url(base_url),
            discovery_evidence_refs=(evidence_ref,), scope_status=scope, verification_status=status,
    ))
    host = urlsplit(url).hostname
    if host and host != urlsplit(base_url).hostname and len(repository.list_assets(task.id)) < boundary.max_discovered_assets:
        repository.upsert_asset(DiscoveredAsset(
            run_id=task.run_id, task_id=task.id, root_target=boundary.root.value,
            asset_type=AssetType.HOST, canonical_value=host, relation=relation,
            discovered_from=route_url(base_url), discovery_evidence_refs=(evidence_ref,),
            scope_status=scope, verification_status=status,
        ))
    return recorded


def record_references(repository, task, boundary, base_url: str, evidence_ref: str,
                      text: str, content_type: str) -> tuple[DiscoveredAsset, ...]:
    recorded = []
    for url, relation in extract_references(text, base_url, content_type):
        asset = record_candidate(repository, task, boundary, base_url, evidence_ref, url, relation)
        if asset is None:
            break
        recorded.append(asset)
    return tuple(recorded)
