from src.contracts.recon_assets import AssetRelation, AssetScopeStatus, AssetVerificationStatus
from src.recon.asset_extraction import extract_references, record_references
from src.recon.scope.models import AuthorizationBoundary, AuthorizedTarget
from src.recon.storage import ReconRepository


def test_html_js_sitemap_robots_and_source_map_preserve_external_references(tmp_path):
    repository = ReconRepository(tmp_path / "recon.db")
    boundary = AuthorizationBoundary(task_id="t", root=AuthorizedTarget(
        kind="DOMAIN", value="example.test", include_subdomains=True))
    task = type("Task", (), {"id": "t", "run_id": "t"})()
    html = ('<html><a href="/admin">admin</a><script src="/app.js"></script>'
            '<a href="https://api.example.test/v1">API</a>'
            '<img src="https://cdn.thirdparty.test/logo.png">'
            '<script>fetch("/api");fetch("https://cdn.thirdparty.test/data")</script></html>')
    assets = record_references(repository, task, boundary, "https://example.test/", "ev-1", html, "text/html")
    assert any(a.canonical_value.endswith("/admin") and a.scope_status == AssetScopeStatus.IN_SCOPE for a in assets)
    assert any("api.example.test" in a.canonical_value and a.scope_status == AssetScopeStatus.IN_SCOPE for a in assets)
    assert any("cdn.thirdparty.test" in a.canonical_value and a.scope_status == AssetScopeStatus.OUT_OF_SCOPE
               and a.verification_status == AssetVerificationStatus.BLOCKED for a in assets)
    assert any(a.canonical_value == "api.example.test" for a in repository.list_assets("t"))
    assert ("https://example.test:443/app.js.map", AssetRelation.JS_REFERENCE) in extract_references(
        "//# sourceMappingURL=app.js.map", "https://example.test/app.js", "application/javascript")
    assert ("https://example.test:443/admin", AssetRelation.ROBOTS) in extract_references(
        "Disallow: /admin", "https://example.test/robots.txt", "text/plain")
    assert ("https://example.test:443/site", AssetRelation.SITEMAP) in extract_references(
        "<loc>https://example.test/site</loc>", "https://example.test/sitemap.xml", "application/xml")
    assert ("https://api.example.test:443/v1", AssetRelation.OPENAPI) in extract_references(
        "servers:\n - url: https://api.example.test/v1", "https://example.test/openapi.yaml", "text/yaml")
