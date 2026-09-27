import json

import pytest

from src.recon.discovery_parsers import parse_html, parse_javascript, parse_openapi, parse_robots, parse_sitemap
from src.recon.web_models import DiscoveryKind

BASE = "http://127.0.0.1:8000/"


def test_html_forms_scripts_and_external_links():
    result = parse_html('''<a href="/items?q=one#top">items</a><a href="https://elsewhere.test/">outside</a>
    <script src="/app.js"></script><script>fetch('/inline')</script>
    <form method="post" action="/save"><input name="token" required><input name="skip" disabled></form>
    <form action="/search"><input name="q"></form>''', BASE)
    found = {(c.url, c.method): c for c in result.candidates}
    assert (BASE + "items?q=one", "GET") in found
    assert found[(BASE + "app.js", "GET")].kind_hint == DiscoveryKind.JAVASCRIPT
    assert (BASE + "inline", "GET") in found
    assert found[(BASE + "save", "POST")].manual is True
    assert found[(BASE + "save", "POST")].parameters[0].name == "token"
    assert found[(BASE + "search", "GET")].manual is True
    assert len(found) == 5


def test_robots_sitemap_index_namespace_and_xxe_rejection():
    robots = parse_robots("Disallow: /private\nAllow: /public\nDisallow: /wild*\nSitemap: /index.xml", BASE)
    assert {c.url for c in robots.candidates} == {BASE + "private", BASE + "public", BASE + "index.xml"}
    index = parse_sitemap('<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>/part.xml</loc></sitemap></sitemapindex>', BASE)
    assert index.kind == DiscoveryKind.SITEMAP_INDEX
    assert index.candidates[0].kind_hint == DiscoveryKind.SITEMAP
    sitemap = parse_sitemap('<urlset><url><loc>/items?q=1&amp;page=2</loc></url></urlset>', BASE)
    assert sitemap.candidates[0].url == BASE + "items?q=1&page=2"
    with pytest.raises(ValueError, match="DTD"):
        parse_sitemap('<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///secret">]><urlset/>', BASE)


def test_openapi3_refs_operation_overrides_methods_and_server_scope():
    document = {
        "openapi": "3.0.3", "servers": [{"url": "/api"}],
        "components": {"parameters": {"Q": {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}}}},
        "paths": {
            "/items/{id}": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                              "get": {"parameters": [{"$ref": "#/components/parameters/Q"}]},
                              "post": {"requestBody": {"required": True}}},
            "/offsite": {"get": {"servers": [{"url": "https://example.test"}]}},
            "/unresolved": {"get": {"parameters": [{"$ref": "https://example.test/params.json"}]}},
        },
    }
    result = parse_openapi(json.dumps(document), BASE)
    found = {(c.url, c.method): c for c in result.candidates}
    params = found[(BASE + "api/items/{id}", "GET")].parameters
    assert {(p.name, p.location, p.required) for p in params} == {("id", "path", True), ("q", "query", True)}
    assert found[(BASE + "api/items/{id}", "POST")].manual is True
    assert found[(BASE + "api/unresolved", "GET")].manual is True
    assert len(found) == 3


def test_swagger2_yaml_basepath_and_parameter_override():
    result = parse_openapi('''swagger: "2.0"
basePath: /v2
paths:
  /items:
    parameters:
      - {name: q, in: query, required: true, type: string}
    get:
      parameters:
        - {name: q, in: query, required: false, type: string}
    post:
      parameters:
        - {name: payload, in: body, required: true, schema: {type: object}}
''', BASE)
    assert result.candidates[0].url == BASE + "v2/items"
    assert result.candidates[0].parameters[0].required is False
    assert result.candidates[1].method == "POST"
    with pytest.raises(ValueError, match="aliases"):
        parse_openapi('openapi: "3.0.3"\npaths: &loop {again: *loop}', BASE)


def test_javascript_records_static_methods_without_evaluating_code():
    parsed = parse_javascript('''fetch('/items'); fetch('/save', {method: 'POST'});
    axios.delete('/remove'); xhr.open('HEAD', '/health');
    fetch('/dynamic/' + id); fetch('/unknown', options); fetch(`/template/${id}`);
    fetch('/ambiguous', {method: mode}); fetch('/spread', {...options});
    axios.get('/configured', config);''', BASE)
    found = {(c.url, c.method): c for c in parsed.candidates}
    assert (BASE + "items", "GET") in found
    assert (BASE + "save", "POST") in found
    assert (BASE + "remove", "DELETE") in found
    assert (BASE + "health", "HEAD") in found
    assert found[(BASE + "unknown", "GET")].manual is True
    assert found[(BASE + "ambiguous", "GET")].manual is True
    assert found[(BASE + "spread", "GET")].manual is True
    assert found[(BASE + "configured", "GET")].manual is True
    assert not any("dynamic" in url or "template" in url for url, _ in found)
