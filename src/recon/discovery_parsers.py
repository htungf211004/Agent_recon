"""Pure, bounded parsers. No parser performs I/O or evaluates target code."""

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit
from xml.etree import ElementTree

import yaml

from src.recon.urls import normalize_candidate
from src.recon.web_models import DiscoveryKind, EndpointParameter, HttpMethod

MAX_CANDIDATES = 256
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}


@dataclass(frozen=True)
class Candidate:
    url: str
    method: HttpMethod = "GET"
    parameters: tuple[EndpointParameter, ...] = ()
    relation: str = "link"
    kind_hint: DiscoveryKind = DiscoveryKind.SEED
    manual: bool = False


@dataclass(frozen=True)
class ParseResult:
    kind: DiscoveryKind
    candidates: tuple[Candidate, ...]
    limited: bool = False


class Collector:
    def __init__(self, base: str):
        self.base = base
        self.items: list[Candidate] = []
        self.limited = False

    def add(self, value: str, **kwargs):
        url = normalize_candidate(value, self.base)
        if url is None:
            return
        if len(self.items) >= MAX_CANDIDATES:
            self.limited = True
            return
        self.items.append(Candidate(url, **kwargs))

    def result(self, kind: DiscoveryKind) -> ParseResult:
        return ParseResult(kind, tuple(self.items), self.limited)


class _HTML(HTMLParser):
    def __init__(self, collector: Collector):
        super().__init__(convert_charrefs=True)
        self.collector = collector
        self.form = None
        self.script = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base" and attrs.get("href"):
            # Never reinterpret off-origin base URLs as local links.
            base = normalize_candidate(attrs["href"], self.collector.base)
            self.collector.base = base or "https://invalid.invalid/"
        if tag in {"a", "area", "link"} and attrs.get("href"):
            self.collector.add(attrs["href"], relation="link")
        if tag == "script":
            self.script = True
            if attrs.get("src"):
                self.collector.add(attrs["src"], relation="script", kind_hint=DiscoveryKind.JAVASCRIPT)
        if tag == "form":
            self._finish_form()
            method = (attrs.get("method") or "GET").upper()
            if method in METHODS:
                self.form = [attrs.get("action") or self.collector.base, method, []]
        if tag in {"input", "select", "textarea", "button"} and self.form and "disabled" not in attrs:
            if attrs.get("name") and len(attrs["name"]) <= 256:
                self.form[2].append(EndpointParameter(
                    name=attrs["name"], location="query" if self.form[1] == "GET" else "formData",
                    required="required" in attrs, data_type="string",
                ))
            if attrs.get("formaction"):
                method = (attrs.get("formmethod") or self.form[1]).upper()
                if method in METHODS:
                    self.collector.add(attrs["formaction"], method=method, relation="form", manual=True)

    def handle_endtag(self, tag):
        if tag == "form":
            self._finish_form()
        if tag == "script":
            self.script = False

    def handle_data(self, data):
        if self.script:
            parsed = parse_javascript(data, self.collector.base)
            for candidate in parsed.candidates:
                self.collector.add(candidate.url, method=candidate.method, relation=candidate.relation,
                                   manual=candidate.manual)
            self.collector.limited |= parsed.limited

    def _finish_form(self):
        if self.form:
            action, method, parameters = self.form
            self.collector.add(action, method=method, parameters=tuple(parameters[:256]), relation="form", manual=True)
            self.form = None


def parse_html(text: str, base: str) -> ParseResult:
    collector = Collector(base)
    parser = _HTML(collector)
    parser.feed(text)
    parser.close()
    parser._finish_form()
    return collector.result(DiscoveryKind.HTML)


def parse_robots(text: str, base: str) -> ParseResult:
    collector = Collector(base)
    for line in text.splitlines():
        key, separator, value = line.partition("#")[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if separator and value and not any(c in value for c in "*$"):
            if key in {"allow", "disallow"}:
                collector.add(value, relation=f"robots-{key}")
            elif key == "sitemap":
                collector.add(value, relation="sitemap", kind_hint=DiscoveryKind.SITEMAP)
    return collector.result(DiscoveryKind.ROBOTS)


def parse_sitemap(text: str, base: str) -> ParseResult:
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("DTD and entities are not supported")
    root = ElementTree.fromstring(text)
    kind = root.tag.rsplit("}", 1)[-1]
    if kind not in {"urlset", "sitemapindex"}:
        raise ValueError("not a sitemap")
    collector = Collector(base)
    for item in root:
        expected = "sitemap" if kind == "sitemapindex" else "url"
        if item.tag.rsplit("}", 1)[-1] != expected:
            continue
        for child in item:
            if child.tag.rsplit("}", 1)[-1] == "loc" and child.text:
                collector.add(child.text.strip(), relation=expected,
                              kind_hint=DiscoveryKind.SITEMAP if expected == "sitemap" else DiscoveryKind.SEED)
    return collector.result(DiscoveryKind.SITEMAP_INDEX if kind == "sitemapindex" else DiscoveryKind.SITEMAP)


def _resolve(value, document):
    seen = set()
    for _ in range(8):
        if not isinstance(value, dict):
            return {}
        ref = value.get("$ref")
        if ref is None:
            return value
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return {}
        seen.add(ref)
        value = document
        for key in ref[2:].split("/"):
            value = value.get(key.replace("~1", "/").replace("~0", "~"), {}) if isinstance(value, dict) else {}
    return {}


def _api_parameters(values, document):
    parameters = {}
    unresolved = False
    if not isinstance(values, list):
        return (), True
    for value in values[:256]:
        value = _resolve(value, document)
        name, location = value.get("name"), value.get("in")
        if not isinstance(name, str) or not 1 <= len(name) <= 256 or location not in {"query", "path", "header", "cookie", "body", "formData"}:
            unresolved = True
            continue
        schema = _resolve(value.get("schema", value), document)
        parameters[(location, name)] = EndpointParameter(
            name=name, location=location, required=location == "path" or value.get("required") is True,
            data_type=str(schema.get("type", "unknown"))[:64],
        )
    return tuple(parameters.values()), unresolved or len(values) > 256


def parse_openapi(text: str, base: str) -> ParseResult:
    if text.lstrip().startswith("{"):
        document = json.loads(text)
    else:
        if any(isinstance(token, yaml.tokens.AliasToken) for token in yaml.scan(text)):
            raise ValueError("YAML aliases are not supported")
        document = yaml.safe_load(text)
    if not isinstance(document, dict) or not (str(document.get("openapi", "")).startswith("3.") or document.get("swagger") == "2.0"):
        raise ValueError("not an OpenAPI 3 or Swagger 2 document")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("invalid OpenAPI paths")
    collector = Collector(base)
    swagger = document.get("swagger") == "2.0"
    origin = urlsplit(base)
    for path, raw_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        item = _resolve(raw_item, document)
        inherited, unresolved = _api_parameters(item.get("parameters", []), document)
        for method, raw_operation in item.items():
            if not isinstance(method, str) or method.upper() not in METHODS or not isinstance(raw_operation, dict):
                continue
            operation = _resolve(raw_operation, document)
            own, unknown = _api_parameters(operation.get("parameters", []), document)
            parameters = {(p.location, p.name): p for p in (*inherited, *own)}
            manual = unresolved or unknown or bool(operation.get("security", document.get("security")))
            if "requestBody" in operation:
                manual = True
                parameters[("body", "body")] = EndpointParameter(name="body", location="body", required=True)
            if swagger:
                schemes = document.get("schemes", [origin.scheme])
                servers = [{"url": f"{scheme}://{document.get('host', origin.netloc)}{document.get('basePath', '/')}"}
                           for scheme in schemes if scheme in {"http", "https"}] if isinstance(schemes, list) else []
            else:
                servers = operation.get("servers", item.get("servers", document.get("servers", [{"url": "/"}])))
                if servers == []:
                    servers = [{"url": "/"}]
            if not isinstance(servers, list):
                continue
            for server in servers[:16]:
                value = server.get("url") if isinstance(server, dict) else None
                if not isinstance(value, str) or any(c in value for c in "{}?#"):
                    continue
                server_url = normalize_candidate(value.rstrip("/") + "/", base)
                if server_url:
                    collector.add(server_url.rstrip("/") + path, method=method.upper(),
                                  parameters=tuple(parameters.values()), relation="operation", manual=manual)
    return collector.result(DiscoveryKind.OPENAPI)


def parse_javascript(text: str, base: str) -> ParseResult:
    collector = Collector(base)
    fetch = r"\bfetch\s*\(\s*(['\"])([^'\"\r\n]+)\1\s*(?=[,)])(?:,\s*(\{[^}]{0,2048}\}))?"
    for match in re.finditer(fetch, text):
        value, options = match[2], match[3] or ""
        if any(c in value for c in "{}$"):
            continue
        explicit = re.search(r"\bmethod\s*:\s*['\"]([A-Za-z]+)['\"]", options)
        method = explicit[1].upper() if explicit else "GET"
        # Only a literal method-only options object is understood. Spreads, headers,
        # credentials and computed properties cannot establish a safe automatic call.
        manual = bool(options and not re.fullmatch(r"\{\s*method\s*:\s*['\"][A-Za-z]+['\"]\s*,?\s*\}", options))
        # An unparsed options expression cannot safely imply GET.
        manual |= text[match.end():].lstrip().startswith(",")
        if method in METHODS:
            collector.add(value, method=method, relation="fetch", manual=manual)
    for match in re.finditer(r"\baxios\.(get|head|post|put|patch|delete)\s*\(\s*(['\"])([^'\"\r\n]+)\2\s*(?=[,)])", text):
        collector.add(match[3], method=match[1].upper(), relation="axios",
                      manual=text[match.end():].lstrip().startswith(","))
    for match in re.finditer(r"\.open\s*\(\s*['\"](GET|HEAD|POST|PUT|PATCH|DELETE)['\"]\s*,\s*(['\"])([^'\"\r\n]+)\2\s*(?=[,)])", text):
        collector.add(match[3], method=match[1], relation="xhr")
    return collector.result(DiscoveryKind.JAVASCRIPT)


def parse_document(text: str, base: str, content_type: str, hint: DiscoveryKind) -> ParseResult:
    if len(text.encode("utf-8")) > 524288:
        raise ValueError("discovery document exceeds parser limit")
    path = urlsplit(base).path.lower()
    if hint == DiscoveryKind.ROBOTS or path.endswith("/robots.txt"):
        return parse_robots(text, base)
    if hint in {DiscoveryKind.SITEMAP, DiscoveryKind.SITEMAP_INDEX} or "xml" in content_type or path.endswith(".xml"):
        return parse_sitemap(text, base)
    if hint == DiscoveryKind.OPENAPI or "yaml" in content_type or path.endswith(("openapi.json", "swagger.json", ".yaml", ".yml")):
        return parse_openapi(text, base)
    if "json" in content_type:
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if isinstance(value, dict) and ("openapi" in value or "swagger" in value):
            return parse_openapi(text, base)
    if hint == DiscoveryKind.JAVASCRIPT or "javascript" in content_type or path.endswith(".js"):
        return parse_javascript(text, base)
    if "html" in content_type or text.lstrip().lower().startswith(("<!doctype html", "<html")):
        return parse_html(text, base)
    return ParseResult(hint, ())
