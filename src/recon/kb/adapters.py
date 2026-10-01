"""Deterministic metadata projections and manually compiled safe Recon methodology."""

import csv
import hashlib
import io
import json
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from src.contracts.execution import Risk
from src.contracts.recon_kb import (
    LookupRecord,
    ReconContent,
    RunnerConstraints,
    RunnerDataManifest,
    VectorKnowledgeRecord,
)
from src.recon.kb.fetchers import package_query
from src.recon.kb.registry import validate_url
from src.recon.kb.utils import atomic_write, contained, sha256_file

ADAPTER_VERSION = "2.0.0"
WSTG_ROOT = "document/4-Web_Application_Security_Testing/01-Information_Gathering"
SECLISTS_PATHS = (
    "Discovery/Web-Content/common.txt", "Discovery/Web-Content/raft-small-directories.txt",
    "Discovery/Web-Content/raft-small-files.txt", "Discovery/Web-Content/graphql.txt",
)
# Upstream prose is never copied into executable or vector context. One reviewed semantic document per scenario.
WSTG_SCENARIOS = {
    1: ("Search engine discovery", "public_references", "Review public search results referring to authorized hosts.", "HOST", "search_engine_osint", "DiscoveredAsset"),
    2: ("Fingerprint web server", "service_metadata", "Inspect existing response headers and service evidence.", "SERVICE", "http_probe", "Service"),
    3: ("Review webserver metafiles", "metafiles", "Review same-origin robots.txt and sitemap references using bounded GET or HEAD.", "PATH", "http_fetch", "PATH"),
    4: ("Enumerate applications", "application_inventory", "Inventory applications referenced by existing pages and authorized origins.", "URL", "http_fetch", "DiscoveredAsset"),
    5: ("Review webpage content", "page_metadata", "Inspect existing HTML comments, script references and linked resources.", "PATH", "http_fetch", "PATH"),
    6: ("Identify application entry points", "entry_points", "Record observed routes, methods and parameter names from existing evidence.", "API", "http_fetch", "ENDPOINT_CANDIDATE"),
    7: ("Map application execution paths", "route_relationships", "Map observed navigation and route relationships from passive browsing evidence.", "URL", "browser_explore", "PATH"),
    8: ("Fingerprint application framework", "technology_inventory", "Compare existing static resources and response metadata with framework references.", "TECHNOLOGY", "whatweb", "TechnologyObservation"),
    9: ("Fingerprint web application", "application_metadata", "Record application identity indicators from existing resource and response evidence.", "TECHNOLOGY", "whatweb", "TechnologyObservation"),
    10: ("Map application architecture", "architecture_inventory", "Map evidenced host, service and application relationships.", "HOST", "http_probe", "AttackSurfaceInventory"),
}


def provenance(manifest, source_record):
    keys = ("source_id", "source_url", "source_version", "source_commit", "retrieved_at", "snapshot_id")
    return {**{key: getattr(manifest, key) for key in keys}, "source_record": source_record}


def lookup(manifest, source_record, key, value, *, dataset=None, lookup_keys=None):
    return LookupRecord(**provenance(manifest, source_record), record_id=f"{manifest.source_id}:{key}",
                        dataset=dataset or manifest.source_id, lookup_keys=lookup_keys or {"id": key}, value=value)


def methodology(manifest, source_record, identity, title, category, action, asset_type, capability, output):
    return VectorKnowledgeRecord(
        **provenance(manifest, source_record), knowledge_id=identity, namespace=manifest.namespace,
        title=title, category=category, asset_types=(asset_type,), capabilities=(capability,), risk=Risk.R0,
        requires=("operator_authorized_scope", "gateway_verified_evidence"), produces=(output,),
        api_related=output == "ENDPOINT_CANDIDATE",
        content=ReconContent(objective="Complete " + category.replace("_", " ") + " in the attack surface inventory.",
            applies_when=("The authorized inventory has an unresolved coverage gap for this category.",),
            safe_actions=(action,), expected_observations=(output + " indicators with source relationships.",),
            evidence_required=("Gateway evidence reference, observed origin, retrieval time and response metadata.",),
            follow_up=("Submit only evidence-backed candidates to existing scope classification and policy checks.",),
            completion_rule="Stop when evidenced inventory coverage is recorded or the authorized budget is exhausted; record limitations."))


def wstg(raw, manifest, reports):
    if manifest.source_version != "v4.2":
        raise ValueError("WSTG compiler is reviewed only for v4.2")
    records, seen = [], set()
    for path in sorted((raw / WSTG_ROOT).glob("*.md")):
        text = path.read_text(encoding="utf-8-sig")
        match = re.search(r"\bWSTG-INFO-(\d{2})\b", text)
        if not match:
            continue
        number = int(match[1])
        if number not in WSTG_SCENARIOS or number in seen:
            raise ValueError("unapproved or duplicate WSTG scenario")
        seen.add(number)
        records.append(methodology(manifest, path.relative_to(raw).as_posix(), f"WSTG-INFO-{number:02d}",
                                   *WSTG_SCENARIOS[number]))
    if seen != set(WSTG_SCENARIOS):
        raise ValueError("WSTG INFO-01 through INFO-10 are required")
    return records


class WordlistSafetyError(ValueError):
    def __init__(self, rule):
        self.rule = rule
        super().__init__("wordlist rejected: " + rule)


def sanitize_wordlist(raw: bytes) -> bytes:
    if b"\x00" in raw:
        raise WordlistSafetyError("NUL")
    words, seen = [], set()
    for line in raw.decode("utf-8-sig", errors="strict").splitlines():
        word = line.strip()
        if not word or word.startswith(("#", "//")):
            continue
        decoded = unquote(unquote(word))
        rules = (
            ("MAX_LINE_LENGTH", len(word) > 512),
            ("CONTROL_CHARACTER", any(ord(char) < 32 or ord(char) == 127 for char in word)),
            ("ABSOLUTE_URL_OR_PATH", bool(urlsplit(decoded).scheme) or decoded.startswith(("/", "\\"))),
            ("TRAVERSAL", ".." in decoded.replace("\\", "/").split("/")),
            ("PAYLOAD_OR_MUTATION_CHARACTER", any(char in decoded for char in "<>\x00\r\n`|;&{}")),
            ("COMMAND_OR_PLACEHOLDER", bool(re.search(r"(?i)(\$\(|union\s+select|javascript:|%00)", decoded)) or "FUZZ" in decoded),
        )
        for rule, failed in rules:
            if failed:
                raise WordlistSafetyError(rule)
        if word not in seen:
            seen.add(word)
            words.append(word)
    if not words:
        raise ValueError("empty wordlist")
    return ("\n".join(words) + "\n").encode()


def runner_record(raw_path, source_record, manifest, runner_root, *, api=False, technology=None):
    content = sanitize_wordlist(raw_path.read_bytes())
    digest = hashlib.sha256(content).hexdigest()
    blob = contained(runner_root, f"runner_data/blobs/{digest}.txt")
    if blob.exists():
        if sha256_file(blob) != digest:
            raise ValueError("immutable runner blob digest mismatch")
    else:
        atomic_write(blob, content)
    identity = manifest.source_id.lower() + "-" + hashlib.sha256(source_record.encode()).hexdigest()[:16]
    relative = f"runner_data/{manifest.source_id}/{manifest.snapshot_id}/{identity}.txt"
    output = contained(runner_root, relative)
    if output.exists():
        if output.read_bytes() != content:
            raise ValueError("immutable normalized runner file differs from source")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        # Fail explicitly on filesystems without hardlinks; never claim dedupe after a byte copy.
        os.link(blob, output)
    return RunnerDataManifest(**provenance(manifest, source_record), runner_data_id=identity,
        local_path=relative, sha256=sha256_file(output), line_count=len(content.splitlines()),
        constraints=RunnerConstraints(api_related=api, technology_required=technology))


def seclists(raw, manifest, reports, runner_root):
    records = []
    for name in SECLISTS_PATHS:
        path = contained(raw, name)
        if not path.exists():
            reports.append("missing allowlisted wordlist (no substitution): " + name)
            continue
        try:
            records.append(runner_record(path, name, manifest, runner_root, api=name.endswith("graphql.txt")))
        except ValueError as error:
            # Reject the entire file, retaining only independently safe allowlisted files. Never repair entries.
            reports.append("rejected unsafe allowlisted wordlist (no rewrite or substitution): " + name
                           + "; rule=" + getattr(error, "rule", "INVALID_WORDLIST"))
    if not records:
        raise ValueError("no allowlisted SecLists files")
    return records


class DownloadLink(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.urls.extend(value for key, value in attrs if key == "href")


def assetnote_downloads(raw, spec):
    approved = []
    for selection in spec.assetnote_selections:
        if set(selection) != {"manifest", "filename", "technology", "api_related"}:
            raise ValueError("invalid Assetnote selection")
        name = selection["manifest"]
        if name not in {"data/automated.json", "data/technologies.json", "data/manual.json"}:
            raise ValueError("unapproved Assetnote manifest")
        filename = selection["filename"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.txt", filename) or any(term in filename.lower() for term in
                ("password", "credential", "payload", "fuzz", "shell", "parameter", "subdomain")):
            raise ValueError("unapproved Assetnote dataset")
        value = json.loads(contained(raw, name).read_text(encoding="utf-8"))
        entries = [entry for entry in value["data"] if entry.get("Filename") == filename]
        if len(entries) != 1:
            raise ValueError("selected Assetnote dataset missing or ambiguous")
        parser = DownloadLink()
        parser.feed(entries[0]["Download"])
        if len(parser.urls) != 1:
            raise ValueError("Assetnote manifest must contain exactly one download URL")
        url = validate_url(parser.urls[0], ("wordlists-cdn.assetnote.io",))
        if urlsplit(url).query or Path(urlsplit(url).path).name != filename:
            raise ValueError("Assetnote URL does not match selected filename")
        if name == "data/technologies.json" and not selection["technology"]:
            raise ValueError("technology wordlist requires explicit runtime technology gate")
        api = selection["api_related"] or "api" in filename.lower() or "graphql" in filename.lower()
        approved.append({**selection, "url": url, "api_related": bool(api)})
    return approved


def assetnote(raw, manifest, reports, runner_root, spec):
    records = []
    for selection in assetnote_downloads(raw, spec):
        name = "downloads/" + selection["filename"]
        records.append(runner_record(contained(raw, name), selection["manifest"] + "#" + selection["filename"],
                                     manifest, runner_root, api=selection["api_related"], technology=selection["technology"]))
    if not records:
        raise ValueError("no selected Assetnote datasets")
    return records


def _strings(value):
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(dict.fromkeys(value))
    if value is None:
        return []
    raise ValueError("expected string list")


def cve_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", value):
        raise ValueError("exact uppercase CVE ID required")
    return value


def cwe_id(value):
    text = str(value).upper()
    if not re.fullmatch(r"(?:CWE-)?[1-9]\d*", text):
        raise ValueError("invalid CWE ID")
    return text if text.startswith("CWE-") else "CWE-" + text


def safe_description(value):
    text = str(value or "")[:8000]
    if re.search(r"(?i)(```|<script|\$\(|curl\s|wget\s|union\s+select|/bin/(?:ba)?sh|powershell\s)", text):
        return "Description omitted by metadata security filter."
    return text


def nuclei(raw, manifest, reports):
    records = []
    for path in sorted(raw.rglob("*.yaml")):
        relative = path.relative_to(raw).as_posix()
        try:
            value = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not isinstance(value.get("info"), dict):
                raise ValueError("invalid metadata schema")
            info = value["info"]
            classification, metadata = info.get("classification", {}), info.get("metadata", {})
            # Explicit projection: execution sections cannot survive even when new upstream keys are introduced.
            projected = {
                "template_id": str(value["id"]), "name": safe_description(info["name"]),
                "description": safe_description(info.get("description")),
                "severity": str(info.get("severity", "unknown")),
                "tags": _strings(info.get("tags")), "references": _strings(info.get("reference")),
                "cve_ids": [cve_id(item) for item in _strings(classification.get("cve-id"))],
                "cwe_ids": [cwe_id(item) for item in _strings(classification.get("cwe-id"))],
                "cvss_score": classification.get("cvss-score"), "cvss_metrics": classification.get("cvss-metrics"),
                "vendor": metadata.get("vendor"), "product": metadata.get("product"),
                "max_request": metadata.get("max-request"), "validation_available": True,
                "recon_execution_allowed": False, "candidate_type": "ValidationCandidate",
            }
            records.append(lookup(manifest, relative, projected["template_id"], projected,
                                  lookup_keys={"cve_ids": projected["cve_ids"],
                                               "template_id": projected["template_id"]}))
        except (KeyError, TypeError, ValueError, yaml.YAMLError) as error:
            reason = ("INVALID_CWE_ID" if "CWE" in str(error) else
                      "INVALID_CVE_ID" if "CVE" in str(error) else "INVALID_METADATA_SCHEMA")
            reports.append(f"rejected Nuclei metadata: {relative}; rule={reason}")
    if not records:
        raise ValueError("no valid Nuclei metadata records")
    return records


def kev(raw, manifest, reports):
    from jsonschema import FormatChecker
    from jsonschema.validators import validator_for

    path = raw / "known_exploited_vulnerabilities.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads((raw / "known_exploited_vulnerabilities_schema.json").read_text(encoding="utf-8"))
    # Reject remote refs: upstream schema cannot trigger arbitrary network reads.
    def check_refs(node):
        if isinstance(node, dict):
            if "$ref" in node and not node["$ref"].startswith("#"):
                raise ValueError("external schema references are not approved")
            for child in node.values():
                check_refs(child)
        elif isinstance(node, list):
            for child in node:
                check_refs(child)

    check_refs(schema)
    validator = validator_for(schema)
    validator.check_schema(schema)
    validator(schema, format_checker=FormatChecker()).validate(value)
    records = []
    for item in value["vulnerabilities"]:
        key = cve_id(item["cveID"])
        projected = {"cve_id": key, "vendor": item["vendorProject"], "product": item["product"],
            "name": item["vulnerabilityName"], "date_added": item["dateAdded"],
            "description": safe_description(item["shortDescription"]), "known_exploited": True,
            "known_ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": [cwe_id(item) for item in item.get("cwes", [])], "catalog_version": value["catalogVersion"]}
        records.append(lookup(manifest, "known_exploited_vulnerabilities.json#" + key, key, projected,
                              lookup_keys={"cve_id": key}))
    return records


def psl(raw, manifest, reports):
    section, records = None, []
    for number, line in enumerate((raw / "public_suffix_list.dat").read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if line == "// ===BEGIN ICANN DOMAINS===":
            section = "ICANN"
        elif line == "// ===BEGIN PRIVATE DOMAINS===":
            section = "PRIVATE"
        elif line in {"// ===END ICANN DOMAINS===", "// ===END PRIVATE DOMAINS==="}:
            section = None
        elif line and not line.startswith("//"):
            if section is None:
                raise ValueError("PSL rule outside recognized section")
            kind = "EXCEPTION" if line.startswith("!") else "WILDCARD" if line.startswith("*.") else "EXACT"
            suffix = line.removeprefix("!").removeprefix("*.").encode("idna").decode("ascii").lower()
            if not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*", suffix):
                raise ValueError("invalid PSL rule")
            records.append(lookup(manifest, f"public_suffix_list.dat:{number}", section + ":" + line,
                {"suffix": suffix, "rule_type": kind, "section": section}, lookup_keys={"suffix": suffix}))
    return records


def _csv(path, required):
    reader = csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig")))
    if not reader.fieldnames or not set(required).issubset(reader.fieldnames):
        raise ValueError("upstream CSV schema missing required columns")
    return reader


def iana_well_known(raw, manifest, reports):
    records = []
    for number, row in enumerate(_csv(raw / "well-known-uris.csv", ("URI Suffix", "Status", "Reference", "Date Registered", "Date Modified")), 2):
        suffix = row["URI Suffix"].strip()
        if not suffix:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.~-]+", suffix):
            raise ValueError("invalid well-known suffix")
        value = {"suffix": suffix, "path": "/.well-known/" + suffix, "status": row["Status"],
            "references": _strings(row["Reference"]), "registered_at": row["Date Registered"] or None,
            "modified_at": row["Date Modified"] or None, "methods": ["GET", "HEAD"],
            "same_origin": True, "risk": "R0", "target_presence_confirmed": False}
        records.append(lookup(manifest, f"well-known-uris.csv:{number}", suffix, value, lookup_keys={"suffix": suffix}))
    return records


def iana_ports(raw, manifest, reports):
    records = []
    columns = ("Service Name", "Port Number", "Transport Protocol", "Description", "Reference", "Assignment Notes")
    for number, row in enumerate(_csv(raw / "service-names-port-numbers.csv", columns), 2):
        ports, transport = row["Port Number"].strip(), row["Transport Protocol"].strip().lower()
        if not ports or transport not in {"tcp", "udp", "sctp", "dccp"}:
            continue
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", ports)
        if not match:
            raise ValueError("invalid registered port range")
        start, end = int(match[1]), int(match[2] or match[1])
        if not 0 <= start <= end <= 65535:
            raise ValueError("registered port out of bounds")
        value = {"service_name": row["Service Name"], "port_start": start, "port_end": end,
            "transport": transport, "description": row["Description"], "references": _strings(row["Reference"]),
            "assignment_notes": row["Assignment Notes"], "record_kind": "registered_service"}
        records.append(lookup(manifest, f"service-names-port-numbers.csv:{number}", str(number), value,
                              lookup_keys={"port_start": start, "port_end": end, "transport": transport}))
    return records


def parse_cpe23(value):
    # Split only unescaped separators; retain escaped component punctuation.
    parts = []
    current, escaped = [], False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        raise ValueError("unterminated CPE escape")
    parts.append("".join(current))
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"] or parts[2] not in {"a", "h", "o", "*", "-"}:
        raise ValueError("invalid CPE 2.3 name")
    return dict(zip(("part", "vendor", "product", "version", "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"), parts[2:], strict=True))


def nvd_cpe(raw, manifest, reports):
    records = []
    for path in sorted(raw.glob("page-*.json")):
        response = json.loads(path.read_text(encoding="utf-8"))
        for number, wrapper in enumerate(response["products"]):
            item = wrapper["cpe"]
            if not isinstance(item["deprecated"], bool):
                raise ValueError("invalid CPE deprecated flag")
            parsed = parse_cpe23(item["cpeName"])
            value = {"cpe_name_id": item["cpeNameId"], "cpe23_uri": item["cpeName"],
                "deprecated": item["deprecated"], "deprecated_by": item.get("deprecatedBy", []),
                "titles": item.get("titles", []), "created": item["created"], "last_modified": item["lastModified"],
                **parsed, "match_status": "CANDIDATE"}
            records.append(lookup(manifest, path.name + f"#products/{number}", item["cpeNameId"], value,
                                  lookup_keys={"cpe_name_id": item["cpeNameId"], "vendor": parsed["vendor"], "product": parsed["product"]}))
    return records


def cwe(raw, manifest, reports):
    archives = list(raw.glob("*.zip"))
    if len(archives) != 1:
        raise ValueError("CWE requires one canonical XML release archive")
    with zipfile.ZipFile(archives[0]) as archive:
        names = [item for item in archive.infolist() if item.filename.endswith(".xml")]
        if len(names) != 1 or names[0].file_size > 64_000_000:
            raise ValueError("invalid or excessive CWE release")
        # Do not extract paths supplied by the archive.
        data = archive.read(names[0])
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)", data, re.I):
        raise ValueError("CWE XML entities are disallowed")
    root = ET.fromstring(data)
    namespace = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
    records = []
    for item in root.iter(namespace + "Weakness"):
        key = cwe_id(item.attrib["ID"])
        description = item.find(namespace + "Description")
        related = [{"cwe_id": cwe_id(child.attrib["CWE_ID"]), "nature": child.attrib.get("Nature"),
                    "view_id": child.attrib.get("View_ID")} for child in item.iter(namespace + "Related_Weakness")]
        value = {"cwe_id": key, "name": item.attrib["Name"], "abstraction": item.attrib["Abstraction"],
            "status": item.attrib["Status"], "description": safe_description("".join(description.itertext()) if description is not None else ""),
            "related_weaknesses": related, "release_version": root.attrib.get("Version")}
        records.append(lookup(manifest, archives[0].name + "#" + names[0].filename + "#" + key, key, value, lookup_keys={"cwe_id": key}))
    return records


def osv(raw, manifest, reports):
    records = []
    for path in sorted(raw.glob("query-*-page-*.json")):
        if path.name.endswith(".context.json"):
            continue
        query = json.loads(path.with_suffix(".context.json").read_text(encoding="utf-8"))
        package_query(query)
        response = json.loads(path.read_text(encoding="utf-8"))
        for item in response.get("vulns", []):
            affected = [{"package": {key: entry["package"].get(key) for key in ("name", "ecosystem", "purl")},
                         "ranges": entry.get("ranges", []), "versions": entry.get("versions", [])}
                        for entry in item["affected"]]
            if not any((query.get("purl") and entry["package"]["purl"] == query["purl"]) or
                       (query.get("name") and entry["package"]["name"] == query["name"]
                        and entry["package"]["ecosystem"] == query["ecosystem"]) for entry in affected):
                raise ValueError("OSV advisory package identity differs from evidence query")
            value = {key: item.get(key) for key in ("id", "published", "modified", "withdrawn", "summary")}
            database = item.get("database_specific", {})
            value.update(aliases=_strings(item.get("aliases")), affected=affected, severity=item.get("severity", []),
                references=[{"type": entry["type"], "url": entry["url"]} for entry in item.get("references", [])
                            if entry.get("type") in {"ADVISORY", "REPORT", "WEB"}],
                active_candidate=not bool(item.get("withdrawn")), package_evidence_ref=query["evidence_ref"],
                source_database=database.get("database") or item["id"].split("-")[0],
                source_record=item["id"], source_license=database.get("license"))
            records.append(lookup(manifest, path.name + "#" + item["id"], item["id"] + ":" + query["evidence_ref"],
                                  value, lookup_keys={"id": item["id"], "package": query.get("name") or query.get("purl")}))
    return records


def curated_tool(raw, manifest, reports, spec):
    source_record = spec.paths[0]
    if not source_record.endswith(".md") or not contained(raw, source_record).is_file():
        raise ValueError("curated methodology requires upstream README provenance")
    if manifest.source_id == "KATANA":
        values = ("Katana bounded crawl", "linked_route_discovery",
                  "Inventory links and route indicators within the operator-authorized origin using the existing bounded crawl capability.",
                  "URL", "web_crawl", "ENDPOINT_CANDIDATE")
    else:
        values = ("Amass open asset model", "asset_relationships",
                  "Represent evidenced hosts, services and relationships; submit discovered candidates to existing scope classification.",
                  "HOST", "passive_infra_enum", "DiscoveredAsset")
    record = methodology(manifest, source_record, manifest.source_id + "-RECON-01", *values)
    if manifest.source_id == "KATANA":
        record = record.model_copy(update={"risk": Risk.R1})
    return [record]


def normalize(raw, manifest, spec, runner_root, reports):
    source = spec.source_id
    if source == "RECON_CURATED":
        from src.recon.kb.coverage import compile_curated_knowledge

        return compile_curated_knowledge(raw, manifest)
    if source == "WSTG":
        return wstg(raw, manifest, reports)
    if source == "SECLISTS":
        return seclists(raw, manifest, reports, runner_root)
    if source == "ASSETNOTE":
        return assetnote(raw, manifest, reports, runner_root, spec)
    if source in {"KATANA", "AMASS_OAM"}:
        return curated_tool(raw, manifest, reports, spec)
    adapters = {"NUCLEI_META": nuclei, "CISA_KEV": kev, "PSL": psl, "IANA_WELL_KNOWN": iana_well_known,
                "IANA_PORTS": iana_ports, "NVD_CPE": nvd_cpe, "CWE": cwe, "OSV": osv}
    if source not in adapters:
        raise ValueError("adapter disabled or unavailable")
    return adapters[source](raw, manifest, reports)
