"""Acceptance invariants for staged records; knowledge never becomes execution authority."""

import re

from src.contracts.recon_kb import LookupRecord, RunnerDataManifest, StorageClass, VectorKnowledgeRecord
from src.recon.kb.adapters import SECLISTS_PATHS, WSTG_ROOT, WSTG_SCENARIOS, methodology, sanitize_wordlist
from src.recon.kb.utils import contained, sha256_file

EXECUTABLE_KEYS = {"http", "requests", "raw", "payloads", "network", "code", "javascript", "headless", "flow",
                   "variables", "attack", "body", "matchers", "extractors"}
NUCLEI_FIELDS = {"template_id", "name", "description", "severity", "tags", "references", "cve_ids", "cwe_ids",
                 "cvss_score", "cvss_metrics", "vendor", "product", "max_request", "validation_available",
                 "recon_execution_allowed", "candidate_type"}


def no_executable_sections(value):
    if isinstance(value, dict):
        if value.keys() & EXECUTABLE_KEYS:
            raise ValueError("executable Nuclei section in normalized metadata")
        for item in value.values():
            no_executable_sections(item)
    elif isinstance(value, list):
        for item in value:
            no_executable_sections(item)


def acceptance(records, manifest, root, spec):
    if not records and spec.source_id not in {"OSV", "NVD_CPE"}:
        raise ValueError("empty normalized dataset")
    identities = set()
    for record in records:
        if record.source_id != manifest.source_id or record.storage_class != manifest.storage_class:
            raise ValueError("storage class or source mismatch")
        identity = (record.knowledge_id if isinstance(record, VectorKnowledgeRecord) else
                    record.runner_data_id if isinstance(record, RunnerDataManifest) else record.record_id)
        if identity in identities:
            raise ValueError("duplicate normalized identity")
        identities.add(identity)
        if isinstance(record, VectorKnowledgeRecord):
            if spec.source_id not in {"WSTG", "KATANA", "AMASS_OAM"}:
                raise ValueError("source is not approved for vector ingestion")
            if re.search(r"(?i)(```|<script|\$\(|curl\s|wget\s|/bin/(?:ba)?sh|union\s+select)", record.model_dump_json()):
                raise ValueError("weaponized vector content")
            if spec.source_id == "WSTG":
                match = re.fullmatch(r"WSTG-INFO-(\d{2})", record.knowledge_id)
                if not match or int(match[1]) not in WSTG_SCENARIOS or not record.source_record.startswith(WSTG_ROOT + "/"):
                    raise ValueError("unapproved WSTG subset")
                expected = methodology(manifest, record.source_record, record.knowledge_id, *WSTG_SCENARIOS[int(match[1])])
                if record != expected:
                    raise ValueError("WSTG record differs from reviewed Recon compiler")
        elif isinstance(record, RunnerDataManifest):
            if spec.source_id == "SECLISTS" and record.source_record not in SECLISTS_PATHS:
                raise ValueError("SecLists path is not explicitly allowlisted")
            expected_prefix = f"runner_data/{spec.source_id}/{manifest.snapshot_id}/"
            if not record.local_path.startswith(expected_prefix):
                raise ValueError("runner file outside this dataset snapshot")
            path = contained(root, record.local_path)
            if sha256_file(path) != record.sha256:
                raise ValueError("runner data digest mismatch")
            content = path.read_bytes()
            if sanitize_wordlist(content) != content or len(content.splitlines()) != record.line_count:
                raise ValueError("runner wordlist integrity or normalization mismatch")
        elif isinstance(record, LookupRecord):
            if record.dataset != spec.source_id:
                raise ValueError("lookup dataset mismatch")
            if spec.source_id == "NUCLEI_META":
                if set(record.value) != NUCLEI_FIELDS:
                    raise ValueError("Nuclei metadata projection mismatch")
                no_executable_sections(record.value)
                for key in ("template_id", "name", "description", "severity"):
                    if not isinstance(record.value[key], str):
                        raise ValueError("Nuclei metadata string required")
                for key in ("vendor", "product", "cvss_metrics"):
                    if record.value[key] is not None and not isinstance(record.value[key], str):
                        raise ValueError("invalid Nuclei scalar metadata")
                for key in ("cvss_score", "max_request"):
                    if record.value[key] is not None and type(record.value[key]) not in {int, float}:
                        raise ValueError("invalid Nuclei numeric metadata")
                if record.value["cvss_score"] is not None and not 0 <= record.value["cvss_score"] <= 10:
                    raise ValueError("CVSS score out of bounds")
                for key in ("tags", "references", "cve_ids", "cwe_ids"):
                    if not isinstance(record.value[key], list) or not all(isinstance(item, str) for item in record.value[key]):
                        raise ValueError("invalid Nuclei metadata list")
                if record.value["recon_execution_allowed"] is not False or record.value["candidate_type"] != "ValidationCandidate":
                    raise ValueError("Nuclei metadata cannot enable execution")
            if spec.source_id == "OSV" and record.value.get("withdrawn") and record.value.get("active_candidate"):
                raise ValueError("withdrawn OSV advisory cannot create active candidate")
    if spec.source_id == "WSTG" and identities != {f"WSTG-INFO-{number:02d}" for number in WSTG_SCENARIOS}:
        raise ValueError("incomplete WSTG coverage")
    return {"provenance": True, "hashes": True, "class_isolation": True, "source_acceptance": True,
            "record_count": len(records), "storage_class": StorageClass(manifest.storage_class).value}
