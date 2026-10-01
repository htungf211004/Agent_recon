"""Bounded offline parsing of already acquired Recon evidence."""

import base64
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit
from xml.etree import ElementTree

from src.recon.gateway import AdapterOutput
from src.recon.models import Capability, EvidenceCapabilityRequest, ReconObservation

SAFE_PATH = re.compile(r"^/?[A-Za-z0-9_./-]{1,160}$")
SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


class OfflineEvidenceAdapter:
    def __init__(self, evidence) -> None:
        self.evidence = evidence

    def execute(self, request: EvidenceCapabilityRequest) -> AdapterOutput:
        raw = self.evidence.read(request.evidence_ref)
        if raw is None or len(raw) > request.parameters.max_input_bytes:
            return AdapterOutput(status="error", message="evidence missing or exceeds offline byte limit")
        envelope = json.loads(raw)
        if not isinstance(envelope, dict) or "body_base64" not in envelope:
            return AdapterOutput(status="error", message="HTTP evidence envelope required")
        raw = base64.b64decode(envelope["body_base64"], validate=True)
        metadata = envelope.get("response", {})
        if (len(raw) > request.parameters.max_input_bytes or len(raw) != metadata.get("body_size")
                or hashlib.sha256(raw).hexdigest() != metadata.get("body_sha256")):
            return AdapterOutput(status="error", message="HTTP evidence body integrity mismatch")
        if request.capability == Capability.SOURCEMAP_ANALYZE:
            data, observations = self._sourcemap(raw, request.parameters.max_items)
        else:
            data, observations = self._wsdl(raw, request.parameters.max_items)
        return AdapterOutput(status="success", raw_output=json.dumps(data, sort_keys=True).encode(),
                             observations=observations)

    @staticmethod
    def _sourcemap(raw: bytes, limit: int):
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("version") != 3:
            raise ValueError("not a version 3 source map")
        sources = payload.get("sources", [])
        if not isinstance(sources, list):
            raise ValueError("invalid source map sources")
        safe = sorted({source for source in sources if isinstance(source, str) and SAFE_PATH.fullmatch(source)})[:limit]
        embedded = payload.get("sourcesContent", [])
        data = {"version": 3, "source_count": len(sources), "sources": safe,
                "name_count": len(payload.get("names", [])),
                "embedded_source_count": sum(value is not None for value in embedded) if isinstance(embedded, list) else 0}
        observations = tuple(ReconObservation(kind="METADATA", value=source,
                                              source=Capability.SOURCEMAP_ANALYZE) for source in safe)
        return data, observations

    @staticmethod
    def _wsdl(raw: bytes, limit: int):
        # ElementTree never fetches imports, but reject all DTD/entity declarations
        # before parsing so expansion is impossible as well.
        if b"<!" in raw or b"<?" in raw.replace(b"<?xml", b"", 1):
            raise ValueError("WSDL DTD or processing instruction forbidden")
        root = ElementTree.fromstring(raw)
        def local(tag):
            return tag.rsplit("}", 1)[-1]
        fields = {"service": [], "port": [], "binding": [], "operation": [], "endpoint": [], "import": []}
        for node in root.iter():
            tag = local(node.tag)
            field = {"service": "service", "port": "port", "binding": "binding",
                     "operation": "operation", "address": "endpoint", "import": "import"}.get(tag)
            if field is None or len(fields[field]) >= limit:
                continue
            value = node.attrib.get("location" if field in {"endpoint", "import"} else "name", "")
            # URLs are only metadata. No import or declared endpoint is followed.
            if field in {"endpoint", "import"}:
                try:
                    parts = urlsplit(value)
                except ValueError:
                    continue
                if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
                    continue
                value = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            elif not SAFE_NAME.fullmatch(value):
                continue
            if value and len(value) <= 256 and not any(char in value for char in "\r\n<>"):
                fields[field].append(value)
        observations = tuple(ReconObservation(kind="PROTOCOL", value=value,
                                              source=Capability.WSDL_DISCOVERY)
                             for value in fields["operation"][:limit])
        return fields, observations
