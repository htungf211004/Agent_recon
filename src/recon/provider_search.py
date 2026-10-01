"""Fixed-endpoint provider queries with normalized, secret-free evidence."""

import base64
import ipaddress
import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from src.recon.gateway import AdapterOutput
from src.recon.models import ProviderCapabilityRequest, ReconObservation

ENV_KEYS = {"shodan": "SHODAN_API_KEY", "censys": "CENSYS_API_TOKEN",
            "fofa": "FOFA_API_KEY", "github": "GITHUB_TOKEN", "gitlab": "GITLAB_TOKEN",
            "brave": "BRAVE_SEARCH_API_KEY"}
HOSTS = {"shodan": "api.shodan.io", "censys": "api.platform.censys.io",
         "fofa": "fofa.info", "github": "api.github.com", "gitlab": "gitlab.com",
         "brave": "api.search.brave.com", "rdap": "rdap.verisign.com"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _fixed_fetch(request: Request, timeout: float) -> dict:
    if request.full_url.split("/", 3)[2] not in HOSTS.values() or not request.full_url.startswith("https://"):
        raise ValueError("provider egress host is not allowlisted")
    opener = build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(262145)
    if len(raw) > 262144:
        raise ValueError("provider response too large")
    payload = json.loads(raw)
    if not isinstance(payload, dict) and not isinstance(payload, list):
        raise ValueError("invalid provider response")
    return payload


class ProviderSearchAdapter:
    def __init__(self, provider: str, *, fetch=_fixed_fetch):
        if provider not in ENV_KEYS:
            raise ValueError("unknown provider")
        self.provider = provider
        self.fetch = fetch

    @property
    def available(self) -> bool:
        return bool(os.environ.get(ENV_KEYS[self.provider]))

    def execute(self, request: ProviderCapabilityRequest) -> AdapterOutput:
        if request.provider != self.provider or not self.available:
            return AdapterOutput(status="error", message="provider credential unavailable")
        token = os.environ[ENV_KEYS[self.provider]]
        try:
            outbound = self._build_request(request, token)
            payload = self.fetch(outbound, request.parameters.timeout_seconds)
            observations = self._project(request, payload)[:request.parameters.max_results]
            evidence = json.dumps({"provider": self.provider, "root_domain": request.root_domain,
                                   "profile": request.parameters.profile,
                                   "observations": [row.model_dump(mode="json") for row in observations]},
                                  sort_keys=True).encode()
            return AdapterOutput(status="success", raw_output=evidence, observations=tuple(observations),
                                 message="result limit reached" if len(observations) >= request.parameters.max_results
                                 else "")
        except (HTTPError, URLError, ValueError, KeyError, TypeError, AttributeError, TimeoutError):
            # Never persist provider exception text: Shodan and FOFA put keys in URLs.
            return AdapterOutput(status="error", message="provider request failed")

    def _build_request(self, request: ProviderCapabilityRequest, token: str) -> Request:
        root = request.root_domain
        limit = request.parameters.max_results
        headers = {"Accept": "application/json", "User-Agent": "AgentRecon/3"}
        body = None
        if self.provider == "shodan":
            url = "https://api.shodan.io/shodan/host/search?" + urlencode(
                {"key": token, "query": f"hostname:{root}"})
        elif self.provider == "censys":
            url = "https://api.platform.censys.io/v3/global/search/query"
            headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
            body = json.dumps({"query": f"host.names: {root}", "page_size": limit}).encode()
        elif self.provider == "fofa":
            query = base64.b64encode(f'domain="{root}"'.encode()).decode()
            url = "https://fofa.info/api/v1/search/all?" + urlencode(
                {"key": token, "qbase64": query, "fields": "host,ip,port", "size": limit})
        elif self.provider == "github":
            url = "https://api.github.com/search/code?" + urlencode(
                {"q": f'"{root}" in:file', "per_page": min(limit, 100)})
            headers["Authorization"] = f"Bearer {token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        elif self.provider == "gitlab":
            url = "https://gitlab.com/api/v4/search?" + urlencode(
                {"scope": "blobs", "search": root, "per_page": min(limit, 100)})
            headers["PRIVATE-TOKEN"] = token
        else:
            suffix = {"PUBLIC_DOCUMENTS": "filetype:pdf OR filetype:docx",
                      "ADMIN_LOGIN": "intitle:login OR inurl:admin",
                      "DIRECTORY_INDEX": 'intitle:"index of"',
                      "CONFIG_FILES": "filetype:json OR filetype:yaml",
                      "BACKUP_FILES": "filetype:bak OR filetype:zip"}[request.parameters.profile]
            url = "https://api.search.brave.com/res/v1/web/search?" + urlencode(
                {"q": f"site:{root} {suffix}", "count": min(limit, 20)})
            headers["X-Subscription-Token"] = token
        return Request(url, data=body, headers=headers)

    def _project(self, request: ProviderCapabilityRequest, payload: dict | list) -> list[ReconObservation]:
        rows = []
        if self.provider == "shodan":
            if not isinstance(payload, dict) or not isinstance(payload.get("matches"), list):
                raise ValueError("invalid Shodan response")
            for hit in payload.get("matches", []):
                rows.extend(("HOST", host) for host in hit.get("hostnames", []) if isinstance(host, str))
                rows.append(("IP", hit.get("ip_str", "")))
        elif self.provider == "censys":
            if (not isinstance(payload, dict) or not isinstance(payload.get("result"), dict)
                    or not isinstance(payload["result"].get("hits"), list)):
                raise ValueError("invalid Censys response")
            hits = payload.get("result", {}).get("hits", [])
            for hit in hits:
                rows.append(("IP", hit.get("ip", "")))
                rows.extend(("HOST", host) for host in hit.get("names", []) if isinstance(host, str))
        elif self.provider == "fofa":
            if not isinstance(payload, dict) or payload.get("error") is True or not isinstance(payload.get("results"), list):
                raise ValueError("invalid FOFA response")
            for hit in payload.get("results", []):
                if isinstance(hit, list) and len(hit) >= 2:
                    rows.extend((("URL", hit[0]), ("IP", hit[1])))
        elif self.provider == "github":
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise ValueError("invalid GitHub response")
            rows.extend(("CODE_REFERENCE", hit.get("html_url", "")) for hit in payload.get("items", []))
        elif self.provider == "gitlab":
            if not isinstance(payload, list):
                raise ValueError("invalid GitLab response")
            rows.extend(("CODE_REFERENCE", f"project:{hit.get('project_id')}:{hit.get('path', '')}")
                        for hit in payload if isinstance(hit, dict))
        else:
            if (not isinstance(payload, dict) or not isinstance(payload.get("web"), dict)
                    or not isinstance(payload["web"].get("results"), list)):
                raise ValueError("invalid Brave response")
            rows.extend(("SEARCH_REFERENCE", hit.get("url", ""))
                        for hit in payload.get("web", {}).get("results", []))
        observations = []
        for kind, value in rows:
            if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
                continue
            if kind == "IP":
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    continue
            elif kind == "HOST":
                if len(value) > 253 or not all(part and part.replace("-", "").isalnum()
                                                 for part in value.split(".")):
                    continue
            elif kind in {"URL", "CODE_REFERENCE", "SEARCH_REFERENCE"} and value.startswith("http"):
                parts = urlsplit(value)
                if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                    continue
                value = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
            if len(value) > 2048 or any(marker in value.lower() for marker in ("token=", "api_key=", "secret=")):
                continue
            observations.append(ReconObservation(kind=kind, value=value, source=request.capability,
                                                 provider=self.provider))
        return observations[:request.parameters.max_results]


class ProviderRouter:
    def __init__(self, providers: tuple[str, ...]):
        self.adapters = {provider: ProviderSearchAdapter(provider) for provider in providers}

    def availability(self, provider: str | None) -> str:
        if provider is None:
            return "AVAILABLE" if any(adapter.available for adapter in self.adapters.values()) else "MISSING_CREDENTIAL"
        adapter = self.adapters.get(provider)
        if adapter is None:
            return "UNSUPPORTED_TARGET_KIND"
        return "AVAILABLE" if adapter.available else "MISSING_CREDENTIAL"

    def execute(self, request: ProviderCapabilityRequest) -> AdapterOutput:
        return self.adapters[request.provider].execute(request)


class RdapAdapter:
    """Fixed registry RDAP lookup for .com and .net; no referral following."""

    def __init__(self, *, fetch=_fixed_fetch):
        self.fetch = fetch

    def availability(self, provider: str | None) -> str:
        return "AVAILABLE" if provider in {None, "rdap"} else "UNSUPPORTED_TARGET_KIND"

    def execute(self, request: ProviderCapabilityRequest) -> AdapterOutput:
        tld = request.root_domain.rsplit(".", 1)[-1]
        if request.provider != "rdap" or tld not in {"com", "net"}:
            return AdapterOutput(status="error", message="RDAP TLD unsupported")
        try:
            outbound = Request(f"https://rdap.verisign.com/{tld}/v1/domain/{request.root_domain}",
                               headers={"Accept": "application/rdap+json", "User-Agent": "AgentRecon/3"})
            payload = self.fetch(outbound, request.parameters.timeout_seconds)
            if not isinstance(payload, dict) or payload.get("objectClassName") != "domain":
                raise ValueError("invalid RDAP response")
            observations = []
            for row in payload.get("nameservers", [])[:request.parameters.max_results]:
                if isinstance(row, dict) and isinstance(row.get("ldhName"), str):
                    host = row["ldhName"].lower().rstrip(".")
                    if host and len(host) <= 253 and all(part.replace("-", "").isalnum()
                                                        for part in host.split(".")):
                        observations.append(ReconObservation(kind="HOST", value=host,
                            source=request.capability, provider="rdap"))
            evidence = json.dumps({"provider": "rdap", "root_domain": request.root_domain,
                                   "profile": request.parameters.profile,
                                   "observations": [row.model_dump(mode="json") for row in observations]},
                                  sort_keys=True).encode()
            return AdapterOutput(status="success", raw_output=evidence, observations=tuple(observations))
        except (HTTPError, URLError, ValueError, KeyError, TypeError, AttributeError, TimeoutError):
            return AdapterOutput(status="error", message="RDAP request failed")
