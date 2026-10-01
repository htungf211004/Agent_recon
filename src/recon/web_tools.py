"""Fixed CLI profiles and normalized results for bounded web reconnaissance."""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from src.recon.adapters import _run_fixed
from src.recon.gateway import AdapterOutput
from src.recon.models import Capability, ReconObservation, TechnologyObservation
from src.recon.urls import normalize_candidate, request_url
from src.recon.web_tool_transport import web_tool_bridge
from src.recon.wordlists import load_wordlist

TEMPLATES = Path(__file__).parent / "data" / "nuclei"


class BoundedWebToolAdapter:
    tool = ""

    def __init__(self, repository, *, transport=None):
        self.repository, self.transport = repository, transport

    def execute(self, request):
        task = self.repository.get_task(request.task_id)
        params = request.parameters
        with tempfile.TemporaryDirectory(prefix=f"recon-{self.tool}-") as directory:
            env = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "SYSTEMROOT", "WINDIR"}}
            env.update(HOME=directory, USERPROFILE=directory, XDG_CONFIG_HOME=directory,
                       XDG_CACHE_HOME=directory, XDG_DATA_HOME=directory)
            hosts = ()
            if request.capability == Capability.VHOST_DISCOVERY:
                hosts = tuple(word + "." + params.root_domain for word in load_wordlist(params.wordlist_id).entries)
                hosts += ("recon-missing-a7c3." + params.root_domain, "recon-missing-b8d4." + params.root_domain)
            with web_tool_bridge(request, task, hosts=hosts, transport=self.transport) as bridge:
                target = bridge.origin + params.path
                output_path = Path(directory) / "result.json"
                baseline = set()
                if hosts:
                    with httpx.Client(trust_env=False, timeout=3) as client:
                        for host in hosts[-2:]:
                            response = client.head(target, headers={"Host": host})
                            # Pinned FFUF 1.1.0 reports bytes read, hence zero for
                            # HEAD, rather than the Content-Length header.
                            baseline.add((response.status_code, 0))
                command = self.command(request, target, bridge.origin, output_path)
                # Arjun's Requests client honors these; no credentials or external proxy are inherited.
                env.update(HTTP_PROXY=bridge.origin, HTTPS_PROXY=bridge.origin, NO_PROXY="")
                output = _run_fixed(command, timeout=params.timeout_seconds, env=env, cwd=directory)
                if (output.status != "success" or bridge.failed or bridge.count == 0
                        or "output truncated" in output.message):
                    return AdapterOutput(status="error", timed_out=output.timed_out,
                                         message=f"{self.tool} bounded execution failed")
                raw = output.raw_output
                if output_path.is_file():
                    with output_path.open("rb") as stream:
                        raw = stream.read(262145)
                if len(raw) > 262144:
                    return AdapterOutput(status="error", message="tool output limit exceeded")
                observations, technologies = self.project(request, raw, bridge.origin, baseline)
                envelope = {"profile": self.tool + "-v1", "requests": bridge.count,
                            "observations": [row.model_dump(mode="json") for row in observations]}
                return AdapterOutput(status="success", raw_output=json.dumps(envelope, sort_keys=True).encode(),
                                     observations=tuple(observations), technologies=tuple(technologies))

    def command(self, request, target, proxy, output_path):
        raise NotImplementedError

    def project(self, request, raw, bridge_origin, baseline):
        raise NotImplementedError


class KatanaAdapter(BoundedWebToolAdapter):
    tool = "katana"

    def command(self, request, target, proxy, output_path):
        p = request.parameters
        return ["katana", "-u", target, "-proxy", proxy, "-d", str(p.max_depth), "-c", "1", "-p", "1",
                "-rl", "2", "-retry", "0", "-timeout", "3", "-ct", str(p.timeout_seconds) + "s",
                "-mrs", str(p.max_body_bytes), "-cs", "^" + re.escape(proxy) + "/", "-fs", "fqdn",
                "-dr", "-duc", "-silent", "-or", "-ob", "-o", str(output_path)]

    def project(self, request, raw, bridge_origin, baseline):
        target = request_url(request.target_ip, request.parameters.scheme, request.parameters.port,
                             "/", target_host=request.target_host)
        found = {}
        for line in raw.decode("utf-8").splitlines():
            parts = urlsplit(line)
            if f"{parts.scheme}://{parts.netloc}" != bridge_origin:
                continue
            url = normalize_candidate(parts.path or "/", target)
            if url:
                found[url] = ReconObservation(kind="URL", value=url, source=request.capability)
        if len(found) > request.parameters.max_results:
            raise ValueError("crawl result limit exceeded")
        return list(found.values()), []


class VhostDiscoveryAdapter(BoundedWebToolAdapter):
    tool = "ffuf"

    def command(self, request, target, proxy, output_path):
        p = request.parameters
        return ["ffuf", "-w", str(load_wordlist(p.wordlist_id).path.resolve()), "-u", target,
                "-x", proxy, "-H", "Host: FUZZ." + p.root_domain, "-X", "HEAD", "-t", "1",
                "-p", "0.5", "-timeout", "3", "-maxtime", str(p.timeout_seconds),
                "-r=false", "-ac=false", "-recursion=false", "-s", "-mc", "all",
                "-of", "json", "-o", str(output_path)]

    def project(self, request, raw, bridge_origin, baseline):
        permitted = set(load_wordlist(request.parameters.wordlist_id).entries)
        rows = json.loads(raw)["results"]
        if len(rows) > len(permitted):
            raise ValueError("vhost result limit exceeded")
        found = []
        for row in rows:
            if (not isinstance(row, dict) or type(row.get("status")) is not int
                    or not 100 <= row["status"] <= 599 or type(row.get("length")) is not int
                    or row["length"] < 0):
                raise ValueError("invalid vhost result signature")
            label = row.get("input", {}).get("FUZZ")
            if label in permitted and (row.get("status"), row.get("length")) not in baseline:
                found.append(ReconObservation(kind="HOST", value=label + "." + request.parameters.root_domain,
                                              source=request.capability))
        return found, []


class ArjunAdapter(BoundedWebToolAdapter):
    tool = "arjun"

    def command(self, request, target, proxy, output_path):
        return ["arjun", "-u", target, "-m", "GET", "-w",
                str(load_wordlist(request.parameters.wordlist_id).path.resolve()), "-t", "1", "-c", "2",
                "-T", "3", "--rate-limit", "2", "--disable-redirects", "-oJ", str(output_path)]

    def project(self, request, raw, bridge_origin, baseline):
        # Arjun writes a file only when parameters are found; absence is a bounded negative result.
        if not raw.lstrip().startswith(b"{"):
            if b"No parameters were discovered" not in raw:
                raise ValueError("parameter discovery did not complete")
            return [], []
        document = json.loads(raw)
        permitted = set(load_wordlist(request.parameters.wordlist_id).entries)
        names = set()
        for url, result in document.items():
            if url != bridge_origin + request.parameters.path or result.get("method") != "GET":
                raise ValueError("parameter result endpoint mismatch")
            names.update(name for name in result.get("params", []) if name in permitted)
        return [ReconObservation(kind="METADATA", value="parameter:" + name, source=request.capability)
                for name in sorted(names)], []


class NucleiTechnologyAdapter(BoundedWebToolAdapter):
    tool = "nuclei"

    def command(self, request, target, proxy, output_path):
        lock = json.loads((TEMPLATES / "manifest.json").read_text())
        if (lock.get("version") != request.parameters.profile
                or set(lock["templates"]) != {"apache-header-v1.yaml", "nginx-header-v1.yaml"}):
            raise ValueError("unapproved technology template profile")
        templates = []
        for filename, digest in lock["templates"].items():
            path = TEMPLATES / filename
            if path.parent != TEMPLATES or hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != digest:
                raise ValueError("technology template integrity mismatch")
            templates.extend(["-t", str(path.resolve())])
        return ["nuclei", "-u", target, *templates, "-proxy", proxy, "-ni", "-duc", "-no-stdin",
                "-rl", "2", "-c", "1", "-bs", "1", "-retries", "0", "-timeout", "3",
                "-jsonl", "-omit-raw", "-omit-template", "-silent", "-o", str(output_path)]

    def project(self, request, raw, bridge_origin, baseline):
        names = {"recon-nginx-header-v1": "nginx", "recon-apache-header-v1": "Apache"}
        found = set()
        for line in raw.decode().splitlines():
            row = json.loads(line)
            if row.get("template-id") not in names:
                raise ValueError("unapproved technology template result")
            if row.get("matched-at") != bridge_origin + "/":
                raise ValueError("technology result endpoint mismatch")
            found.add(names[row["template-id"]])
        return ([ReconObservation(kind="TECHNOLOGY", value=name, source=request.capability) for name in sorted(found)],
                [TechnologyObservation(target_ip=request.target_ip, name=name, source=request.capability)
                 for name in sorted(found)])
