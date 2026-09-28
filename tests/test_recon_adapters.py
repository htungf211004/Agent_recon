import subprocess

import httpx

from src.recon.adapters import MAX_OUTPUT_BYTES, HttpProbeAdapter, NmapAdapter, WhatWebAdapter
from src.recon.models import Capability, CapabilityRequest, HttpProbeParams, NmapScanParams, WhatWebParams
from src.recon.parsers import parse_nmap, parse_whatweb

NMAP_SAMPLE = """Nmap scan report for 10.10.10.3
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 2.3.4
22/tcp open ssh OpenSSH 4.7p1 Debian
80/tcp closed http
"""
WHATWEB_SAMPLE = "WhatWeb report for http://10.10.10.3\nSummary   : \x1b[1mApache\x1b[0m[2.2.8], PHP[5,5.2.4-2ubuntu5.10], WebDAV[2]\n"


def req(capability, parameters):
    return CapabilityRequest(id="req", task_id="task", target_ip="10.10.10.3", capability=capability, parameters=parameters)


def test_migrated_nmap_parser_and_whatweb_parser():
    entries = parse_nmap(NMAP_SAMPLE, "10.10.10.3")
    assert [(entry.port, entry.service, entry.version) for entry in entries] == [
        (21, "ftp", "vsftpd 2.3.4"), (22, "ssh", "OpenSSH 4.7p1 Debian")]
    tech = parse_whatweb(WHATWEB_SAMPLE, "10.10.10.3")
    assert [(item.name, item.version) for item in tech] == [
        ("Apache", "2.2.8"), ("PHP", "5.2.4-2ubuntu5.10"), ("WebDAV", "2")]


def test_subprocess_adapters_construct_fixed_arguments(monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        output = NMAP_SAMPLE if command[0] == "nmap" else WHATWEB_SAMPLE
        kwargs["stdout"].write(output.encode())
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("src.recon.adapters.subprocess.run", fake_run)
    nmap = NmapAdapter().execute(req(Capability.NMAP_SCAN, NmapScanParams(ports=(21, 22))))
    whatweb = WhatWebAdapter().execute(req(Capability.WHATWEB, WhatWebParams(port=80)))
    assert nmap.status == "success" and len(nmap.attack_surface) == 2
    assert whatweb.status == "success" and len(whatweb.technologies) == 3
    assert calls[0][0] == ["nmap", "-sT", "-sV", "-Pn", "-n", "--max-retries", "1", "-p", "21,22", "10.10.10.3"]
    assert calls[1][0] == ["whatweb", "-a", "1", "--follow-redirect=never", "http://10.10.10.3:80/"]
    assert all(call[1]["check"] is False for call in calls)


def test_http_probe_does_not_follow_redirect_or_capture_sensitive_headers():
    calls = []

    def handle(request):
        calls.append(request.url)
        return httpx.Response(302, headers={"location": "http://198.51.100.1/", "set-cookie": "secret=abc", "server": "Apache/2.4"})

    adapter = HttpProbeAdapter(httpx.MockTransport(handle))
    result = adapter.execute(req(Capability.HTTP_PROBE, HttpProbeParams(port=80)))
    assert result.status == "success"
    assert len(calls) == 1
    assert b"secret" not in result.raw_output
    assert result.technologies[0].name == "Apache"


def test_subprocess_output_is_bounded_and_timeout_keeps_partial_evidence(monkeypatch):
    def oversized(command, **kwargs):
        kwargs["stdout"].write(b"x" * (MAX_OUTPUT_BYTES + 10))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("src.recon.adapters.subprocess.run", oversized)
    result = NmapAdapter().execute(req(Capability.NMAP_SCAN, NmapScanParams(ports=(21,))))
    assert len(result.raw_output) == MAX_OUTPUT_BYTES
    assert "truncated" in result.message

    def timed_out(command, **kwargs):
        kwargs["stdout"].write(b"partial")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr("src.recon.adapters.subprocess.run", timed_out)
    result = NmapAdapter().execute(req(Capability.NMAP_SCAN, NmapScanParams(ports=(21,))))
    assert result.status == "error"
    assert result.raw_output == b"partial"
