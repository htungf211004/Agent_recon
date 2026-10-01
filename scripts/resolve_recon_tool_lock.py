"""Maintainer-only official release lock resolver; TLS verification remains enabled."""

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

RELEASES = {
    "subfinder": ("projectdiscovery/subfinder", "v2.6.6", "subfinder_2.6.6_linux_amd64.zip", "MIT"),
    "amass": ("owasp-amass/amass", "v3.23.3", "amass_Linux_amd64.zip", "Apache-2.0"),
    "gau": ("lc/gau", "v2.2.4", "gau_2.2.4_linux_amd64.tar.gz", "MIT"),
    "katana": ("projectdiscovery/katana", "v1.1.0", "katana_1.1.0_linux_amd64.zip", "MIT"),
    "nuclei": ("projectdiscovery/nuclei", "v3.3.7", "nuclei_3.3.7_linux_amd64.zip", "MIT"),
}


def resolve_python_packages(fetch, downloads, lock):
    lock["python_packages"] = {}
    for package, version in (("requests", "2.32.5"), ("dicttoxml", "1.7.16"), ("wheel", "0.45.1"),
                             ("urllib3", "2.5.0"), ("idna", "3.10"), ("charset-normalizer", "3.4.2"),
                             ("certifi", "2025.8.3"), ("ratelimit", "2.2.1")):
        metadata = json.loads(fetch(f"https://pypi.org/pypi/{package}/{version}/json"))
        pure = [row for row in metadata["urls"] if row["filename"].endswith("none-any.whl")]
        wheel = pure[0] if pure else next(row for row in metadata["urls"] if row["filename"].endswith(".tar.gz"))
        blob = fetch(wheel["url"])
        if hashlib.sha256(blob).hexdigest() != wheel["digests"]["sha256"]:
            raise ValueError(f"wheel checksum mismatch: {package}")
        (downloads / wheel["filename"]).write_bytes(blob)
        lock["python_packages"][package] = {"version": version, "url": wheel["url"],
            "sha256": wheel["digests"]["sha256"], "archive": wheel["filename"]}
        print(package, version, flush=True)


def main():
    import truststore
    truststore.inject_into_ssl()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def fetch(url):
        with opener.open(url, timeout=60) as response:
            return response.read(100_000_001)

    root = Path(__file__).resolve().parents[1]
    downloads = root.parent / ".recon-v3-runtime"
    downloads.mkdir(exist_ok=True)
    if "--python-only" in sys.argv:
        lock = json.loads((root / "scripts" / "recon-tools.lock.json").read_text())
        resolve_python_packages(fetch, downloads, lock)
        (root / "scripts" / "recon-tools.lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        return
    lock = {"architecture": "amd64", "tools": {}}
    for tool, (repo, tag, filename, license_id) in RELEASES.items():
        metadata = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/tags/{tag}"))
        assets = {asset["name"]: asset for asset in metadata["assets"]}
        checksum_name = next(name for name in assets if "checksum" in name.lower() and
                             ("linux" in name or "mac" not in name and "windows" not in name))
        checksums = fetch(assets[checksum_name]["browser_download_url"]).decode()
        digest = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip("*") == filename)
        blob = ((downloads / filename).read_bytes() if (downloads / filename).is_file()
                else fetch(assets[filename]["browser_download_url"]))
        if hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError(f"official checksum mismatch: {tool}")
        (downloads / filename).write_bytes(blob)
        lock["tools"][tool] = {"version": tag, "url": assets[filename]["browser_download_url"],
                              "sha256": digest, "license": license_id, "archive": filename}
        license_metadata = json.loads(fetch(f"https://api.github.com/repos/{repo}/license?ref={tag}"))
        license_blob = fetch(license_metadata["download_url"])
        license_name = tool + "-LICENSE"
        (downloads / license_name).write_bytes(license_blob)
        lock["tools"][tool].update(license_url=license_metadata["download_url"],
            license_sha256=hashlib.sha256(license_blob).hexdigest(), license_file=license_name)
        (root / "scripts" / "recon-tools.lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        print(tool, tag, digest, flush=True)
    metadata = json.loads(fetch("https://pypi.org/pypi/arjun/2.2.7/json"))
    wheel = next(row for row in metadata["urls"] if row["filename"].endswith((".whl", ".tar.gz")))
    blob = fetch(wheel["url"])
    if hashlib.sha256(blob).hexdigest() != wheel["digests"]["sha256"]:
        raise ValueError("Arjun wheel checksum mismatch")
    (downloads / wheel["filename"]).write_bytes(blob)
    lock["tools"]["arjun"] = {"version": "2.2.7", "url": wheel["url"],
                                "sha256": wheel["digests"]["sha256"], "license": "GPL-3.0-only",
                                "archive": wheel["filename"]}
    print("arjun dependencies", metadata["info"]["requires_dist"], flush=True)
    license_metadata = json.loads(fetch("https://api.github.com/repos/s0md3v/Arjun/license?ref=2.2.7"))
    license_blob = fetch(license_metadata["download_url"])
    (downloads / "arjun-LICENSE").write_bytes(license_blob)
    lock["tools"]["arjun"].update(license_url=license_metadata["download_url"],
        license_sha256=hashlib.sha256(license_blob).hexdigest(), license_file="arjun-LICENSE")
    resolve_python_packages(fetch, downloads, lock)
    (root / "scripts" / "recon-tools.lock.json").write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    main()
