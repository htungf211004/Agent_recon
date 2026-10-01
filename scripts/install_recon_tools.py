"""Install reviewed release archives, checking hashes before extracting allowlisted files."""

import argparse
import hashlib
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

PIP_ENV = {**os.environ, "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INDEX": "1"}


def install(lock_path, prefix, cache=None):
    lock = json.loads(Path(lock_path).read_text())
    if set(lock["tools"]) != {"subfinder", "amass", "gau", "katana", "nuclei", "arjun"}:
        raise ValueError("incomplete Recon CLI release lock")
    if set(lock.get("python_packages", {})) != {"requests", "dicttoxml", "wheel", "urllib3",
                                               "idna", "charset-normalizer", "certifi", "ratelimit"}:
        raise ValueError("incomplete Arjun dependency lock")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError("Recon CLI lock currently supports linux/amd64 only")
    prefix = Path(prefix)
    binary_dir = prefix / "bin"
    legal_dir = prefix / "share" / "recon-tools"
    binary_dir.mkdir(parents=True, exist_ok=True)
    legal_dir.mkdir(parents=True, exist_ok=True)
    python_env = prefix / "python"
    subprocess.run([sys.executable, "-m", "venv", str(python_env)], check=True)
    tool_python = python_env / "bin" / "python"
    for entry in lock.get("python_packages", {}).values():
        cached = Path(cache) / entry["archive"] if cache else None
        if cached and cached.is_file():
            blob = cached.read_bytes()
        else:
            with urllib.request.urlopen(entry["url"], timeout=60) as response:
                blob = response.read(10_000_001)
        if len(blob) > 10_000_000 or hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise ValueError("Python tool dependency integrity mismatch")
        wheel = prefix / entry["archive"]
        wheel.write_bytes(blob)
        subprocess.run([str(tool_python), "-m", "pip", "install", "--no-deps", "--no-build-isolation", str(wheel)], check=True, env=PIP_ENV)
        wheel.unlink()
    for tool, entry in lock["tools"].items():
        cached = Path(cache) / entry["archive"] if cache else None
        if cached and cached.is_file():
            blob = cached.read_bytes()
        else:
            with urllib.request.urlopen(entry["url"], timeout=90) as response:
                blob = response.read(100_000_001)
        if len(blob) > 100_000_000 or hashlib.sha256(blob).hexdigest() != entry["sha256"]:
            raise ValueError(f"release integrity mismatch: {tool}")
        if tool == "arjun":
            wheel = prefix / entry["archive"]
            wheel.write_bytes(blob)
            subprocess.run([str(tool_python), "-m", "pip", "install", "--no-deps", "--no-build-isolation", str(wheel)], check=True, env=PIP_ENV)
            wheel.unlink()
            (binary_dir / "arjun").symlink_to(python_env / "bin" / "arjun")
        members = {}
        if entry["archive"].endswith((".zip", ".whl")):
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                for member in archive.infolist():
                    name = Path(member.filename).name
                    if member.file_size <= 200_000_000 and (name == tool or name.upper().startswith(("LICENSE", "NOTICE", "COPYING"))):
                        members[name] = archive.read(member)
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
                for member in archive:
                    name = Path(member.name).name
                    if member.isfile() and member.size <= 200_000_000 and (name == tool or name.upper().startswith(("LICENSE", "NOTICE", "COPYING"))):
                        members[name] = archive.extractfile(member).read()
        if tool != "arjun":
            if tool not in members:
                raise ValueError(f"release lacks required binary: {tool}")
            destination = binary_dir / tool
            destination.write_bytes(members.pop(tool))
            destination.chmod(0o755)
        directory = legal_dir / tool
        directory.mkdir(exist_ok=True)
        for name, body in members.items():
            (directory / name).write_bytes(body)
        if "license_url" in entry:
            cached_license = Path(cache) / entry["license_file"] if cache else None
            if cached_license and cached_license.is_file():
                license_blob = cached_license.read_bytes()
            else:
                with urllib.request.urlopen(entry["license_url"], timeout=30) as response:
                    license_blob = response.read(1_000_001)
            if hashlib.sha256(license_blob).hexdigest() != entry["license_sha256"]:
                raise ValueError(f"license integrity mismatch: {tool}")
            (directory / "LICENSE").write_bytes(license_blob)
        if not any(path.name.upper().startswith(("LICENSE", "COPYING")) for path in directory.iterdir()):
            raise ValueError(f"release lacks license text: {tool}")
        (directory / "release.json").write_text(json.dumps(entry, indent=2) + "\n")
        print(f"installed {tool} {entry['version']}", flush=True)
    (legal_dir / "recon-tools.lock.json").write_text(json.dumps(lock, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", default="scripts/recon-tools.lock.json")
    parser.add_argument("--prefix", default="/usr/local")
    parser.add_argument("--cache")
    args = parser.parse_args()
    install(args.lock, args.prefix, args.cache)
