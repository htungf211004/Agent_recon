"""Atomic persistence, contained paths, and deterministic content identities."""

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def contained(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not relative or ".." in path.parts or "\\" in relative or ":" in relative:
        raise ValueError("unsafe artifact path")
    result = (root / path).resolve()
    if not result.is_relative_to(root.resolve()) or (root / path).is_symlink():
        raise ValueError("artifact escapes snapshot")
    return result


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".write-" + uuid4().hex + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def artifact_hashes(root: Path) -> dict[str, str]:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    return {path.relative_to(root).as_posix(): sha256_file(contained(root, path.relative_to(root).as_posix()))
            for path in files}


def tree_hash(hashes: dict[str, str]) -> str:
    return hashlib.sha256(json_bytes(hashes)).hexdigest()
