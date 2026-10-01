"""Trusted packaged paths only. Versions bind both content and request identity."""

import hashlib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).parent / "data" / "wordlists"
TRUSTED = {
    "web-common-small-v1": ("web", ("robots.txt", "sitemap.xml", "openapi.json", "swagger.json", "health", "hidden")),
    "api-common-small-v1": ("api", ("openapi.json", "swagger.json", "api-docs", "v3/api-docs", "health", "status")),
    "well-known-small-v1": ("well-known", (".well-known/security.txt", ".well-known/openid-configuration",
                                            ".well-known/jwks.json", ".well-known/assetlinks.json")),
    "backup-small-v1": ("backup", ("backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
                                          "config.bak", "config.old", ".env.backup", "site.zip", "www.zip")),
    "scm-small-v1": ("scm", (".git/HEAD", ".git/config", ".svn/entries", ".hg/requires",
                                    ".bzr/branch/branch.conf")),
}


@dataclass(frozen=True)
class TrustedWordlist:
    id: str
    path: Path
    version: str
    sha256: str
    max_entries: int
    category: str
    intended_phase: str
    entries: tuple[str, ...]


def load_wordlist(wordlist_id):
    if wordlist_id not in TRUSTED:
        raise ValueError("unknown trusted wordlist")
    category, entries = TRUSTED[wordlist_id]
    path = ROOT / (wordlist_id + ".txt")
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    expected = ("\n".join(entries) + "\n").encode()
    if raw != expected:
        raise ValueError("packaged wordlist integrity mismatch")
    return TrustedWordlist(wordlist_id, path, "1", hashlib.sha256(raw).hexdigest(), len(entries), category,
                           "content_discovery", entries)


def request_units(request):
    return (load_wordlist(request.parameters.wordlist_id).max_entries
            if request.capability in {"content_discovery", "exposure_discovery"} else 1)
