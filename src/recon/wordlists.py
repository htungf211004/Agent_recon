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
    "backup-small-v2": ("backup", ("backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
                                          "config.bak", "config.old", ".env.backup", "site.zip", "www.zip",
                                          "index.php.bak", "config.php~", "web.config.old", "dump.sql.gz")),
    "scm-small-v1": ("scm", (".git/HEAD", ".git/config", ".svn/entries", ".hg/requires",
                                    ".bzr/branch/branch.conf")),
    "vhosts-small-v1": ("vhost", ("www", "api", "admin", "dev", "staging", "portal")),
    "parameters-small-v1": ("parameter", ("id", "page", "limit", "offset", "sort", "search")),
}
_SELECTED_EXTERNAL: dict[str, "TrustedWordlist"] = {}


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


def install_external_wordlist(wordlist: TrustedWordlist):
    """Install an operator-selected, already verified runner dataset for this process."""
    if wordlist.id in TRUSTED:
        raise ValueError("runner wordlist ID collides with packaged catalog")
    existing = _SELECTED_EXTERNAL.get(wordlist.id)
    if existing is not None and existing != wordlist:
        raise ValueError("runner wordlist ID is already bound to different content")
    _SELECTED_EXTERNAL[wordlist.id] = wordlist


def clear_external_wordlists():
    """Reset process-local selections (used by isolated runners and tests)."""
    _SELECTED_EXTERNAL.clear()


def available_wordlist_ids(*, exclude_categories=()):
    packaged = (key for key, (category, _) in TRUSTED.items() if category not in exclude_categories)
    external = (key for key, value in _SELECTED_EXTERNAL.items() if value.category not in exclude_categories)
    return tuple(sorted((*packaged, *external)))


def load_wordlist(wordlist_id):
    if wordlist_id in _SELECTED_EXTERNAL:
        return _SELECTED_EXTERNAL[wordlist_id]
    if wordlist_id not in TRUSTED:
        raise ValueError("unknown trusted wordlist")
    category, entries = TRUSTED[wordlist_id]
    path = ROOT / (wordlist_id + ".txt")
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    expected = ("\n".join(entries) + "\n").encode()
    if raw != expected:
        raise ValueError("packaged wordlist integrity mismatch")
    return TrustedWordlist(wordlist_id, path, "1", hashlib.sha256(raw).hexdigest(), len(entries), category,
                           {"vhost": "vhost_discovery", "parameter": "parameter_discovery"}.get(category, "content_discovery"), entries)


def request_units(request):
    if request.capability in {"web_crawl", "vhost_discovery", "parameter_discovery", "technology_scan"}:
        return request.parameters.max_requests
    return (load_wordlist(request.parameters.wordlist_id).max_entries
            if request.capability in {"content_discovery", "exposure_discovery"} else 1)
