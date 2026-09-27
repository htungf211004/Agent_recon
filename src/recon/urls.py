"""Conservative URL identity and path checks shared by policy and discovery."""

import ipaddress
import re
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit


def validate_path(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or len(path) > 2048:
        raise ValueError("an absolute local path is required")
    if any(ord(c) <= 32 or ord(c) >= 127 for c in path) or any(c in path for c in "\\?#"):
        raise ValueError("invalid path characters")
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        raise ValueError("invalid percent encoding")
    decoded = unquote(path)
    if any(c in decoded for c in "\\%?#") or any(ord(c) <= 32 for c in decoded):
        raise ValueError("ambiguous encoded path")
    if re.search(r"%2f", path, re.I) or "//" in path or any(p in {".", ".."} for p in decoded.split("/")):
        raise ValueError("ambiguous path segments")
    return path


def validate_query(query: str) -> str:
    if len(query) > 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in query) or "#" in query:
        raise ValueError("invalid query")
    if re.search(r"%(?![0-9a-fA-F]{2})", query) or any(ord(c) < 32 for c in unquote(query)):
        raise ValueError("invalid query encoding")
    return query


def path_allowed(path: str, prefixes: tuple[str, ...]) -> bool:
    validate_path(path)
    decoded = unquote(path)
    return any(prefix == "/" or decoded == unquote(prefix).rstrip("/") or
               decoded.startswith(unquote(prefix).rstrip("/") + "/") for prefix in prefixes)


def canonical_url(url: str) -> str:
    if len(url) > 4096 or any(ord(c) <= 32 for c in url) or "\\" in url:
        raise ValueError("invalid URL")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.username is not None or parts.password is not None:
        raise ValueError("only HTTP URLs without credentials are supported")
    host = str(ipaddress.ip_address(parts.hostname or ""))
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    path = parts.path or "/"
    validate_path(path)
    path = quote(path, safe="/%:@!$&'()*+,;=-._~{}")
    # Normalize only unreserved escapes; keep case, slash and query ordering.
    path = re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16))
                  if chr(int(m[1], 16)) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
                  else m[0].upper(), path)
    query = validate_query(parts.query)
    host = f"[{host}]" if ":" in host else host
    return urlunsplit((parts.scheme, f"{host}:{port}", path, query, ""))


def normalize_candidate(value: str, base_url: str) -> str | None:
    try:
        # Reject traversal before urljoin could erase it.
        if (not value or value.startswith("#") or "\\" in value or len(value) > 4096
                or any(ord(c) <= 32 for c in value)):
            return None
        path = urlsplit(value).path
        if path:
            validate_path(path if path.startswith("/") else "/" + path)
        base = canonical_url(base_url)
        normalized = canonical_url(urljoin(base, value))
        if urlsplit(normalized)[:2] != urlsplit(base)[:2]:
            return None
        return normalized
    except (ValueError, UnicodeError):
        return None


def request_url(target_ip: str, scheme: str, port: int, path: str, query: str = "") -> str:
    host = f"[{target_ip}]" if ":" in target_ip else target_ip
    # Templates are retained in inventory, but must never become HTTP requests.
    if any(c in path for c in "{}"):
        raise ValueError("unresolved path template")
    return canonical_url(urlunsplit((scheme, f"{host}:{port}", quote(path, safe="/%:@!$&'()*+,;=-._~"), query, "")))
