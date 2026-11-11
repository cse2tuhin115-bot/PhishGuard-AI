"""
PhishGuard AI - Security & Sanitization Utilities
Protects the defensive scanner from unsafe inputs, credential leakage, and SSRF.
"""

import re
from urllib.parse import urlparse, urlunparse


FORBIDDEN_SCHEMES = ("javascript:", "data:", "file:", "ftp:", "vbscript:", "blob:")


def sanitize_and_validate_url(url: str, max_length: int = 2048) -> str:
    """
    Validates and sanitizes a URL before processing.
    - Strips whitespace and null characters.
    - Rejects input exceeding max_length.
    - Rejects forbidden schemes.
    - Strips embedded basic auth credentials (user:pass) to protect privacy.
    """
    if not url:
        raise ValueError("URL cannot be empty.")

    clean_url = url.strip().replace("\x00", "")

    if len(clean_url) > max_length:
        raise ValueError(f"URL exceeds maximum allowed length of {max_length} characters.")

    lower = clean_url.lower()
    for scheme in FORBIDDEN_SCHEMES:
        if lower.startswith(scheme):
            raise ValueError(f"Dangerous or non-web URL scheme '{scheme}' is rejected.")

    # Ensure a web scheme is present for parsing
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url))
    url_to_parse = clean_url if has_scheme else ("http://" + clean_url)

    parsed = urlparse(url_to_parse)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'. Only http:// and https:// are accepted.")

    # Strip embedded credentials if present (e.g. user:pass@host)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("URL does not contain a valid destination hostname.")

    port_part = f":{parsed.port}" if parsed.port else ""
    netloc_clean = f"{hostname}{port_part}"

    # Reconstruct sanitized URL without userinfo credentials
    sanitized = urlunparse((
        parsed.scheme,
        netloc_clean,
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return sanitized

