"""
PhishGuard AI - URL Feature Extractor
Extracts lexical, structural, and heuristic features from URLs for machine learning classification.
Defensive security tool: Operates strictly offline on URL strings without making network requests.
"""

import math
import re
from typing import Any, Dict, List
from urllib.parse import urlparse


# Standard feature column order used for training and model inference.
# MAINTAIN THIS EXACT ORDER AT ALL TIMES.
FEATURE_NAMES: List[str] = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_at_symbols",
    "num_ampersands",
    "num_percent_signs",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_ip_address",
    "is_https",
    "has_at_symbol",
    "has_double_slash_redirect",
    "has_suspicious_tld",
    "has_sensitive_keywords",
    "is_shortened_url",
    "prefix_suffix_in_domain",
    "entropy",
]

# Known high-abuse or commonly abused TLDs in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "fit", "gq", "cf", "ml", "ga",
    "tk", "buzz", "rest", "support", "icu", "bar", "monster", "cam",
    "sbs", "cfd", "shop", "club", "online", "site", "vip", "kim",
}

# Known URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly",
    "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly", "cutt.ly", "shorturl.at",
}

# Sensitive credential / finance / security keywords often abused in phishing URLs
SENSITIVE_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account",
    "update", "banking", "signin", "sign-in", "ebayisapi", "paypal",
    "wallet", "password", "credential", "auth", "support", "confirm",
    "billing", "recover", "service", "appleid", "microsoft", "token",
]

# IP address regex patterns (IPv4)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$"
)


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def normalize_url(url: str) -> str:
    """
    Normalizes a URL string by trimming whitespace and ensuring a scheme exists.
    Rejects dangerous or unsupported schemes (e.g., javascript:, data:, file:).
    """
    if not url:
        return ""
    clean_url = url.strip()

    # Reject non-web schemes
    forbidden_schemes = ("javascript:", "data:", "file:", "ftp:", "vbscript:", "blob:")
    for scheme in forbidden_schemes:
        if clean_url.lower().startswith(scheme):
            raise ValueError(f"Unsupported or dangerous URL scheme: {scheme}")

    # Add default scheme if missing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url

    return clean_url


def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts all lexical, structural, and heuristic features from a given URL.
    Returns a dictionary mapping feature names to their numeric values.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)

    # Core components
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # Length calculations
    url_length = len(normalized)
    domain_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Character counts
    num_dots = normalized.count(".")
    num_hyphens = normalized.count("-")
    num_underscores = normalized.count("_")
    num_slashes = normalized.count("/")
    num_question_marks = normalized.count("?")
    num_equal_signs = normalized.count("=")
    num_at_symbols = normalized.count("@")
    num_ampersands = normalized.count("&")
    num_percent_signs = normalized.count("%")
    num_digits = sum(c.isdigit() for c in normalized)
    digit_ratio = (num_digits / url_length) if url_length > 0 else 0.0

    # Domain / Subdomain analysis
    parts = hostname.split(".")
    # Rough estimate of subdomain count (excluding SLD and TLD)
    if len(parts) > 2:
        num_subdomains = len(parts) - 2
    else:
        num_subdomains = 0

    # IP address check
    has_ip_address = 1 if IPV4_REGEX.match(hostname) else 0

    # Scheme
    is_https = 1 if parsed.scheme.lower() == "https" else 0

    # Phishing Indicators
    has_at_symbol = 1 if "@" in normalized else 0
    # Double slash in path is often used for redirection tricks
    has_double_slash_redirect = 1 if "//" in path else 0

    # TLD analysis
    tld = parts[-1].lower() if parts else ""
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Sensitive keywords check in path, query, or subdomains
    lower_url = normalized.lower()
    keyword_hits = sum(1 for kw in SENSITIVE_KEYWORDS if kw in lower_url)
    has_sensitive_keywords = 1 if keyword_hits > 0 else 0

    # URL Shorteners
    is_shortened_url = 1 if hostname.lower() in URL_SHORTENERS else 0

    # Hyphen in domain (prefix-suffix abuse, e.g. paypal-security.com)
    prefix_suffix_in_domain = 1 if "-" in hostname else 0

    # Shannon Entropy
    entropy = calculate_entropy(normalized)

    features = {
        "url_length": float(url_length),
        "domain_length": float(domain_length),
        "path_length": float(path_length),
        "query_length": float(query_length),
        "num_dots": float(num_dots),
        "num_hyphens": float(num_hyphens),
        "num_underscores": float(num_underscores),
        "num_slashes": float(num_slashes),
        "num_question_marks": float(num_question_marks),
        "num_equal_signs": float(num_equal_signs),
        "num_at_symbols": float(num_at_symbols),
        "num_ampersands": float(num_ampersands),
        "num_percent_signs": float(num_percent_signs),
        "num_digits": float(num_digits),
        "digit_ratio": float(round(digit_ratio, 4)),
        "num_subdomains": float(num_subdomains),
        "has_ip_address": float(has_ip_address),
        "is_https": float(is_https),
        "has_at_symbol": float(has_at_symbol),
        "has_double_slash_redirect": float(has_double_slash_redirect),
        "has_suspicious_tld": float(has_suspicious_tld),
        "has_sensitive_keywords": float(has_sensitive_keywords),
        "is_shortened_url": float(is_shortened_url),
        "prefix_suffix_in_domain": float(prefix_suffix_in_domain),
        "entropy": float(round(entropy, 4)),
    }

    return features


def extract_features_vector(url: str) -> List[float]:
    """
    Extracts features as an ordered numeric list matching FEATURE_NAMES.
    Guarantees exact feature alignment for model inference.
    """
    features_dict = extract_features(url)
    return [features_dict[name] for name in FEATURE_NAMES]


def get_heuristic_indicators(url: str, features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Produces actionable cybersecurity indicators and risk factors based on extracted features.
    Provides users with transparent explanations of why a URL may be suspicious.
    """
    indicators = []

    if features.get("has_ip_address", 0) == 1:
        indicators.append({
            "code": "IP_HOSTNAME",
            "severity": "HIGH",
            "title": "Raw IP Address as Hostname",
            "description": "The URL connects directly to an IP address instead of a recognized domain name, a common tactic to bypass domain reputation filters."
        })

    if features.get("has_at_symbol", 0) == 1:
        indicators.append({
            "code": "EMBEDDED_AT_SYMBOL",
            "severity": "HIGH",
            "title": "Embedded '@' Symbol in URL",
            "description": "The '@' character in URLs causes browsers to ignore preceding characters as authentication credentials, disguising the true destination host."
        })

    if features.get("has_double_slash_redirect", 0) == 1:
        indicators.append({
            "code": "PATH_REDIRECT_DOUBLE_SLASH",
            "severity": "HIGH",
            "title": "Redirection '//' in URL Path",
            "description": "A double slash inside the path component frequently indicates an open redirect or destination masking trick."
        })

    if features.get("has_suspicious_tld", 0) == 1:
        indicators.append({
            "code": "HIGH_ABUSE_TLD",
            "severity": "MEDIUM",
            "title": "High-Abuse Top-Level Domain",
            "description": "The domain uses a TLD with a historically elevated correlation with malicious registrations and spam campaigns."
        })

    if features.get("is_shortened_url", 0) == 1:
        indicators.append({
            "code": "URL_SHORTENER",
            "severity": "MEDIUM",
            "title": "Known URL Shortener Service",
            "description": "The link employs an external URL shortening service, masking the final destination domain."
        })

    if features.get("prefix_suffix_in_domain", 0) == 1:
        indicators.append({
            "code": "DOMAIN_HYPHEN_DECEPTION",
            "severity": "MEDIUM",
            "title": "Hyphenated Domain Structure",
            "description": "Hyphens in domain names are frequently used in brand impersonation (e.g. 'paypal-update-account')."
        })

    if features.get("num_subdomains", 0) >= 3:
        indicators.append({
            "code": "EXCESSIVE_SUBDOMAINS",
            "severity": "MEDIUM",
            "title": "Excessive Subdomain Levels",
            "description": f"URL contains {int(features.get('num_subdomains', 0))} subdomain levels, commonly used to simulate legitimate brand names on arbitrary domains."
        })

    if features.get("digit_ratio", 0) > 0.25:
        indicators.append({
            "code": "HIGH_DIGIT_DENSITY",
            "severity": "MEDIUM",
            "title": "High Numeric Digit Density",
            "description": "Over 25% of the URL characters are numbers, indicating potential algorithmically generated domains or token tracking."
        })

    if features.get("entropy", 0) > 4.4:
        indicators.append({
            "code": "HIGH_ENTROPY",
            "severity": "LOW",
            "title": "Elevated Shannon Entropy",
            "description": "The URL contains an unusually high degree of character randomness, often observed with obfuscated or encrypted payloads."
        })

    if features.get("url_length", 0) > 100:
        indicators.append({
            "code": "EXCESSIVE_LENGTH",
            "severity": "LOW",
            "title": "Unusually Long URL",
            "description": f"The URL spans {int(features.get('url_length', 0))} characters, which is often used to conceal malicious parameters or simulate deep legitimate paths."
        })

    if features.get("has_sensitive_keywords", 0) == 1 and features.get("is_https", 1) == 0:
        indicators.append({
            "code": "INSECURE_SENSITIVE_FORM",
            "severity": "HIGH",
            "title": "Security-Sensitive Keywords over HTTP",
            "description": "The URL targets login or account procedures without HTTPS transport encryption, exposing potential credentials."
        })

    return indicators

