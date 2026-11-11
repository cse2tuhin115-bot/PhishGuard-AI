"""
Unit tests for URL feature extraction and heuristic indicator detection.
"""

import pytest
from ml.feature_extractor import (
    FEATURE_NAMES,
    calculate_entropy,
    extract_features,
    extract_features_vector,
    get_heuristic_indicators,
    normalize_url,
)


def test_normalize_url_adds_scheme():
    assert normalize_url("google.com") == "http://google.com"
    assert normalize_url("https://example.com/test") == "https://example.com/test"


def test_normalize_url_rejects_dangerous_schemes():
    with pytest.raises(ValueError, match="Unsupported or dangerous"):
        normalize_url("javascript:alert(1)")

    with pytest.raises(ValueError, match="Unsupported or dangerous"):
        normalize_url("data:text/html,<script>alert(1)</script>")

    with pytest.raises(ValueError, match="Unsupported or dangerous"):
        normalize_url("file:///etc/passwd")


def test_calculate_entropy():
    # Empty string has 0 entropy
    assert calculate_entropy("") == 0.0
    # Single repeating character has 0 entropy
    assert calculate_entropy("aaaaa") == 0.0
    # Diverse string has higher entropy
    ent = calculate_entropy("a1b2c3d4e5f6g7h8")
    assert ent > 3.0


def test_extract_features_structure():
    url = "https://www.paypal-verification.xyz/login.php?user=test#section"
    features = extract_features(url)

    # Verify all expected feature names are present
    for name in FEATURE_NAMES:
        assert name in features, f"Missing feature: {name}"

    assert features["is_https"] == 1.0
    assert features["has_suspicious_tld"] == 1.0
    assert features["prefix_suffix_in_domain"] == 1.0
    assert features["has_sensitive_keywords"] == 1.0
    assert features["has_ip_address"] == 0.0


def test_feature_vector_order_and_types():
    url = "http://192.168.1.50/admin/update"
    vector = extract_features_vector(url)

    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(val, (int, float)) for val in vector)

    # Check IP feature position
    ip_index = FEATURE_NAMES.index("has_ip_address")
    assert vector[ip_index] == 1.0


def test_heuristic_indicators():
    url = "http://192.168.1.100@phishing.xyz//redirect/login.php"
    features = extract_features(url)
    indicators = get_heuristic_indicators(url, features)

    codes = [ind["code"] for ind in indicators]
    assert "IP_HOSTNAME" in codes or "EMBEDDED_AT_SYMBOL" in codes

