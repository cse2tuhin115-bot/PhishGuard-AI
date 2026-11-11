"""
Unit tests for SQLite database persistence, search filtering, and analytics metrics.
"""

import os
import tempfile
import pytest

from app.core.config import settings
from app.database.connection import init_db
from app.database.models import (
    delete_scan_by_id,
    get_all_scans_for_export,
    get_analytics_metrics,
    get_scan_by_id,
    get_scans,
    save_scan,
)


@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    """Sets up a temporary SQLite database for test isolation."""
    temp_dir = tempfile.mkdtemp()
    test_db_path = os.path.join(temp_dir, "test_phishguard.db")
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db_path)
    init_db()
    yield test_db_path


def test_save_and_retrieve_scan():
    scan_payload = {
        "submitted_url": "https://example.com/test",
        "normalized_url": "https://example.com/test",
        "domain": "example.com",
        "prediction": "Legitimate",
        "risk_level": "Low Risk",
        "risk_score": 12.5,
        "confidence": 0.88,
        "probability": 0.12,
        "is_fallback": False,
        "is_uncertain": False,
        "model_info": {"version": "1.0.0"},
        "features": {"url_length": 24.0},
        "indicators": [],
    }

    record_id = save_scan(scan_payload)
    assert record_id is not None
    assert record_id > 0

    scan = get_scan_by_id(record_id)
    assert scan is not None
    assert scan["domain"] == "example.com"
    assert scan["prediction"] == "Legitimate"
    assert scan["risk_score"] == 12.5


def test_search_and_filter_scans():
    save_scan({
        "submitted_url": "https://bankofamerica.com",
        "normalized_url": "https://bankofamerica.com",
        "domain": "bankofamerica.com",
        "prediction": "Legitimate",
        "risk_level": "Low Risk",
        "risk_score": 5.0,
        "confidence": 0.95,
        "probability": 0.05,
        "is_fallback": False,
        "is_uncertain": False,
    })
    save_scan({
        "submitted_url": "http://evil-phish.xyz/login",
        "normalized_url": "http://evil-phish.xyz/login",
        "domain": "evil-phish.xyz",
        "prediction": "Phishing",
        "risk_level": "High Risk",
        "risk_score": 95.0,
        "confidence": 0.95,
        "probability": 0.95,
        "is_fallback": False,
        "is_uncertain": False,
    })

    # Filter by prediction
    phish_items, phish_count = get_scans(prediction="Phishing")
    assert phish_count == 1
    assert phish_items[0]["domain"] == "evil-phish.xyz"

    # Search by domain
    search_items, search_count = get_scans(search="bank")
    assert search_count == 1
    assert search_items[0]["domain"] == "bankofamerica.com"


def test_delete_scan():
    rec_id = save_scan({
        "submitted_url": "https://to-delete.com",
        "normalized_url": "https://to-delete.com",
        "domain": "to-delete.com",
        "prediction": "Legitimate",
        "risk_level": "Low Risk",
        "risk_score": 10.0,
        "confidence": 0.9,
        "probability": 0.1,
    })
    assert delete_scan_by_id(rec_id) is True
    assert get_scan_by_id(rec_id) is None


def test_analytics_calculation():
    # Empty state
    metrics = get_analytics_metrics()
    assert metrics["total_scans"] == 0

    # Insert items
    save_scan({
        "submitted_url": "https://safe1.com",
        "normalized_url": "https://safe1.com",
        "domain": "safe1.com",
        "prediction": "Legitimate",
        "risk_level": "Low Risk",
        "risk_score": 10.0,
        "confidence": 0.9,
        "probability": 0.1,
    })
    save_scan({
        "submitted_url": "http://threat1.xyz",
        "normalized_url": "http://threat1.xyz",
        "domain": "threat1.xyz",
        "prediction": "Phishing",
        "risk_level": "High Risk",
        "risk_score": 90.0,
        "confidence": 0.9,
        "probability": 0.9,
        "indicators": [{"code": "HIGH_ABUSE_TLD", "title": "High-Abuse Top-Level Domain"}]
    })

    updated_metrics = get_analytics_metrics()
    assert updated_metrics["total_scans"] == 2
    assert updated_metrics["phishing_count"] == 1
    assert updated_metrics["legitimate_count"] == 1
    assert updated_metrics["high_risk_count"] == 1
    assert updated_metrics["avg_risk_score"] == 50.0

