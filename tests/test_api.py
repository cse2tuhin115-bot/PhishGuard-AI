"""
Integration tests for FastAPI endpoints: health, scan, history, analytics, error handling.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "model" in data
    assert "database" in data


def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_scan_valid_url():
    payload = {"url": "https://www.google.com"}
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["submitted_url"] == "https://www.google.com"
    assert data["prediction"] in ("Legitimate", "Phishing")
    assert data["risk_level"] in ("Low Risk", "Medium Risk", "High Risk")
    assert "features" in data
    assert "id" in data
    assert data["id"] is not None


def test_scan_phishing_url():
    payload = {"url": "http://paypal-verification-center-account.xyz/signin/index.php"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["prediction"] == "Phishing"
    assert data["risk_level"] in ("High Risk", "Medium Risk")
    assert len(data["indicators"]) > 0


def test_scan_invalid_empty_url():
    response = client.post("/scan", json={"url": ""})
    assert response.status_code in (400, 422)


def test_scan_dangerous_scheme_rejected():
    response = client.post("/scan", json={"url": "javascript:alert(document.cookie)"})
    assert response.status_code == 400
    assert "rejected" in response.json()["detail"].lower()


def test_history_and_pagination():
    # Make a scan first
    client.post("/scan", json={"url": "https://wikipedia.org"})

    response = client.get("/history?page=1&page_size=5")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1


def test_analytics_endpoint():
    response = client.get("/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "risk_distribution" in data
    assert "daily_trend" in data


def test_export_endpoint():
    response = client.get("/history/export")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "Submitted URL" in response.text

