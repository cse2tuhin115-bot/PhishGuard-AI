"""
PhishGuard AI - Analytics Service
Aggregates telemetry and model prediction distribution metrics.
"""

from typing import Any, Dict
from app.database.models import get_analytics_metrics


def fetch_analytics() -> Dict[str, Any]:
    """Retrieves computed threat intelligence and scan statistics."""
    return get_analytics_metrics()

