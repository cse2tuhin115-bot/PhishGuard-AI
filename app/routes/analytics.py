"""
PhishGuard AI - Threat Analytics Endpoint
Delivers aggregated statistics, category distributions, and daily trends.
"""

from fastapi import APIRouter
from app.schemas.analytics import AnalyticsResponse
from app.services.analytics_service import fetch_analytics

router = APIRouter(tags=["Analytics"])


@router.get(
    "/analytics",
    response_model=AnalyticsResponse,
    summary="Get Aggregated Threat Analytics"
)
def get_analytics():
    """Returns telemetry metrics and historical distribution for the dashboard."""
    return fetch_analytics()

