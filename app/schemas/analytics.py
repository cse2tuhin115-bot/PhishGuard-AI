"""
PhishGuard AI - Analytics Schemas
Pydantic models for threat intelligence and historical trends.
"""

from typing import Any, Dict, List
from pydantic import BaseModel


class RiskDistributionItem(BaseModel):
    name: str
    value: int
    color: str


class TrendPoint(BaseModel):
    date: str
    total: int
    phishing: int
    legitimate: int


class IndicatorStat(BaseModel):
    name: str
    count: int


class AnalyticsResponse(BaseModel):
    total_scans: int
    phishing_count: int
    legitimate_count: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    avg_risk_score: float
    phishing_percentage: float
    risk_distribution: List[RiskDistributionItem]
    daily_trend: List[TrendPoint]
    top_indicators: List[IndicatorStat]
    recent_scans: List[Dict[str, Any]]

