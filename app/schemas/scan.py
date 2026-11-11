"""
PhishGuard AI - Scan Request & Response Schemas
Pydantic data models for URL scanning and history endpoints.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=3,
        max_length=2048,
        description="The target website URL to evaluate for phishing indicators."
    )


class IndicatorItem(BaseModel):
    code: str
    severity: str
    title: str
    description: str


class ModelInfo(BaseModel):
    name: str
    version: str
    type: str
    feature_count: int
    trained_at: Optional[str] = None
    notice: Optional[str] = None


class ScanResponse(BaseModel):
    id: Optional[int] = None
    submitted_url: str
    normalized_url: str
    domain: str
    prediction: str
    risk_level: str
    risk_score: float
    probability: float
    confidence: float
    is_uncertain: bool
    uncertainty_warning: Optional[str] = None
    is_fallback: bool
    model_info: ModelInfo
    indicators: List[IndicatorItem] = []
    features: Dict[str, float] = {}
    timestamp: str


class ScanHistoryItem(BaseModel):
    id: int
    submitted_url: str
    normalized_url: str
    domain: str
    prediction: str
    risk_level: str
    risk_score: float
    confidence: float
    probability: float
    model_version: Optional[str] = None
    is_fallback: bool = False
    is_uncertain: bool = False
    feature_summary: Optional[Dict[str, Any]] = None
    created_at: str


class ScanHistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[ScanHistoryItem]

