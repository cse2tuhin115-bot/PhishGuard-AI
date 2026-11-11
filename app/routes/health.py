"""
PhishGuard AI - Health Check Endpoints
Verifies API availability, database connectivity, and ML model status.
"""

from datetime import datetime, timezone
import os
import sqlite3
from fastapi import APIRouter
from app.core.config import settings
from ml.predict import PhishingPredictor

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Returns detailed operational health telemetry."""
    predictor = PhishingPredictor.get_instance()

    # Check SQLite connectivity
    db_status = "unavailable"
    db_records = 0
    try:
        if os.path.exists(settings.DATABASE_PATH):
            with sqlite3.connect(settings.DATABASE_PATH, timeout=2.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM scans;")
                db_records = cursor.fetchone()[0]
                db_status = "healthy"
        else:
            db_status = "uninitialized"
    except Exception as e:
        db_status = f"degraded: {str(e)[:50]}"

    return {
        "status": "healthy",
        "service": "PhishGuard AI Threat Analysis Platform",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "status": db_status,
            "total_records": db_records,
        },
        "model": {
            "loaded": not predictor.is_fallback,
            "is_fallback": predictor.is_fallback,
            "name": predictor.metadata.get("model_name", "Random Forest Classifier"),
            "version": predictor.metadata.get("model_version", "1.0.0"),
            "feature_count": predictor.metadata.get("feature_count", 25),
        }
    }

