"""
PhishGuard AI - Scan Service
Coordinates URL sanitization, feature extraction, ML inference, and DB persistence.
"""

import csv
import io
import math
from typing import Any, Dict, List, Optional, Tuple

from app.core.security import sanitize_and_validate_url
from app.database.models import (
    delete_scan_by_id,
    get_all_scans_for_export,
    get_scan_by_id,
    get_scans,
    save_scan,
)
from ml.predict import PhishingPredictor


def process_url_scan(raw_url: str) -> Dict[str, Any]:
    """
    Executes a complete scan workflow:
    1. Sanitizes and validates the raw URL.
    2. Runs feature extraction and model prediction.
    3. Persists the evaluation to SQLite.
    4. Returns the full scan response including database ID.
    """
    clean_url = sanitize_and_validate_url(raw_url)
    predictor = PhishingPredictor.get_instance()
    result = predictor.predict_url(clean_url)

    # Save to SQLite
    record_id = save_scan(result)
    result["id"] = record_id
    return result


def fetch_scans_paginated(
    search: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None,
    page: int = 1,
    page_size: int = 10,
    sort_by: str = "created_at",
    order: str = "desc"
) -> Dict[str, Any]:
    """Retrieves filtered scans and paginated metadata."""
    limit = max(1, min(page_size, 100))
    offset = (max(1, page) - 1) * limit

    items, total = get_scans(
        search=search,
        prediction=prediction,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
        sort_by=sort_by,
        order=order
    )

    total_pages = max(1, math.ceil(total / limit)) if total > 0 else 1

    return {
        "total": total,
        "page": page,
        "page_size": limit,
        "total_pages": total_pages,
        "items": items,
    }


def fetch_scan_detail(scan_id: int) -> Optional[Dict[str, Any]]:
    return get_scan_by_id(scan_id)


def remove_scan(scan_id: int) -> bool:
    return delete_scan_by_id(scan_id)


def export_scans_csv() -> str:
    """Generates a CSV representation of all recorded scans."""
    records = get_all_scans_for_export()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Submitted URL", "Normalized URL", "Domain", "Prediction",
        "Risk Level", "Risk Score", "Confidence", "Model Version", "Timestamp"
    ])

    for r in records:
        writer.writerow([
            r.get("id"),
            r.get("submitted_url"),
            r.get("normalized_url"),
            r.get("domain"),
            r.get("prediction"),
            r.get("risk_level"),
            r.get("risk_score"),
            r.get("confidence"),
            r.get("model_version"),
            r.get("created_at"),
        ])

    return output.getvalue()

