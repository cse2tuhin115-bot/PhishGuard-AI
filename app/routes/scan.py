"""
PhishGuard AI - URL Scan Endpoint
Receives target URLs, runs feature extraction and ML classification,
and returns full defensive threat assessment.
"""

import logging
from fastapi import APIRouter, HTTPException, status
from app.schemas.scan import ScanRequest, ScanResponse
from app.services.scan_service import process_url_scan

logger = logging.getLogger("phishguard.routes.scan")
router = APIRouter(tags=["Scanning"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate URL for Phishing Indicators"
)
def scan_url(payload: ScanRequest):
    """
    Submits a target URL to the AI analysis pipeline.
    The URL is analyzed purely syntactically without network visits.
    """
    try:
        result = process_url_scan(payload.url)
        return result
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        logger.error("Scan processing encountered unexpected failure: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while evaluating the target URL. Please verify the URL format and try again."
        )

