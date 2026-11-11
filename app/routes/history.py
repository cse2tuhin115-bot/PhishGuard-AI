"""
PhishGuard AI - Scan History Endpoints
Provides paginated query, search, retrieval, deletion, and CSV export of historical evaluations.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from app.schemas.scan import ScanHistoryResponse, ScanResponse
from app.services.scan_service import (
    export_scans_csv,
    fetch_scan_detail,
    fetch_scans_paginated,
    remove_scan,
)

router = APIRouter(tags=["History"])


@router.get(
    "/history",
    response_model=ScanHistoryResponse,
    summary="List Historical Scans with Filtering"
)
def get_history(
    search: Optional[str] = Query(None, description="Filter by URL or domain substring"),
    prediction: Optional[str] = Query(None, description="Filter by Legitimate or Phishing"),
    risk_level: Optional[str] = Query(None, description="Filter by Low Risk, Medium Risk, or High Risk"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("created_at", description="Field to sort by"),
    order: str = Query("desc", description="Sort direction (asc or desc)"),
):
    """Retrieves paginated history of executed URL scans."""
    return fetch_scans_paginated(
        search=search,
        prediction=prediction,
        risk_level=risk_level,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        order=order
    )


@router.get(
    "/history/export",
    summary="Export Complete Scan History as CSV"
)
def export_history():
    """Generates a downloadable CSV snapshot of all recorded scans."""
    csv_content = export_scans_csv()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_scans_export.csv"}
    )


@router.get(
    "/history/{scan_id}",
    summary="Get Specific Scan Details"
)
def get_scan(scan_id: int):
    """Fetches full extracted characteristics and indicators for a historical scan."""
    record = fetch_scan_detail(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID {scan_id} was not found."
        )
    return record


@router.delete(
    "/history/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Historical Scan"
)
def delete_scan(scan_id: int):
    """Permanently deletes a single scan entry from the local SQLite store."""
    deleted = remove_scan(scan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID {scan_id} does not exist or has already been removed."
        )
    return {"status": "success", "message": f"Scan #{scan_id} deleted successfully."}

