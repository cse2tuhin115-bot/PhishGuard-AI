"""
PhishGuard AI - Database Operations
Implements parameterized SQL queries for scans and analytics.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Tuple

from app.database.connection import get_db_connection


def save_scan(scan_data: Dict[str, Any]) -> int:
    """Inserts a new scan record and returns the created record id."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        feature_summary_json = json.dumps({
            "features": scan_data.get("features", {}),
            "indicators": scan_data.get("indicators", []),
            "model_info": scan_data.get("model_info", {}),
            "uncertainty_warning": scan_data.get("uncertainty_warning"),
        })

        created_at = scan_data.get("timestamp") or datetime.now(timezone.utc).isoformat()

        cursor.execute("""
            INSERT INTO scans (
                submitted_url,
                normalized_url,
                domain,
                prediction,
                risk_level,
                risk_score,
                confidence,
                probability,
                model_version,
                is_fallback,
                is_uncertain,
                feature_summary,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            scan_data["submitted_url"],
            scan_data["normalized_url"],
            scan_data["domain"],
            scan_data["prediction"],
            scan_data["risk_level"],
            scan_data["risk_score"],
            scan_data["confidence"],
            scan_data["probability"],
            scan_data.get("model_info", {}).get("version", "1.0.0"),
            1 if scan_data.get("is_fallback") else 0,
            1 if scan_data.get("is_uncertain") else 0,
            feature_summary_json,
            created_at,
        ))
        conn.commit()
        return cursor.lastrowid


def get_scans(
    search: Optional[str] = None,
    prediction: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    sort_by: str = "created_at",
    order: str = "desc"
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieves paginated scan records with filtering and returns (scans, total_count)."""
    where_clauses = []
    params: List[Any] = []

    if search:
        where_clauses.append("(normalized_url LIKE ? OR domain LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    if prediction and prediction.lower() != "all":
        where_clauses.append("LOWER(prediction) = LOWER(?)")
        params.append(prediction)

    if risk_level and risk_level.lower() != "all":
        where_clauses.append("LOWER(risk_level) = LOWER(?)")
        params.append(risk_level)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    # Validate sort order and column
    valid_sorts = {
        "created_at": "created_at",
        "risk_score": "risk_score",
        "domain": "domain",
        "prediction": "prediction",
    }
    col = valid_sorts.get(sort_by, "created_at")
    dir_sql = "ASC" if order.lower() == "asc" else "DESC"

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Count total
        count_query = f"SELECT COUNT(*) FROM scans {where_sql};"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Fetch page
        query = f"""
            SELECT id, submitted_url, normalized_url, domain, prediction, risk_level,
                   risk_score, confidence, probability, model_version, is_fallback,
                   is_uncertain, feature_summary, created_at
            FROM scans
            {where_sql}
            ORDER BY {col} {dir_sql}
            LIMIT ? OFFSET ?;
        """
        cursor.execute(query, params + [limit, offset])
        rows = cursor.fetchall()

        scans = []
        for r in rows:
            summary = {}
            if r["feature_summary"]:
                try:
                    summary = json.loads(r["feature_summary"])
                except Exception:
                    summary = {}

            scans.append({
                "id": r["id"],
                "submitted_url": r["submitted_url"],
                "normalized_url": r["normalized_url"],
                "domain": r["domain"],
                "prediction": r["prediction"],
                "risk_level": r["risk_level"],
                "risk_score": r["risk_score"],
                "confidence": r["confidence"],
                "probability": r["probability"],
                "model_version": r["model_version"],
                "is_fallback": bool(r["is_fallback"]),
                "is_uncertain": bool(r["is_uncertain"]),
                "feature_summary": summary,
                "created_at": r["created_at"],
            })

        return scans, total_count


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single scan record with full details."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, submitted_url, normalized_url, domain, prediction, risk_level,
                   risk_score, confidence, probability, model_version, is_fallback,
                   is_uncertain, feature_summary, created_at
            FROM scans
            WHERE id = ?;
        """, (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None

        summary = {}
        if row["feature_summary"]:
            try:
                summary = json.loads(row["feature_summary"])
            except Exception:
                summary = {}

        return {
            "id": row["id"],
            "submitted_url": row["submitted_url"],
            "normalized_url": row["normalized_url"],
            "domain": row["domain"],
            "prediction": row["prediction"],
            "risk_level": row["risk_level"],
            "risk_score": row["risk_score"],
            "confidence": row["confidence"],
            "probability": row["probability"],
            "model_version": row["model_version"],
            "is_fallback": bool(row["is_fallback"]),
            "is_uncertain": bool(row["is_uncertain"]),
            "feature_summary": summary,
            "created_at": row["created_at"],
        }


def delete_scan_by_id(scan_id: int) -> bool:
    """Deletes a single scan by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0


def get_all_scans_for_export() -> List[Dict[str, Any]]:
    """Fetches all scans for JSON/CSV export without pagination limits."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, submitted_url, normalized_url, domain, prediction, risk_level,
                   risk_score, confidence, probability, model_version, created_at
            FROM scans
            ORDER BY created_at DESC;
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_analytics_metrics() -> Dict[str, Any]:
    """Computes real aggregated metrics strictly from SQLite records."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Total count
        cursor.execute("SELECT COUNT(*) FROM scans;")
        total_scans = cursor.fetchone()[0]

        if total_scans == 0:
            return {
                "total_scans": 0,
                "phishing_count": 0,
                "legitimate_count": 0,
                "high_risk_count": 0,
                "medium_risk_count": 0,
                "low_risk_count": 0,
                "avg_risk_score": 0.0,
                "phishing_percentage": 0.0,
                "risk_distribution": [
                    {"name": "Low Risk", "value": 0, "color": "#10b981"},
                    {"name": "Medium Risk", "value": 0, "color": "#f59e0b"},
                    {"name": "High Risk", "value": 0, "color": "#ef4444"},
                ],
                "daily_trend": [],
                "top_indicators": [],
                "recent_scans": [],
            }

        # Counts by prediction
        cursor.execute("SELECT COUNT(*) FROM scans WHERE prediction = 'Phishing';")
        phishing_count = cursor.fetchone()[0]
        legitimate_count = total_scans - phishing_count

        # Counts by risk level
        cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High Risk';")
        high_risk_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium Risk';")
        medium_risk_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Low Risk';")
        low_risk_count = cursor.fetchone()[0]

        # Average risk score
        cursor.execute("SELECT AVG(risk_score) FROM scans;")
        avg_score_res = cursor.fetchone()[0]
        avg_risk_score = round(float(avg_score_res), 1) if avg_score_res is not None else 0.0

        phishing_percentage = round((phishing_count / total_scans) * 100.0, 1)

        # Daily scanning activity (last 14 days)
        cursor.execute("""
            SELECT SUBSTR(created_at, 1, 10) as scan_date,
                   COUNT(*) as count,
                   SUM(CASE WHEN prediction = 'Phishing' THEN 1 ELSE 0 END) as phishing,
                   SUM(CASE WHEN prediction = 'Legitimate' THEN 1 ELSE 0 END) as legitimate
            FROM scans
            GROUP BY scan_date
            ORDER BY scan_date ASC
            LIMIT 14;
        """)
        trend_rows = cursor.fetchall()
        daily_trend = [
            {
                "date": row["scan_date"],
                "total": row["count"],
                "phishing": row["phishing"],
                "legitimate": row["legitimate"],
            }
            for row in trend_rows
        ]

        # Most frequent warning indicators
        cursor.execute("SELECT feature_summary FROM scans WHERE feature_summary IS NOT NULL;")
        summary_rows = cursor.fetchall()
        indicator_counts: Dict[str, int] = {}
        for s_row in summary_rows:
            try:
                data = json.loads(s_row["feature_summary"])
                for ind in data.get("indicators", []):
                    code = ind.get("title", ind.get("code", "Unknown"))
                    indicator_counts[code] = indicator_counts.get(code, 0) + 1
            except Exception:
                continue

        top_indicators = [
            {"name": k, "count": v}
            for k, v in sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:6]
        ]

        # Fetch recent 5 scans
        cursor.execute("""
            SELECT id, submitted_url, normalized_url, domain, prediction, risk_level,
                   risk_score, created_at
            FROM scans
            ORDER BY created_at DESC
            LIMIT 5;
        """)
        recent_rows = cursor.fetchall()
        recent_scans = [dict(r) for r in recent_rows]

        return {
            "total_scans": total_scans,
            "phishing_count": phishing_count,
            "legitimate_count": legitimate_count,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count,
            "avg_risk_score": avg_risk_score,
            "phishing_percentage": phishing_percentage,
            "risk_distribution": [
                {"name": "Low Risk", "value": low_risk_count, "color": "#10b981"},
                {"name": "Medium Risk", "value": medium_risk_count, "color": "#f59e0b"},
                {"name": "High Risk", "value": high_risk_count, "color": "#ef4444"},
            ],
            "daily_trend": daily_trend,
            "top_indicators": top_indicators,
            "recent_scans": recent_scans,
        }

