"""
PhishGuard AI - Database Connection Manager
Provides safe, parameterized SQLite database connectivity and schema migrations.
"""

from contextlib import contextmanager
import logging
import os
import sqlite3
from typing import Generator

from app.core.config import settings

logger = logging.getLogger("phishguard.db")


def get_db_path() -> str:
    db_path = settings.DATABASE_PATH
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    return db_path


def init_db() -> None:
    """Initializes the SQLite schema non-destructively with performance indexes."""
    db_path = get_db_path()
    logger.info("Initializing database schema at: %s", db_path)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")

        # Create scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_url TEXT NOT NULL,
                normalized_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                prediction TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence REAL NOT NULL,
                probability REAL NOT NULL,
                model_version TEXT,
                is_fallback INTEGER DEFAULT 0,
                is_uncertain INTEGER DEFAULT 0,
                feature_summary TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Create indexes for fast filtering, search, and analytics
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_prediction ON scans(prediction);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(normalized_url);")

        conn.commit()
    logger.info("Database schema and indexes initialized successfully.")


@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """Yields a SQLite connection with row factory enabled."""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

