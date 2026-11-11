"""
PhishGuard AI - Main FastAPI Application
AI-Powered Phishing Website Detection System & Security Intelligence Backend.
"""

from contextlib import asynccontextmanager
import json
import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database.connection import init_db
from app.routes.analytics import router as analytics_router
from app.routes.health import router as health_router
from app.routes.history import router as history_router
from app.routes.scan import router as scan_router
from ml.predict import PhishingPredictor

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("Initializing %s v%s...", settings.PROJECT_NAME, settings.VERSION)

    # 1. Non-destructive database initialization
    init_db()

    # 2. Warm up and verify ML predictor singleton
    predictor = PhishingPredictor.get_instance()
    if predictor.is_fallback:
        logger.warning("ML predictor running in labeled fallback mode.")
    else:
        logger.info("ML predictor loaded successfully: %s", predictor.metadata.get("model_name"))

    yield
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


app = FastAPI(
    title="PhishGuard AI - Intelligent Phishing Detection API",
    description=(
        "Production-style cybersecurity threat assessment API evaluating URL characteristics "
        "using machine learning classification and heuristic indicators. Designed strictly "
        "for defensive research and educational triage."
    ),
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register endpoints at root level for backward compatibility
app.include_router(health_router)
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(analytics_router)

# Also register endpoints under /api prefix for standard REST architectures
app.include_router(health_router, prefix=settings.API_PREFIX)
app.include_router(scan_router, prefix=settings.API_PREFIX)
app.include_router(history_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)


@app.get("/", tags=["System"])
def root():
    return {
        "service": "PhishGuard AI Platform",
        "tagline": "AI-Powered Phishing Website Detection System",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/api/samples", tags=["Samples"])
@app.get("/samples", tags=["Samples"])
def get_sample_urls():
    """Provides curated test URLs for quick evaluation in the UI."""
    sample_path = os.path.join(settings.DATA_DIR, "sample_urls.json")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

