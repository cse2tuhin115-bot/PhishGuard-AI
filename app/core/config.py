"""
PhishGuard AI - Application Configuration
Manages environment variables, default paths, and service configurations.
"""

import os
from typing import List


class Settings:
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"

    # Base Directories
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DATA_DIR: str = os.path.join(BASE_DIR, "data")
    MODELS_DIR: str = os.path.join(BASE_DIR, "models")

    # Database
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH",
        os.path.join(DATA_DIR, "phishguard.db")
    )

    # ML Model
    MODEL_PATH: str = os.getenv(
        "MODEL_PATH",
        os.path.join(MODELS_DIR, "phishing_model.joblib")
    )
    METADATA_PATH: str = os.getenv(
        "METADATA_PATH",
        os.path.join(MODELS_DIR, "model_metadata.json")
    )

    # Security & Limits
    MAX_URL_LENGTH: int = 2048
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]


settings = Settings()

