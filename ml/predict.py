"""
PhishGuard AI - Prediction & Inference Engine
Loads the serialized machine learning model once on startup and performs
probabilistic phishing classification, risk scoring, and heuristic extraction.
"""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

from ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    extract_features_vector,
    get_heuristic_indicators,
    normalize_url,
)

logger = logging.getLogger("phishguard.ml")

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.joblib")
DEFAULT_METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


class PhishingPredictor:
    """Singleton inference class for PhishGuard AI."""

    _instance: Optional["PhishingPredictor"] = None

    def __init__(self, model_path: Optional[str] = None, metadata_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL_PATH
        self.metadata_path = metadata_path or DEFAULT_METADATA_PATH
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.is_fallback: bool = False
        self._load_model()

    @classmethod
    def get_instance(cls, model_path: Optional[str] = None) -> "PhishingPredictor":
        if cls._instance is None:
            cls._instance = PhishingPredictor(model_path=model_path)
        return cls._instance

    def _load_model(self) -> None:
        """Loads model and metadata from disk, or enables explicit fallback mode."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_fallback = False
                logger.info("Successfully loaded ML model from %s", self.model_path)
            except Exception as e:
                logger.error("Failed to load ML model from %s: %s", self.model_path, e)
                self.model = None
                self.is_fallback = True
        else:
            logger.warning(
                "Model file not found at %s. Operating in labeled fallback heuristic mode.",
                self.model_path
            )
            self.model = None
            self.is_fallback = True

        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.error("Failed to load metadata from %s: %s", self.metadata_path, e)
                self.metadata = {}
        else:
            self.metadata = {
                "model_name": "PhishGuard Rule Heuristic Fallback",
                "model_version": "0.1.0-fallback",
                "feature_count": len(FEATURE_NAMES),
                "trained_at": None,
            }

    def predict_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Executes end-to-end evaluation for an input URL:
        1. Normalization & safety check.
        2. Feature extraction (25 features).
        3. Model inference (Random Forest probabilities) or explicit rule-based fallback.
        4. Risk scoring, confidence calibration, and threat indicators.
        """
        normalized_url = normalize_url(raw_url)
        features_dict = extract_features(normalized_url)
        feature_vector = [features_dict[name] for name in FEATURE_NAMES]
        indicators = get_heuristic_indicators(normalized_url, features_dict)

        if not self.is_fallback and self.model is not None:
            # Model inference
            X = np.array([feature_vector], dtype=np.float64)
            probabilities = self.model.predict_proba(X)[0]
            # probabilities[0] = Legitimate, probabilities[1] = Phishing
            phishing_prob = float(probabilities[1])
            legitimate_prob = float(probabilities[0])

            if phishing_prob >= 0.50:
                prediction = "Phishing"
                confidence = phishing_prob
            else:
                prediction = "Legitimate"
                confidence = legitimate_prob

            risk_score = round(phishing_prob * 100.0, 1)
            used_fallback = False
            model_info = {
                "name": self.metadata.get("model_name", "Random Forest Classifier"),
                "version": self.metadata.get("model_version", "1.0.0"),
                "type": self.metadata.get("model_type", "RandomForestClassifier"),
                "feature_count": len(FEATURE_NAMES),
                "trained_at": self.metadata.get("trained_at"),
            }
        else:
            # Labeled development fallback: transparent rule-based heuristic
            used_fallback = True
            high_sev = sum(1 for ind in indicators if ind["severity"] == "HIGH")
            med_sev = sum(1 for ind in indicators if ind["severity"] == "MEDIUM")
            low_sev = sum(1 for ind in indicators if ind["severity"] == "LOW")

            base_score = min(100.0, (high_sev * 40.0) + (med_sev * 20.0) + (low_sev * 5.0))
            risk_score = round(base_score, 1)
            phishing_prob = round(risk_score / 100.0, 4)

            if phishing_prob >= 0.50:
                prediction = "Phishing"
                confidence = phishing_prob
            else:
                prediction = "Legitimate"
                confidence = round(1.0 - phishing_prob, 4)

            model_info = {
                "name": "Heuristic Rule Fallback (Development Mode)",
                "version": "0.1.0-fallback",
                "type": "RuleHeuristicEngine",
                "feature_count": len(FEATURE_NAMES),
                "trained_at": None,
                "notice": "Development fallback mode active. Predictions generated by heuristic rules, not ML model.",
            }

        # Calibrate Risk Level
        if risk_score >= 70.0:
            risk_level = "High Risk"
        elif risk_score >= 35.0:
            risk_level = "Medium Risk"
        else:
            risk_level = "Low Risk"

        # Low confidence uncertainty detection (boundary between 40% and 60%)
        is_uncertain = 0.40 <= phishing_prob <= 0.60
        uncertainty_warning = (
            "Model prediction lies within the uncertainty boundary (40-60%). "
            "Manual review or secondary verification is strongly advised."
            if is_uncertain else None
        )

        # Parse domain for quick referencing
        from urllib.parse import urlparse
        parsed = urlparse(normalized_url)
        domain = parsed.hostname or ""

        return {
            "submitted_url": raw_url,
            "normalized_url": normalized_url,
            "domain": domain,
            "prediction": prediction,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "probability": round(phishing_prob, 4),
            "confidence": round(confidence, 4),
            "is_uncertain": is_uncertain,
            "uncertainty_warning": uncertainty_warning,
            "is_fallback": used_fallback,
            "model_info": model_info,
            "indicators": indicators,
            "features": features_dict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

