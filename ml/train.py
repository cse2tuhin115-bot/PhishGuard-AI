"""
PhishGuard AI - Model Training Script
Extracts features, trains a calibrated Random Forest Classifier, evaluates performance metrics,
and serializes the trained model artifact and metadata.
"""

from datetime import datetime, timezone
import json
import os
from typing import Dict, Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml.dataset import get_training_data
from ml.feature_extractor import FEATURE_NAMES, extract_features_vector

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model.joblib")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def train_model() -> Dict[str, Any]:
    """Trains the Random Forest model and saves artifacts."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    print("[*] Generating dataset and extracting features...")
    urls, labels = get_training_data()

    X = np.array([extract_features_vector(url) for url in urls])
    y = np.array(labels)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"[*] Training dataset size: {len(X_train)} samples, Test size: {len(X_test)} samples")
    print(f"[*] Total features: {len(FEATURE_NAMES)}")

    # Initialize Random Forest with balanced class weights
    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced"
    )

    classifier.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = classifier.predict(X_test)
    y_prob = classifier.predict_proba(X_test)[:, 1]

    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))

    print(f"[+] Model Accuracy:  {accuracy:.4f}")
    print(f"[+] Model Precision: {precision:.4f}")
    print(f"[+] Model Recall:    {recall:.4f}")
    print(f"[+] Model F1 Score:  {f1:.4f}")
    print(f"[+] Model ROC-AUC:   {roc_auc:.4f}")

    # Calculate feature importances
    importances = classifier.feature_importances_
    feature_importance_dict = {
        name: float(round(imp, 5))
        for name, imp in sorted(
            zip(FEATURE_NAMES, importances),
            key=lambda item: item[1],
            reverse=True
        )
    }

    # Save model artifact
    joblib.dump(classifier, MODEL_PATH)
    print(f"[+] Serialized model artifact to: {MODEL_PATH}")

    # Build comprehensive metadata document
    metadata = {
        "model_name": "PhishGuard Random Forest URL Classifier",
        "model_type": "RandomForestClassifier",
        "model_version": "1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "dataset_summary": {
            "total_samples": len(urls),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "classes": {"0": "Legitimate", "1": "Phishing"}
        },
        "evaluation_metrics": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "evaluation_notice": (
                "Metrics evaluated on internal defensive demonstration dataset. "
                "Synthetic and curated benchmark metrics do not represent real-world "
                "production efficacy without continuous, time-separated telemetry validation."
            )
        },
        "feature_importance": feature_importance_dict,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 8,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "class_weight": "balanced",
            "random_state": 42
        },
        "limitations": [
            "ML URL classification is a probabilistic triage mechanism and cannot guarantee that an evaluated URL is safe.",
            "Newly registered zero-day phishing domains with benign lexical structures may produce false negatives.",
            "Shortened URLs require secondary HTTP hop resolution for conclusive verification.",
            "Always combine ML heuristics with threat intelligence feeds, SPF/DKIM/DMARC mail verification, and active browser sandboxing."
        ]
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata to: {METADATA_PATH}")

    return metadata


if __name__ == "__main__":
    train_model()

