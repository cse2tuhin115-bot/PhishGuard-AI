"""
Unit tests for ML prediction engine, risk scoring, and fallback modes.
"""

from ml.predict import PhishingPredictor


def test_predictor_singleton():
    p1 = PhishingPredictor.get_instance()
    p2 = PhishingPredictor.get_instance()
    assert p1 is p2


def test_predict_legitimate_url():
    predictor = PhishingPredictor.get_instance()
    result = predictor.predict_url("https://docs.python.org/3/")

    assert result["prediction"] in ("Legitimate", "Phishing")
    assert result["risk_level"] in ("Low Risk", "Medium Risk", "High Risk")
    assert 0.0 <= result["probability"] <= 1.0
    assert 0.0 <= result["risk_score"] <= 100.0
    assert "features" in result
    assert "indicators" in result
    assert "domain" in result


def test_predict_phishing_url():
    predictor = PhishingPredictor.get_instance()
    result = predictor.predict_url("http://paypal-verification-center-account.xyz/signin/index.php")

    assert result["prediction"] == "Phishing"
    assert result["risk_level"] in ("High Risk", "Medium Risk")
    assert result["risk_score"] >= 50.0


def test_fallback_mode_flag():
    # Instantiate predictor with non-existent model to verify fallback behavior
    fallback_predictor = PhishingPredictor(model_path="non_existent_model.joblib")
    assert fallback_predictor.is_fallback is True

    res = fallback_predictor.predict_url("http://192.168.1.1/login.php")
    assert res["is_fallback"] is True
    assert "Fallback" in res["model_info"]["name"]

