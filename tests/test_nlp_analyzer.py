"""Tests for nlp_analyzer module."""

import pytest
from modules.nlp_analyzer import analyze_text, highlight_keywords, load_model


def test_analyze_text_suspicious_phishing():
    scam_msg = "URGENT: Your SBI account is blocked immediately! Share your OTP to verify KYC at once."
    res = analyze_text(scam_msg)
    assert res["verdict"] in ("High Risk", "Warning")
    assert res["risk_score"] > 0.5
    assert len(res["flags"]) > 0
    assert "assessment_type" in res
    assert "disclaimer" in res


def test_analyze_text_lottery_scam():
    lottery_msg = "Congratulations! You have won Rs 50,00,000 in lucky draw lottery. Pay registration fee now."
    res = analyze_text(lottery_msg)
    assert res["verdict"] in ("High Risk", "Warning")
    assert any("Prize" in f["category"] or "Advance fee" in f["category"] for f in res["flags"])


def test_analyze_text_benign_message():
    benign_msg = "Rs 200 debited from your account ending 5432. Available balance Rs 5,400. Do not share your OTP."
    res = analyze_text(benign_msg)
    assert res["verdict"] == "Safe"
    assert res["risk_score"] < 0.35


def test_analyze_text_empty_input():
    with pytest.raises(ValueError, match="enter some text"):
        analyze_text("")

    with pytest.raises(ValueError, match="enter some text"):
        analyze_text("   \n\t  ")

    with pytest.raises(ValueError, match="enter some text"):
        analyze_text(None)


def test_analyze_text_oversized_input():
    huge_text = "A" * 15_000
    with pytest.raises(ValueError, match="maximum allowed length"):
        analyze_text(huge_text)


def test_highlight_keywords():
    text = "Please share your otp and verify kyc"
    flags = [
        {"category": "Credential / OTP request", "keywords": ["otp", "kyc"]}
    ]
    highlighted = highlight_keywords(text, flags)
    assert "**otp**" in highlighted or "**OTP**" in highlighted.upper()
    assert "**kyc**" in highlighted or "**KYC**" in highlighted.upper()


def test_model_loading_and_fallback():
    # Should return pipeline or fall back to None without crashing
    model = load_model()
    assert model is not None
