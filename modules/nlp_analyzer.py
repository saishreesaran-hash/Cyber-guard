"""
NLP Content Analyzer: classifies SMS / email / chat text as Safe, Warning, or High Risk.

Reliability & Security Strategy:
1. Input Validation: Enforces type checks, whitespace checks, and maximum text length limits.
2. ML Model: TF-IDF (word 1-2 grams) + Logistic Regression trained on data/scam_messages.csv.
   The trained pipeline is cached to models/scam_model.joblib.
3. Rule-based Fallback: If the model cannot be loaded or trained (missing dependencies or files),
   a robust keyword/regex scoring engine is used seamlessly.
4. Hybrid Blending: High-confidence heuristic rules (OTP requests, KYC threats, remote access)
   reinforce model predictions to ensure critical scam patterns are not missed.
5. Explicit Disclaimers: Clearly distinguishes AI heuristic predictions from confirmed fraud.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "scam_messages.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "scam_model.joblib"

MAX_TEXT_LENGTH = 10_000

# Rule categories: name -> (weight, list of regex patterns)
RULE_CATEGORIES: Dict[str, tuple] = {
    "Urgency / threat": (
        0.20,
        [
            r"\burgent(ly)?\b", r"\bimmediately\b", r"\bact now\b", r"\bfinal (notice|warning)\b",
            r"\blast warning\b", r"\bwithin 24 hours\b", r"\bexpires? (today|soon|in \d+)",
            r"\bblocked\b", r"\bsuspended\b", r"\bdeactivated\b", r"\bdisconnected\b",
            r"\bterminated\b", r"\bhurry\b", r"\bavoid (arrest|penalty)\b",
        ],
    ),
    "Credential / OTP request": (
        0.35,
        [
            r"\botp\b", r"\bcvv\b", r"\bpin\b", r"\bpassword\b", r"\bshare (your )?(code|otp)\b",
            r"\bcard number\b", r"\bnet ?banking\b", r"\bverify (your )?(account|pan|aadhaar|identity)\b",
            r"\bupdate (your )?(kyc|pan|bank details|payment)\b", r"\bkyc\b",
        ],
    ),
    "Prize / lottery bait": (
        0.30,
        [
            r"\blottery\b", r"\blucky (draw|winner)\b", r"\bcongratulations\b", r"\byou (have )?won\b",
            r"\bgiveaway\b", r"\bprize\b", r"\bcashback\b", r"\bfree (iphone|recharge|gift)\b",
            r"\bpre-?approved\b", r"\bguaranteed returns?\b", r"\b\d{2,3} ?(percent|%) returns?\b",
        ],
    ),
    "Advance fee / payment demand": (
        0.30,
        [
            r"\bregistration fee\b", r"\bprocessing fee\b", r"\bclearance charges?\b",
            r"\bpay (rs\.?|inr|₹)? ?[\d,]+", r"\btransfer (rs\.?|inr|₹)? ?[\d,]+",
            r"\b(gst|insurance|tax) fee\b", r"\breturn (it|the money|the amount)\b",
            r"\bsent .{0,20}by mistake\b", r"\baccidentally sent\b",
        ],
    ),
    "Fake authority / bank impersonation": (
        0.20,
        [
            r"\bpolice case\b", r"\bcustoms\b", r"\bincome tax\b", r"\bhead office\b",
            r"\b(sbi|hdfc|icici|axis|paytm|phonepe|gpay)\b.{0,40}\b(blocked|suspended|expired|kyc|verify)\b",
            r"\baadhaar\b.{0,30}\b(deactivat|block|verify)", r"\bsim\b.{0,30}\b(deactivat|block)",
        ],
    ),
    "Suspicious link / remote access": (
        0.25,
        [
            r"https?://\S+\.(xyz|top|tk|ml|ga|cf|gq|click|work|info|buzz)\b",
            r"\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy)/\S+",
            r"\banydesk\b", r"\bteamviewer\b", r"\bquicksupport\b", r"\bscan this qr\b",
            r"\bclick (the |this )?(link|here)\b", r"\binstall this app\b",
        ],
    ),
}

# Phrases that reassure. They slightly reduce rule score (e.g. real bank alerts).
SAFE_HINTS = [
    r"\bdo not share (it|your otp)\b", r"\bnever ask for your (pin|otp)\b",
    r"\bofficial (app|website)\b", r"\bavailable balance\b", r"\bfor your records\b",
]

_pipeline = None  # lazy-loaded sklearn pipeline


# --------------------------------------------------------------------------- #
# Rule-based engine
# --------------------------------------------------------------------------- #
def _rule_based_analysis(text: str) -> Dict[str, Any]:
    lowered = text.lower()
    score = 0.0
    flags: List[Dict[str, Any]] = []

    for category, (weight, patterns) in RULE_CATEGORIES.items():
        hits = []
        for pattern in patterns:
            try:
                for match in re.finditer(pattern, lowered):
                    hits.append(match.group(0).strip())
            except Exception:
                continue
        if hits:
            # diminishing returns for multiple hits in the same category
            category_score = weight * min(1.0, 0.6 + 0.2 * (len(set(hits)) - 1))
            score += category_score
            flags.append({"category": category, "keywords": sorted(set(hits))[:6]})

    if any(re.search(p, lowered) for p in SAFE_HINTS):
        score -= 0.15

    return {"score": max(0.0, min(1.0, score)), "flags": flags}


# --------------------------------------------------------------------------- #
# ML model
# --------------------------------------------------------------------------- #
def train_model(save: bool = True):
    """Train the TF-IDF + Logistic Regression pipeline from data/scam_messages.csv."""
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Training data not found at {DATA_PATH}")

    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    df = pd.read_csv(DATA_PATH).dropna()
    if df.empty or "text" not in df.columns or "label" not in df.columns:
        raise ValueError("Training dataset must contain 'text' and 'label' columns with rows.")

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True, ngram_range=(1, 2), stop_words="english",
                    sublinear_tf=True, min_df=1,
                ),
            ),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=3.0)),
        ]
    )
    pipeline.fit(df["text"], df["label"])

    if save:
        try:
            import joblib

            MODEL_DIR.mkdir(parents=True, exist_ok=True)
            joblib.dump(pipeline, MODEL_PATH)
        except Exception as exc:
            logger.warning("Could not cache model to disk: %s", exc)
    return pipeline


def load_model():
    """Load the cached model, training it first if needed. Returns None if unavailable."""
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    try:
        if MODEL_PATH.exists():
            import joblib

            _pipeline = joblib.load(MODEL_PATH)
        elif DATA_PATH.exists():
            _pipeline = train_model(save=True)
        else:
            logger.warning("No model file or training data found; using rule-based fallback.")
    except Exception as exc:
        logger.warning("Model load failed (%s); using rule-based fallback.", exc)
        _pipeline = None
    return _pipeline


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def _verdict_from_score(score: float) -> str:
    if score >= 0.65:
        return "High Risk"
    if score >= 0.35:
        return "Warning"
    return "Safe"


def analyze_text(text: Optional[str]) -> Dict[str, Any]:
    """
    Analyze a message for fraud, phishing, or financial scam indicators.

    Parameters
    ----------
    text : Optional[str]
        The message content to analyze.

    Returns
    -------
    dict with keys:
        verdict          : "Safe" | "Warning" | "High Risk"
        confidence       : float 0-1 (confidence in the verdict)
        risk_score       : float 0-1 (scam probability)
        flags            : list of {"category", "keywords"}
        highlighted      : original text with flagged keywords in **bold**
        method           : "ml+rules" or "rules"
        assessment_type  : "AI Heuristic Prediction (Not Confirmed Fraud)"
        disclaimer       : explanation that this is a predictive assessment
    """
    if text is None or not isinstance(text, str) or not text.strip():
        raise ValueError("Please enter some text to analyze.")

    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"Input text exceeds maximum allowed length of {MAX_TEXT_LENGTH:,} characters.")

    cleaned_text = text.strip()
    rules = _rule_based_analysis(cleaned_text)
    model = load_model()

    if model is not None:
        try:
            ml_prob = float(model.predict_proba([cleaned_text])[0][1])
            # blend: model carries primary weight, rules protect against false negatives
            risk = 0.65 * ml_prob + 0.35 * min(1.0, rules["score"] * 1.5)
            # a strong rule hit should never be washed out
            risk = max(risk, min(0.9, rules["score"]) if rules["score"] >= 0.6 else risk)
            method = "ml+rules"
        except Exception as exc:
            logger.warning("Model prediction failed (%s); falling back to rule-based analysis.", exc)
            risk, method = rules["score"], "rules"
    else:
        risk, method = rules["score"], "rules"

    risk = max(0.0, min(1.0, risk))
    verdict = _verdict_from_score(risk)
    confidence = risk if verdict == "High Risk" else (1 - risk if verdict == "Safe" else 1 - abs(risk - 0.5) * 2 * 0.5)

    return {
        "verdict": verdict,
        "confidence": round(float(confidence), 3),
        "risk_score": round(float(risk), 3),
        "flags": rules["flags"],
        "highlighted": highlight_keywords(cleaned_text, rules["flags"]),
        "method": method,
        "assessment_type": "AI Heuristic Prediction (Not Confirmed Fraud)",
        "disclaimer": "This rating is an automated statistical estimate based on pattern analysis and should not be taken as legal or financial proof of fraud.",
    }


def highlight_keywords(text: str, flags: List[Dict[str, Any]]) -> str:
    """Wrap flagged keywords in markdown bold so the UI can highlight them."""
    if not text or not flags:
        return text

    keywords = sorted({kw for f in flags for kw in f.get("keywords", []) if kw}, key=len, reverse=True)
    highlighted = text
    for kw in keywords:
        try:
            highlighted = re.sub(f"(?i)({re.escape(kw)})", r"**\1**", highlighted)
        except Exception:
            continue
    return highlighted.replace("****", "**")
