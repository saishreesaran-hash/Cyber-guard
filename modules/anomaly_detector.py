"""
Device Health & App Permission Auditor using Isolation Forest Anomaly Detection.

Pipeline & Features:
1. Input Validation: Robust CSV/JSON parser with file size limits, whitespace stripping,
   and intelligent boolean conversion ('yes'/'no', 'true'/'false', 1/0).
2. Synthetic Baseline: Trained on normal smartphone application permission and background data distributions.
3. Unsupervised Outlier Detection: Scored with scikit-learn's IsolationForest algorithm.
4. Explainable AI: Generates human-readable explanations of why specific apps were flagged
   (e.g., overlay permissions, excessive background data usage, dangerous permission bundles).
5. Explicit Disclaimers: Clearly labels outputs as statistical anomalies rather than confirmed malware.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any, Dict, Optional, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MOCK_APPS_PATH = DATA_DIR / "mock_app_permissions.csv"

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB max upload for CSV/JSON

FEATURES = [
    "has_sms_permission",
    "has_camera_permission",
    "has_contacts_permission",
    "background_data_usage_mb",
    "overlay_permission",
]
REQUIRED_COLUMNS = ["app_name"] + FEATURES

_model: Optional[IsolationForest] = None
_threshold_warn: float = 0.0


# --------------------------------------------------------------------------- #
# Data
# --------------------------------------------------------------------------- #
def generate_training_data(n_samples: int = 600, seed: int = 42) -> pd.DataFrame:
    """Generate synthetic 'normal' app behaviour for baseline training."""
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(
        {
            "has_sms_permission": rng.choice([0, 1], n_samples, p=[0.93, 0.07]),
            "has_camera_permission": rng.choice([0, 1], n_samples, p=[0.75, 0.25]),
            "has_contacts_permission": rng.choice([0, 1], n_samples, p=[0.85, 0.15]),
            "background_data_usage_mb": np.clip(rng.gamma(2.0, 12.0, n_samples), 0, 150),
            "overlay_permission": rng.choice([0, 1], n_samples, p=[0.97, 0.03]),
        }
    )
    return df


def build_mock_app_list() -> pd.DataFrame:
    """A realistic demo dataset containing safe apps, warnings, and high-risk anomalies."""
    rows = [
        # name, sms, camera, contacts, bg_mb, overlay
        ("WhatsApp", 0, 1, 1, 45, 0),
        ("Google Maps", 0, 1, 0, 30, 0),
        ("Calculator", 0, 0, 0, 1, 0),
        ("Spotify", 0, 0, 0, 55, 0),
        ("Instagram", 0, 1, 1, 70, 0),
        ("Notes", 0, 0, 0, 2, 0),
        ("Weather", 0, 0, 0, 18, 0),
        ("Banking App", 1, 1, 0, 14, 0),
        ("Flashlight Pro", 1, 1, 1, 310, 1),
        ("Free Wallpapers HD", 1, 0, 1, 260, 1),
        ("System Update Service", 1, 1, 1, 420, 1),
        ("Battery Saver Plus", 0, 1, 1, 380, 1),
        ("PDF Reader", 0, 0, 0, 6, 0),
        ("Camera Filters", 0, 1, 0, 25, 0),
        ("QuickCash Loan", 1, 1, 1, 190, 1),
    ]
    return pd.DataFrame(rows, columns=REQUIRED_COLUMNS)


def ensure_sample_files() -> None:
    """Ensure the mock CSV exists in data/ for download or demonstration."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not MOCK_APPS_PATH.exists():
        build_mock_app_list().to_csv(MOCK_APPS_PATH, index=False)


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
def train_model(contamination: float = 0.03, seed: int = 42) -> IsolationForest:
    global _model, _threshold_warn
    X = generate_training_data()[FEATURES]
    _model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    _model.fit(X)
    train_scores = _model.decision_function(X)
    _threshold_warn = float(np.percentile(train_scores, 12))
    return _model


def get_model() -> IsolationForest:
    return _model if _model is not None else train_model()


# --------------------------------------------------------------------------- #
# Input handling
# --------------------------------------------------------------------------- #
def _convert_boolean_or_numeric(val: Any) -> float:
    """Helper to convert boolean strings ('yes', 'no', 'true', 'false') or numbers safely."""
    if pd.isna(val):
        return np.nan
    if isinstance(val, (bool, np.bool_)):
        return 1.0 if val else 0.0
    if isinstance(val, (int, float, np.number)):
        return float(val)
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "y", "enable", "enabled"):
        return 1.0
    if s in ("0", "false", "no", "n", "disable", "disabled", ""):
        return 0.0
    try:
        return float(s)
    except ValueError:
        return np.nan


def load_app_data(file_or_text: Union[str, bytes, object], filename: str = "") -> pd.DataFrame:
    """
    Parse uploaded CSV or JSON file with validation against empty, malformed, or oversized inputs.
    """
    try:
        if hasattr(file_or_text, "read"):
            raw = file_or_text.read()
        else:
            raw = file_or_text

        if isinstance(raw, bytes):
            if len(raw) > MAX_FILE_SIZE:
                raise ValueError(f"Uploaded file exceeds {MAX_FILE_SIZE / (1024*1024):.0f} MB size limit.")
            raw = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str) and len(raw.encode("utf-8")) > MAX_FILE_SIZE:
            raise ValueError(f"Uploaded content exceeds {MAX_FILE_SIZE / (1024*1024):.0f} MB size limit.")

        if not raw or not raw.strip():
            raise ValueError("The uploaded file is empty.")

        clean_raw = raw.strip()
        if filename.lower().endswith(".json") or clean_raw.startswith(("[", "{")):
            try:
                data = json.loads(clean_raw)
            except Exception as exc:
                raise ValueError(f"Invalid JSON format: {exc}")
            if isinstance(data, dict):
                data = data.get("apps", [data])
            if not isinstance(data, list):
                raise ValueError("JSON structure must be an array of app objects or an object with an 'apps' list.")
            df = pd.DataFrame(data)
        else:
            df = pd.read_csv(StringIO(clean_raw))

    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Could not parse the uploaded file: {exc}")

    if df.empty:
        raise ValueError("The uploaded file contains no app records.")

    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"Missing required columns: {', '.join(missing)}. "
            f"Required columns are: {', '.join(REQUIRED_COLUMNS)}."
        )

    df = df[REQUIRED_COLUMNS].copy()

    # Convert features and validate
    for col in FEATURES:
        df[col] = df[col].apply(_convert_boolean_or_numeric)

    if df[FEATURES].isna().any().any():
        raise ValueError("Permission and data-usage columns must contain numeric values or valid booleans (0/1, true/false).")

    # Sanity checks: background data cannot be negative
    if (df["background_data_usage_mb"] < 0).any():
        raise ValueError("Background data usage cannot be negative.")

    return df.reset_index(drop=True)


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
def _explain(row: pd.Series) -> str:
    reasons = []
    if row.get("has_sms_permission"):
        reasons.append("reads/sends SMS")
    if row.get("overlay_permission"):
        reasons.append("can draw over other apps (screen overlay)")
    if row.get("has_contacts_permission") and row.get("has_camera_permission") and row.get("has_sms_permission"):
        reasons.append("SMS + contacts + camera combined access")
    if row.get("background_data_usage_mb", 0) > 150:
        reasons.append(f"heavy background data consumption ({row['background_data_usage_mb']:.0f} MB)")
    return "; ".join(reasons) if reasons else "unusual combination of permission behaviours"


def analyze_apps(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Score apps using Isolation Forest outlier detection.
    Returns:
        results: pd.DataFrame with columns app_name, features, anomaly_label, anomaly_score, risk_level, reason
        summary: dict of metrics and overall verdict
    """
    if df.empty:
        raise ValueError("No app records to analyze.")

    model = get_model()
    X = df[FEATURES]
    labels = model.predict(X)
    scores = model.decision_function(X)  # lower score = more anomalous

    out = df.copy()
    out["anomaly_label"] = labels
    out["anomaly_score"] = np.round(scores, 4)
    out["risk_level"] = np.where(
        labels == -1, "High Risk", np.where(scores < _threshold_warn, "Warning", "Safe")
    )
    out["reason"] = [
        _explain(r) if lvl != "Safe" else "" for (_, r), lvl in zip(out.iterrows(), out["risk_level"])
    ]
    out = out.sort_values("anomaly_score").reset_index(drop=True)

    high = int((out["risk_level"] == "High Risk").sum())
    warn = int((out["risk_level"] == "Warning").sum())
    safe_cnt = len(out) - high - warn

    summary = {
        "total_apps": len(out),
        "high_risk": high,
        "warning": warn,
        "safe": safe_cnt,
        "verdict": "High Risk" if high > 0 else ("Warning" if warn > 0 else "Safe"),
        "assessment_type": "Statistical Anomaly Detection (Not Confirmed Malware)",
        "disclaimer": "Isolation Forest flags statistical outliers in permission profiles and data volume. High risk indicates abnormal privilege behavior, not confirmed malicious software.",
    }
    return {"results": out, "summary": summary}
