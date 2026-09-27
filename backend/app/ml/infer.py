"""
ML inference at request time. Loads the artifacts produced by train.py.
If no trained model exists yet (fresh install, before any training run),
falls back to a documented "not scored" state rather than fabricating a
probability -- this keeps section 51's "never fabricate evidence" rule
intact for the AI layer too.
"""
import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

from app.config import BASE_DIR, MODEL_VERSION

ARTIFACT_DIR = Path(BASE_DIR) / "app" / "ml" / "artifacts"

_classifier = None
_anomaly = None
_anomaly_bounds = None
_loaded = False


def _load():
    global _classifier, _anomaly, _anomaly_bounds, _loaded
    if _loaded:
        return
    clf_path = ARTIFACT_DIR / "risk_classifier.joblib"
    iso_path = ARTIFACT_DIR / "anomaly_detector.joblib"
    bounds_path = ARTIFACT_DIR / "anomaly_score_bounds.json"
    if clf_path.exists():
        _classifier = joblib.load(clf_path)
    if iso_path.exists():
        _anomaly = joblib.load(iso_path)
    if bounds_path.exists():
        _anomaly_bounds = json.loads(bounds_path.read_text())
    _loaded = True


def score_session(feature_dict: dict) -> dict:
    """
    Returns {probability, anomaly_score, top_contributors, model_version, scored}.
    scored=False means no trained model is available yet; caller must not
    treat probability/anomaly_score as meaningful in that case.
    """
    _load()
    row = pd.DataFrame([feature_dict])
    # Object-dtype columns can hold a mix of None/np.nan/bool/str; force a
    # single canonical missing-value representation so the fitted
    # SimpleImputer steps inside `prep` reliably recognize every gap. Without
    # this, a session with little/no TLS or certificate evidence (a short or
    # non-TLS capture) can leave a raw None that slips past imputation and
    # crashes the classifier -- exactly the "sparse capture" case a real
    # PCAP will frequently produce, so this must not throw.
    row = row.where(pd.notnull(row), np.nan)

    if _classifier is None:
        return {
            "probability": None, "anomaly_score": None, "top_contributors": [],
            "model_version": MODEL_VERSION, "scored": False,
            "note": "No trained model artifact found. Run app.ml.bootstrap_dataset then app.ml.train first.",
        }

    try:
        proba = float(_classifier.predict_proba(row)[:, 1][0])
        anomaly_score = None
        if _anomaly is not None:
            raw = _anomaly.named_steps["iso"].score_samples(
                _anomaly.named_steps["prep"].transform(row)
            )[0]
            anomaly_score = _normalize_anomaly_score(raw)
        top_contributors = _top_contributors(row)
    except Exception as e:
        # A single session's feature vector must never be able to fail the
        # whole investigation (rule-based findings for this and every other
        # session are still valid and must be kept). Degrade honestly to
        # "not scored" instead -- never fabricate a probability.
        logger.warning("ML scoring failed for this session, marking unscored: %s", e)
        return {
            "probability": None, "anomaly_score": None, "top_contributors": [],
            "model_version": MODEL_VERSION, "scored": False,
            "note": f"ML scoring failed for this session ({type(e).__name__}); "
                    f"risk falls back to rule-based findings only.",
        }

    return {
        "probability": proba, "anomaly_score": anomaly_score,
        "top_contributors": top_contributors, "model_version": MODEL_VERSION, "scored": True,
    }


def _normalize_anomaly_score(raw: float) -> float:
    """
    IsolationForest.score_samples() has no fixed scale -- it depends on the
    training data's own distribution. We normalize against THIS model's
    training-set score range (saved by train.py as p01/p99), not a guessed
    constant. Lower raw score = more anomalous, so p01 (most anomalous end
    of training) maps to 1.0 and p99 (least anomalous end) maps to 0.0.
    Falls back to a neutral 0.5 if bounds weren't saved (older artifact).
    """
    if not _anomaly_bounds:
        return 0.5
    p01, p99 = _anomaly_bounds["p01"], _anomaly_bounds["p99"]
    if p99 == p01:
        return 0.5
    normalized = (p99 - raw) / (p99 - p01)
    return round(max(0.0, min(1.0, normalized)), 4)


def _top_contributors(row: pd.DataFrame, k: int = 5):
    """
    Feature-importance based contributors -- supports both tree models
    (feature_importances_) and linear models (coef_, e.g. Logistic
    Regression, which is what the bootstrap benchmark actually selects).
    Not SHAP by default -- see ML_PIPELINE.md for the upgrade path. Only
    returns real computed values, never a fabricated placeholder.
    """
    try:
        clf = _classifier.named_steps["clf"]
        prep = _classifier.named_steps["prep"]
        names = prep.get_feature_names_out()

        if hasattr(clf, "feature_importances_"):
            importances = clf.feature_importances_
        elif hasattr(clf, "coef_"):
            # magnitude of the standardized coefficient = influence on the decision
            importances = abs(clf.coef_[0])
        else:
            return []

        pairs = sorted(zip(names, importances), key=lambda p: -p[1])[:k]
        return [{"feature": n, "contribution": float(v)} for n, v in pairs]
    except Exception:
        return []
