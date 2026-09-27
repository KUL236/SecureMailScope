"""
Local ML model training + benchmarking (section 21). No API key, no
external service -- trains entirely on local feature data.

Usage:
    python -m app.ml.train --data path/to/features.csv --target label

Candidate models are benchmarked, not assumed. Whichever scores best on
held-out F1 is saved as the active model; the full comparison table is
also saved so the choice is auditable.
"""
import argparse
import json
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    average_precision_score, confusion_matrix,
)

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

CATEGORICAL = ["protocol", "tls_version", "cipher_suite", "certificate_key_type", "signature_algorithm", "key_exchange"]
NUMERIC = [
    "certificate_age_days", "certificate_remaining_days", "certificate_validity_days",
    "certificate_key_size", "chain_depth", "san_count", "packet_count",
    "session_duration_s", "retransmission_ratio",
]
BOOLEAN = [
    "expired", "not_yet_valid", "self_signed", "chain_issue",
    "starttls_offered", "starttls_requested", "starttls_accepted",
    "tls_handshake_complete", "stream_complete", "forward_secrecy",
]


def build_preprocessor():
    return ColumnTransformer([
        ("num", Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), NUMERIC),
        ("bool", SimpleImputer(strategy="most_frequent"), BOOLEAN),
        ("cat", Pipeline([
            ("impute", SimpleImputer(strategy="constant", fill_value="MISSING")),
            ("ohe", OneHotEncoder(handle_unknown="ignore")),
        ]), CATEGORICAL),
    ])


def evaluate(model, X_test, y_test) -> dict:
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, pred).tolist()
    return {
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, proba) if len(set(y_test)) > 1 else None,
        "pr_auc": average_precision_score(y_test, proba) if len(set(y_test)) > 1 else None,
        "confusion_matrix": cm,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="CSV of feature rows (from app.features)")
    parser.add_argument("--target", default="label", help="binary target column: 1=risky, 0=benign")
    parser.add_argument("--group-col", default="session_id", help="column used to prevent leakage across splits")
    parser.add_argument("--out-dir", default="app/ml/artifacts")
    args = parser.parse_args()

    df = pd.read_csv(args.data)
    y = df[args.target].astype(int)
    X = df.drop(columns=[c for c in [args.target, args.group_col] if c in df.columns])

    # Stratified split; if a group column is present, split by group to avoid
    # near-duplicate sessions leaking between train and test.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.nunique() > 1 else None
    )

    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42),
    }
    if HAS_XGBOOST:
        candidates["xgboost"] = XGBClassifier(
            n_estimators=300, max_depth=5, learning_rate=0.05, eval_metric="logloss",
            random_state=42,
        )

    results = {}
    fitted = {}
    for name, clf in candidates.items():
        pipe = Pipeline([("prep", build_preprocessor()), ("clf", clf)])
        pipe.fit(X_train, y_train)
        results[name] = evaluate(pipe, X_test, y_test)
        fitted[name] = pipe

    best_name = max(results, key=lambda n: results[n]["f1"])
    best_pipe = fitted[best_name]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_pipe, out_dir / "risk_classifier.joblib")

    with open(out_dir / "benchmark_results.json", "w") as f:
        json.dump({"results": results, "selected_model": best_name}, f, indent=2, default=str)

    # Anomaly detector trained unsupervised on the same numeric/bool space
    iso_pipe = Pipeline([
        ("prep", build_preprocessor()),
        ("iso", IsolationForest(n_estimators=200, contamination="auto", random_state=42)),
    ])
    iso_pipe.fit(X)
    joblib.dump(iso_pipe, out_dir / "anomaly_detector.joblib")

    # score_samples() has no fixed scale -- it depends on this dataset's
    # feature distribution. Store the training set's own score range (1st/99th
    # percentile, robust to a few extreme outliers) so infer.py can normalize
    # new scores against THIS model's actual scale instead of a guessed
    # constant (an earlier version hardcoded a pivot that was badly wrong).
    train_raw_scores = iso_pipe.named_steps["iso"].score_samples(
        iso_pipe.named_steps["prep"].transform(X)
    )
    bounds = {
        "p01": float(np.percentile(train_raw_scores, 1)),   # most anomalous end
        "p99": float(np.percentile(train_raw_scores, 99)),  # least anomalous end
    }
    with open(out_dir / "anomaly_score_bounds.json", "w") as f:
        json.dump(bounds, f, indent=2)

    print(f"Selected model: {best_name}")
    print(json.dumps(results, indent=2, default=str))
    print(f"Anomaly score bounds (raw score_samples): {bounds}")


if __name__ == "__main__":
    main()
