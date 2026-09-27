# ML Pipeline

## No API key, fully local
Training (`app/ml/train.py`) and inference (`app/ml/infer.py`) run on
`scikit-learn` locally (`xgboost` is used automatically if installed, but
isn't required). No network call, no API key.

## Shipped model: trained on a synthetic bootstrap dataset
This repo ships **real, already-trained model artifacts** in
`app/ml/artifacts/` (`risk_classifier.joblib`, `anomaly_detector.joblib`,
`anomaly_score_bounds.json`, `benchmark_results.json`) — not placeholders.
They were trained on `app/ml/bootstrap_dataset.py`'s synthetic data because
real labelled email-session traffic doesn't exist yet for this project.

**Be clear about what this is and isn't.** The bootstrap generator
samples session feature rows from hand-authored realistic distributions
(TLS version mix, cert validity windows, key exchange choices, etc.) and
labels them with an independent hand-authored risk function plus 15%
random label noise — deliberately *not* a copy of `app/rules.py`'s logic,
so the model learns generalizable correlations rather than memorizing
rule literals. This is a bootstrap to get a working, non-trivial model
shipping on day one, not a substitute for training on real traffic. Treat
its risk scores as directionally reasonable, not production-grade, until
retrained on real sessions (see "Migrating to real traffic" below).

Actual benchmark from the shipped model (4,000 synthetic sessions, 20%
held out, see `benchmark_results.json`):

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| **Logistic Regression (selected)** | 0.51 | 0.69 | **0.59** | 0.70 |
| Random Forest | 0.51 | 0.31 | 0.38 | 0.64 |

Logistic Regression won on F1 and was saved as the active classifier.
These numbers are modest by design — the 15% label noise caps the
achievable ceiling intentionally, so the benchmark reflects a realistic
noisy-label problem instead of a suspiciously perfect toy dataset.

Regenerate/retrain any time:
```bash
python -m app.ml.bootstrap_dataset --n 4000 --out app/ml/artifacts/bootstrap_features.csv
python -m app.ml.train --data app/ml/artifacts/bootstrap_features.csv --target label --out-dir app/ml/artifacts
```

## Training on real data
```bash
python -m app.ml.train --data path/to/features.csv --target label --out-dir app/ml/artifacts
```
Input CSV: one row per session, columns matching `app/features.py`'s
output keys plus a binary `label` column (1 = risky/anomalous ground
truth, 0 = benign) and ideally a `session_id` column excluded from
features but usable for grouped splitting.

The script benchmarks Logistic Regression, Random Forest, and XGBoost (if
installed), reports precision/recall/F1/ROC-AUC/PR-AUC/confusion matrix for
each, and saves both the winning classifier and the full comparison
(`benchmark_results.json`) so the choice is auditable — never assumed.

## Migrating to real traffic
1. Use the Certificate Test Lab (`tests/certgen.py` + the PCAP-generation
   workflow in `PCAP_ANALYSIS.md`) to capture real, known-ground-truth
   PCAPs (valid/expired/self-signed/no-FS/etc.)
2. Run them through `POST /api/pcaps/upload`, then pull the resulting
   `FeatureSet` rows out of the database (`SELECT values FROM features`)
   as your real training CSV, labelled by an analyst
3. Blend real rows into (or replace) `bootstrap_features.csv` and retrain
4. As real volume grows, phase out the synthetic rows entirely — the
   bootstrap dataset's job is to be replaced, not to be the permanent
   training set

## Inference
`app/ml/infer.py::score_session(feature_dict)` loads both artifacts once
(module-level cache) and returns `{probability, anomaly_score,
top_contributors, model_version, scored}`. If no trained model artifact
exists (`scored: False`), the risk fusion layer (`app/risk.py`) falls back
to rule-score-only rather than fabricating a probability.

## Anomaly score: normalized against the model's own training distribution
`IsolationForest.score_samples()` has no fixed scale — its range depends
entirely on the training data. **An earlier version of this code
hardcoded a normalization pivot (`0.5 - raw`) that was wrong for this
dataset's actual score range (roughly -0.54 to -0.36), causing nearly
every session to be reported as highly anomalous regardless of how
typical it actually was.** This is now fixed: `train.py` computes the
training set's 1st/99th percentile raw scores and saves them as
`anomaly_score_bounds.json`; `infer.py` normalizes new scores against
those actual bounds. Verified end-to-end: a deliberately risky synthetic
session (expired, self-signed, TLS 1.0, weak key) now scores
`anomaly≈1.0`, a clean modern session scores `anomaly≈0.05`, and a
middling one (valid cert, but no forward secrecy) lands at `≈0.47`.

## Explainability
`top_contributors` supports both tree-based models (`feature_importances_`)
and linear models (`abs(coef_)`, e.g. Logistic Regression — the model this
repo actually ships). **An earlier version only checked
`feature_importances_`, so it silently returned an empty list whenever a
linear model won the benchmark** (which is exactly what happened here).
Fixed and verified — the shipped model now returns real top contributors,
e.g. `expired`, `chain_issue`, `starttls_offered` for a deliberately risky
test session.

Not SHAP by default, to avoid a heavy dependency and the risk of
silently-wrong SHAP values on a misconfigured explainer. To upgrade:
1. `pip install shap`
2. In `app/ml/infer.py`, replace `_top_contributors` with a
   `shap.LinearExplainer`/`shap.TreeExplainer` call matching whichever
   model type won the benchmark
3. Keep the same "only return real computed values, never a
   fabricated placeholder" contract

## Avoiding leakage
`train.py` does a stratified split on `label`. If your dataset has
near-duplicate sessions (e.g. many captures of the same test server),
pass `--group-col` and switch to `GroupShuffleSplit` so near-duplicates
never appear in both train and test.

## "Anomalous ≠ Malicious"
The API (`GET /api/ai/{session_id}`) and the frontend assistant both
surface this framing explicitly. An anomaly score is a prompt for
analyst review, not a verdict — do not silently escalate purely on
anomaly score without a corroborating rule finding.
