import pandas as pd

from app.ml.bootstrap_dataset import generate
from app.ml import infer as infer_module


def test_bootstrap_dataset_has_expected_columns():
    df = generate(n=200, seed=1)
    expected = {
        "protocol", "tls_version", "cipher_suite", "key_exchange", "forward_secrecy",
        "certificate_age_days", "certificate_remaining_days", "certificate_validity_days",
        "certificate_key_type", "certificate_key_size", "signature_algorithm",
        "chain_depth", "san_count", "expired", "not_yet_valid", "self_signed", "chain_issue",
        "starttls_offered", "starttls_requested", "starttls_accepted", "tls_handshake_complete",
        "packet_count", "session_duration_s", "retransmission_ratio", "stream_complete", "label",
    }
    assert expected.issubset(set(df.columns))


def test_bootstrap_dataset_label_is_binary():
    df = generate(n=200, seed=1)
    assert set(df["label"].unique()).issubset({0, 1})


def test_bootstrap_dataset_is_reproducible_with_seed():
    df1 = generate(n=100, seed=7)
    df2 = generate(n=100, seed=7)
    pd.testing.assert_frame_equal(df1, df2)


def test_bootstrap_dataset_has_both_classes_at_reasonable_scale():
    # with 4000 rows the risk function + 15% noise should produce a
    # reasonably balanced (not degenerate) label distribution
    df = generate(n=4000, seed=42)
    positive_rate = df["label"].mean()
    assert 0.15 < positive_rate < 0.60


def test_normalize_anomaly_score_maps_p01_to_high_anomaly():
    infer_module._anomaly_bounds = {"p01": -0.5, "p99": -0.36}
    score = infer_module._normalize_anomaly_score(-0.5)
    assert score == 1.0


def test_normalize_anomaly_score_maps_p99_to_low_anomaly():
    infer_module._anomaly_bounds = {"p01": -0.5, "p99": -0.36}
    score = infer_module._normalize_anomaly_score(-0.36)
    assert score == 0.0


def test_normalize_anomaly_score_clips_outside_training_range():
    infer_module._anomaly_bounds = {"p01": -0.5, "p99": -0.36}
    # a raw score more extreme than anything seen in training still clips to [0, 1]
    assert infer_module._normalize_anomaly_score(-0.9) == 1.0
    assert infer_module._normalize_anomaly_score(0.0) == 0.0


def test_normalize_anomaly_score_without_bounds_returns_neutral():
    infer_module._anomaly_bounds = None
    assert infer_module._normalize_anomaly_score(-0.4) == 0.5
