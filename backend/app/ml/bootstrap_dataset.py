"""
Synthetic training data bootstrap (referenced in ML_PIPELINE.md).

Real labelled email-session traffic is scarce and slow to collect. This
generates a plausible synthetic dataset of session feature rows --
independent of, and not a tautological copy of, app/rules.py -- so the
classifier learns generalizable patterns (e.g. "old + weak key + no FS
correlates with risk") rather than memorizing rule engine literals.

The label comes from a hand-authored risk function with realistic noise
(15% label flips) so the model isn't trained on a perfectly separable
toy problem. This is a BOOTSTRAP, not a substitute for real traffic --
see ML_PIPELINE.md's "Real deployment" note for the migration path.

Usage:
    python -m app.ml.bootstrap_dataset --n 4000 --out app/ml/artifacts/bootstrap_features.csv
"""
import argparse
import numpy as np
import pandas as pd

RNG_SEED = 42

TLS_VERSIONS = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"]
TLS_VERSION_WEIGHTS = [0.55, 0.33, 0.07, 0.05]
KEY_TYPES = ["RSA", "EC (secp256r1)"]
SIG_ALGOS = ["sha256WithRSAEncryption", "sha384WithRSAEncryption", "ecdsa-with-SHA256", "sha1WithRSAEncryption"]
SIG_ALGO_WEIGHTS = [0.55, 0.15, 0.22, 0.08]
KEY_EXCHANGES = ["ECDHE", "DHE", "RSA", "ECDHE/DHE (key_share)"]
PROTOCOLS = ["SMTP", "IMAP", "POP3"]


def _sample_session(rng: np.random.Generator) -> dict:
    tls_version = rng.choice(TLS_VERSIONS, p=TLS_VERSION_WEIGHTS)
    is_tls13 = tls_version == "TLS 1.3"

    key_type = rng.choice(KEY_TYPES, p=[0.8, 0.2])
    key_size = int(rng.choice([1024, 2048, 3072, 4096])) if key_type == "RSA" else 256
    # weight toward modern key sizes
    if key_type == "RSA":
        key_size = int(rng.choice([1024, 2048, 3072, 4096], p=[0.08, 0.62, 0.2, 0.1]))

    sig_algo = rng.choice(SIG_ALGOS, p=SIG_ALGO_WEIGHTS)

    key_exchange = "ECDHE/DHE (key_share)" if is_tls13 else rng.choice(["ECDHE", "DHE", "RSA"], p=[0.55, 0.15, 0.3])
    forward_secrecy = key_exchange != "RSA"

    cert_validity_days = int(rng.choice([90, 365, 730, 1095], p=[0.15, 0.55, 0.2, 0.1]))
    cert_age_days = int(rng.uniform(0, cert_validity_days * 1.15))  # can exceed validity => expired
    cert_remaining_days = cert_validity_days - cert_age_days
    expired = cert_remaining_days < 0
    not_yet_valid = False  # rare edge case, omitted from the synthetic generator for simplicity
    self_signed = bool(rng.random() < 0.12)
    chain_issue = bool(rng.random() < 0.08) if not self_signed else False

    san_count = int(rng.choice([1, 2, 3, 5, 8], p=[0.35, 0.25, 0.2, 0.15, 0.05]))
    chain_depth = int(rng.choice([1, 2, 3], p=[0.15, 0.65, 0.2]))

    protocol = rng.choice(PROTOCOLS, p=[0.7, 0.2, 0.1])
    starttls_offered = bool(rng.random() < 0.9)
    starttls_requested = starttls_offered and bool(rng.random() < 0.95)
    starttls_accepted = starttls_requested and bool(rng.random() < 0.93)
    tls_handshake_complete = starttls_accepted and bool(rng.random() < 0.96)

    packet_count = int(rng.integers(20, 600))
    session_duration_s = float(rng.uniform(0.2, 45))
    retransmission_ratio = float(np.clip(rng.normal(0.02, 0.03), 0, 1))
    stream_complete = bool(rng.random() < 0.93)

    row = {
        "protocol": protocol,
        "tls_version": tls_version if starttls_accepted else None,
        "cipher_suite": f"0x{rng.integers(0x1301, 0x1306):04X}" if is_tls13 else f"0xC0{rng.integers(9,31):02X}",
        "key_exchange": key_exchange if starttls_accepted else None,
        "forward_secrecy": forward_secrecy if starttls_accepted else None,
        "certificate_age_days": cert_age_days if starttls_accepted else None,
        "certificate_remaining_days": cert_remaining_days if starttls_accepted else None,
        "certificate_validity_days": cert_validity_days if starttls_accepted else None,
        "certificate_key_type": key_type if starttls_accepted else None,
        "certificate_key_size": key_size if starttls_accepted else None,
        "signature_algorithm": sig_algo if starttls_accepted else None,
        "chain_depth": chain_depth if starttls_accepted else 0,
        "san_count": san_count if starttls_accepted else None,
        "expired": expired if starttls_accepted else None,
        "not_yet_valid": not_yet_valid if starttls_accepted else None,
        "self_signed": self_signed if starttls_accepted else None,
        "chain_issue": chain_issue if starttls_accepted else None,
        "starttls_offered": starttls_offered,
        "starttls_requested": starttls_requested,
        "starttls_accepted": starttls_accepted,
        "tls_handshake_complete": tls_handshake_complete,
        "packet_count": packet_count,
        "session_duration_s": session_duration_s,
        "retransmission_ratio": retransmission_ratio,
        "stream_complete": stream_complete,
    }

    # --- Ground-truth risk function (independent of app/rules.py) ---
    risk = 0.0
    if expired:
        risk += 0.45
    if self_signed:
        risk += 0.20
    if chain_issue:
        risk += 0.25
    if key_type == "RSA" and key_size < 2048:
        risk += 0.35
    if "sha1" in sig_algo.lower():
        risk += 0.25
    if tls_version in ("TLS 1.0", "TLS 1.1"):
        risk += 0.30
    if starttls_accepted and not forward_secrecy:
        risk += 0.15
    if starttls_offered and not starttls_accepted:
        risk += 0.40
    if not starttls_offered:
        risk += 0.20
    if not stream_complete:
        risk += 0.08
    if not tls_handshake_complete and starttls_accepted:
        risk += 0.10
    if retransmission_ratio > 0.15:
        risk += 0.05

    risk = float(np.clip(risk, 0, 1))
    label = int(rng.random() < risk)
    # 15% label noise -- real analysts disagree at the margins; keeps the
    # problem from being perfectly separable (which would make the
    # benchmark numbers meaningless).
    if rng.random() < 0.15:
        label = 1 - label

    row["label"] = label
    return row


def generate(n: int, seed: int = RNG_SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = [_sample_session(rng) for _ in range(n)]
    return pd.DataFrame(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=RNG_SEED)
    parser.add_argument("--out", default="app/ml/artifacts/bootstrap_features.csv")
    args = parser.parse_args()

    df = generate(args.n, args.seed)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} rows ({df['label'].mean():.1%} positive) to {args.out}")


if __name__ == "__main__":
    main()
