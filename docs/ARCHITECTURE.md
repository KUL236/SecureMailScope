# Architecture

## Pipeline
```
PCAP upload
  -> validate_pcap()              [app/parsing/pcap_loader.py]
  -> reassemble_streams()         [app/parsing/tcp_reassembly.py]     (scapy)
  -> analyze_smtp_starttls()      [app/parsing/smtp_starttls.py]
  -> parse_tls_records()          [app/parsing/tls_x509.py]           (pure-Python TLS record parser
                                                                        -> cryptography.x509)
  -> evaluate_rules()             [app/rules.py]
  -> build_feature_vector()       [app/features.py]
  -> score_session()              [app/ml/infer.py]                  (sklearn/xgboost, local)
  -> fuse_risk()                  [app/risk.py]
  -> persisted via SQLAlchemy     [app/models.py]
```
Orchestrated end-to-end in `app/pipeline.py::run_analysis`, invoked as a
FastAPI `BackgroundTask` so large PCAPs don't block the upload request
(see section 44 of the original spec / `DEPLOYMENT.md` for scaling this
to Celery + Redis if capture volume grows).

## Why a pure-Python TLS parser AND TShark
`app/parsing/tls_x509.py` implements a minimal but correct TLS 1.2/1.3
record/handshake parser so the core pipeline has **zero system
dependencies** beyond `cryptography`. This is intentional: it keeps
`pip install -r requirements.txt` sufficient to run the whole analysis
pipeline (just not the TCP reassembly, which needs `scapy`, which needs
libpcap).

TShark is still installed in the Docker image and checked by
`/api/system/dependencies`, because:
- It's a more battle-tested parser for edge cases (fragmented TLS records
  spread across many packets, unusual extension orderings)
- Section 44 of the spec expects it to be available in the analysis
  environment

Production teams should treat the pure-Python parser as the fast path and
add a TShark-based fallback (via `pyshark`) for captures it can't fully
parse — this is flagged as a TODO in `PCAP_ANALYSIS.md`.

## Versioning & reproducibility
Every finding, feature set, model run, and report is stamped with
`parser_version` / `feature_version` / `rule_version` / `model_version` /
`policy_version` (see `app/config.py`). Bump these whenever the
corresponding logic changes so historical findings stay interpretable.

## Database
SQLAlchemy ORM, schema in `app/models.py`. `Base.metadata.create_all()` is
used for local/hackathon bootstrapping; swap in Alembic migrations
(`alembic init`, then autogenerate from `app.models`) before any real
deployment so schema changes are tracked.

## Background jobs
Currently: FastAPI `BackgroundTasks` (in-process, no extra infra). If PCAP
volume grows beyond what fits comfortably in a request-response cycle,
swap to Celery + Redis (`REDIS_URL` is already wired in `config.py` as an
opt-in) — `app/pipeline.py::run_analysis` is already a pure function of
`(db, investigation_id)` so it drops into a Celery task with minimal
change.

## Frontend
React + Vite, no state management library (component-local `useState`
throughout — appropriate for this scope). Dark mode is implemented via a
CSS custom-property theme (`:root` vs `:root[data-theme="dark"]` in
`styles.css`), toggled by writing `data-theme` on `<html>` and persisted
to `localStorage`. The current build talks to demo/mock data; wiring it to
the live API is the main remaining frontend task (see `API.md` for the
contract each page needs).
