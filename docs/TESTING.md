# Testing

## Running tests
```bash
cd backend
pytest --cov=app tests/
```

## What's covered now
- `tests/test_pcap_loader.py` — valid pcap/pcapng magic bytes, empty
  file, corrupted file, wrong extension, SHA-256 determinism
- `tests/test_tls_x509.py` — valid/expired/not-yet-valid/self-signed/
  CA-chained certificates (generated locally via `tests/certgen.py`,
  never fetched from the internet), fingerprint format, hostname
  match/wildcard-match/mismatch/no-evidence
- `tests/test_rules.py` — one test per rule in the required fixture list:
  valid chain (no findings), expired cert, self-signed, broken chain,
  weak RSA key, legacy TLS version, STARTTLS rejected, STARTTLS not
  offered, hostname mismatch, incomplete TCP session, incomplete TLS
  handshake
- `tests/test_cipher_suites.py` — cipher suite name/key-exchange lookup,
  forward secrecy classification (ECDHE/DHE = forward secret, static
  RSA = not, TLS 1.3 = always forward secret, unknown codes conservatively
  treated as not forward secret), and the `NO_FORWARD_SECRECY` rule firing
  correctly
- `tests/test_ml.py` — bootstrap dataset shape/reproducibility/label
  balance, and the anomaly score normalization logic (including the
  p01/p99 clipping behavior)

All 41 tests have actually been executed in the environment this was
built in (not just syntax-checked) — this run caught two real bugs in
the ML inference code (a mis-scaled anomaly score, and an empty
`top_contributors` for non-tree models) that are documented and fixed in
`ML_PIPELINE.md`'s "Anomaly score" and "Explainability" sections.

## Required fixtures from the spec — status
| Fixture | Covered by |
|---|---|
| valid certificate | `test_tls_x509.py::test_ca_signed_certificate_is_not_self_signed` |
| expired certificate | `test_tls_x509.py::test_expired_certificate_detected`, `test_rules.py::test_expired_certificate` |
| self-signed certificate | `test_tls_x509.py::test_valid_certificate_parses_fields`, `test_rules.py::test_self_signed_certificate` |
| valid chain | `test_tls_x509.py::test_ca_signed_certificate_is_not_self_signed` |
| broken chain | `test_rules.py::test_broken_chain` |
| TLS 1.2 / TLS 1.3 | exercised via `make_tls()` fixtures in `test_rules.py`; add a raw-bytes TLS 1.2 fixture once you have a captured/synthetic PCAP (see `PCAP_ANALYSIS.md`'s cert-lab workflow) for an end-to-end `parse_tls_records` test |
| incomplete capture | `test_rules.py::test_incomplete_tcp_session_flagged` |
| certificate missing | covered implicitly — `tls_info.certificates == []` short-circuits every certificate rule in `evaluate_rules` |
| forward secrecy present/absent | `test_cipher_suites.py::test_forward_secrecy_present_no_finding`, `test_no_forward_secrecy_rule_fires` |

## Not yet written (flagged, not skipped silently)
- **Integration tests**: a full `POST /api/pcaps/upload` -> poll status ->
  `GET /api/findings` round trip against a real test PCAP (needs the
  cert-lab-generated PCAP described in `PCAP_ANALYSIS.md`)
- **API tests**: auth flow, RBAC enforcement, 404/400 error shapes
- **Security tests**: rate-limit enforcement once limits are added,
  object-level authorization once that gap (noted in `SECURITY.md`) is
  closed
- **Frontend tests**: none yet — the component structure in `App.jsx`
  is plain enough for React Testing Library if/when you add Vitest
- **ML pipeline tests**: `train.py`'s benchmarking logic isn't yet unit
  tested against a small synthetic dataset — worth adding once a labelled
  dataset exists (see `ML_PIPELINE.md`)

## CI suggestion
```yaml
# .github/workflows/test.yml (not included — add when you set up CI)
- run: pip install -r backend/requirements.txt
- run: pytest --cov=app backend/tests/
```
