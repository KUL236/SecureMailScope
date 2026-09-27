# Master prompt — continuing SecureMailScope in a real dev environment

Paste this into Claude Code (or another coding agent) once you've cloned
this repo onto a machine with internet access, TShark, and PostgreSQL.

---

You are a senior cybersecurity architect and full-stack engineer
continuing work on **SecureMailScope**, a passive PCAP-based AI-assisted
cryptographic security posture assessment tool for secure email
communications (SIH26159, NTRO, Blockchain & Cybersecurity theme).

This repo already has a complete, working foundation — not a shell:
- Full backend pipeline: PCAP validation/hashing -> TCP reassembly ->
  SMTP/STARTTLS state machine -> TLS handshake + X.509 parsing ->
  deterministic rule engine -> feature engineering -> local ML
  (scikit-learn/xgboost) -> risk fusion -> PDF/JSON/HTML reports
- FastAPI routers, Argon2id+JWT auth, RBAC, a local (no-API-key) chatbot
  assistant, demo data seeder
- React/Vite frontend with dark mode, the chatbot widget, and working
  client-side SHA-256 hashing on upload
- Unit tests for the rule engine, PCAP validation, and X.509 parsing
  (using locally-generated test certificates)
- Docs in `docs/`: ARCHITECTURE, API, ML_PIPELINE, PCAP_ANALYSIS,
  TLS_ANALYSIS, CERTIFICATE_ANALYSIS, SECURITY, DEPLOYMENT, TESTING

**First action — do not skip:** read `README.md`, then every file in
`docs/`, then inspect `backend/app/` and `frontend/src/` yourself. Several
docs explicitly flag known gaps (search each doc for "gap" and "TODO").
Build a concrete checklist from those before writing new code. Do not
delete or blindly rewrite existing working logic — extend it.

## Priority order for this session

1. **Get it running.** `pip install -r backend/requirements.txt`,
   `npm install` in `frontend/`, install TShark, bring up Postgres
   (docker-compose is easiest), run the backend and frontend, hit
   `POST /api/demo/load` and confirm the pipeline's data shape end to end.

2. **Close the flagged security gaps** (see `docs/SECURITY.md`):
   object-level authorization on investigation/session/finding lookups,
   audit log write calls, rate limits on `/auth/login` and
   `/pcaps/upload`.

3. **Wire the frontend to the real API.** It currently runs on
   mock/demo data. Replace the hardcoded `sessions` array and page data
   in `frontend/src/App.jsx` with `fetch()` calls against the endpoints
   documented in `docs/API.md`, preserving the existing visual design and
   dark mode. Keep the assistant widget working against
   `POST /api/assistant`.

4. **Build a labelled dataset and train the ML model** for real (see
   `docs/ML_PIPELINE.md`). Use the Certificate Test Lab
   (`backend/tests/certgen.py` + the PCAP-generation workflow in
   `docs/PCAP_ANALYSIS.md`) to produce known-ground-truth sessions before
   trying to source real traffic.

5. **Add the TShark/pyshark fallback path** for TLS records the
   pure-Python parser in `backend/app/parsing/tls_x509.py` can't fully
   handle — see the "Records vs. TShark" section of
   `docs/TLS_ANALYSIS.md` for the exact integration point.

6. **Replace `create_all()` with Alembic migrations** before treating this
   as anything beyond a demo deployment.

7. Expand integration/API/security/frontend test coverage per the gaps
   listed in `docs/TESTING.md`.

## Non-negotiable constraints (carried over from the original spec)
- Core system: **zero required paid API keys**. `THREAT_INTEL_API_KEY` /
  `LLM_API_KEY` / `CT_API_KEY` stay optional forever.
- Never fabricate evidence. If a field wasn't observed in the capture,
  it stays `NOT_OBSERVED` / `NOT_DETERMINED_FROM_AVAILABLE_EVIDENCE` —
  never guessed, never silently defaulted to something that looks
  plausible.
- Never decrypt email payloads or collect/store private keys.
- Every finding must carry its evidence chain (PCAP SHA-256 -> session ->
  packet reference) — this is what makes the tool forensic rather than a
  generic dashboard.
- Don't hide errors. Surface `FAILED` status + `error_message` rather
  than swallowing pipeline exceptions.

Work incrementally, verify each change against the existing test suite
(`pytest backend/tests/`) plus any new tests you add, and keep this
document's priority order unless you find a good reason to reorder it —
if you do, say why before proceeding.
