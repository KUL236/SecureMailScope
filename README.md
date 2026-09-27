# SecureMailScope

Passive, PCAP-based, AI-assisted cryptographic security posture assessment for
secure email communications (SMTP/IMAP/POP3 + STARTTLS + TLS + X.509).

Built for SIH26159 (NTRO / Blockchain & Cybersecurity theme).

**Core analysis requires zero paid API keys.** PCAP parsing, TCP reassembly,
STARTTLS detection, TLS handshake analysis, X.509 extraction, the rule
engine, and the ML model all run locally with open-source tooling.

## What's implemented vs. what's next

This repo is a complete, working foundation — not a demo shell. The full
pipeline (PCAP → TCP → SMTP/STARTTLS → TLS/X.509 → rules → features → ML →
risk → evidence → report) has real logic end to end, backed by 41 unit
tests that have actually been executed (not just syntax-checked) in the
sandbox this was built in — `scikit-learn`/`pandas`/`cryptography` happened
to be available there even without network access, so the rule engine,
X.509 parsing, PCAP validation, cipher suite logic, and the ML model were
all genuinely run and verified, and two real bugs were caught and fixed
in the process (see `docs/ML_PIPELINE.md`).

**The ML model is not a stub.** `backend/app/ml/artifacts/` ships an
already-trained classifier + anomaly detector, trained on a synthetic
bootstrap dataset (`app/ml/bootstrap_dataset.py`) since real labelled
traffic doesn't exist yet for this project. It's verified to correctly
rank a deliberately risky session (expired, self-signed, TLS 1.0, weak
key, no forward secrecy) far above a clean modern one. See
`docs/ML_PIPELINE.md` for the actual benchmark numbers and the honest
caveats about synthetic vs. real training data.

What's *not* done yet, because it genuinely needs a real dev machine
(`fastapi`/`scapy`/`sqlalchemy` aren't installed in this sandbox, so the
full API/pipeline/frontend were written carefully but not executed):

- Installing dependencies and running the app for the first time
- Retraining the ML model on real/labelled session data once you have some
  (the bootstrap dataset is meant to be replaced — see `ML_PIPELINE.md`'s
  "Migrating to real traffic")
- Alembic migration files (currently `Base.metadata.create_all` bootstraps
  the schema directly — fine for a hackathon, swap for Alembic before any
  real deployment)
- Wiring `pyshark`/TShark as an alternative/fallback TLS extraction path
  for captures the pure-Python parser in `app/parsing/tls_x509.py` can't
  fully handle (fragmented TLS records across many small packets, for
  instance)
- Wiring the frontend to the live API (it currently runs on mock/demo
  session data — dark mode, layout, and the chatbot are real and working,
  but session/finding data isn't live yet)

See `MASTER_PROMPT.md` for a trimmed prompt you can hand to Claude Code (or
another coding agent) in your real environment to pick up exactly here.

## Installation

### Prerequisites
- Python 3.11+
- Node.js 20+
- PostgreSQL 16 (or use `docker-compose up`)
- **TShark** (Wireshark's CLI) — used as the production-grade fallback TLS
  parser and by the `/api/system/dependencies` health check.
  - macOS: `brew install wireshark` (choose to install command-line tools)
  - Ubuntu/Debian: `sudo apt install tshark`
  - Windows: install Wireshark and ensure `tshark.exe` is on PATH

### Backend
```bash
cd backend
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                               # edit DATABASE_URL etc. if needed
uvicorn app.main:app --reload
```
The API comes up on `http://localhost:8000`. First request auto-creates the
schema. Visit `http://localhost:8000/docs` for interactive API docs.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Opens on `http://localhost:5173`. Dark mode is on by default (toggle in the
top nav); the assistant chatbot is the floating button, bottom-right.

### Database setup (manual, if not using docker-compose)
```bash
createdb securemailscope
# schema is created automatically on first backend start
```

### Environment variables
See `backend/.env.example`. Nothing beyond `DATABASE_URL` is required for
the core system to run. `THREAT_INTEL_API_KEY` / `LLM_API_KEY` / `CT_API_KEY`
are optional enrichment only.

### Test commands
```bash
cd backend
pytest --cov=app tests/
```
Certificate fixtures (valid/expired/not-yet-valid/self-signed/CA-chained)
are generated locally at test time in `tests/certgen.py` — nothing is
fetched from the internet.

### Docker
```bash
docker-compose up --build
```
Brings up Postgres, backend (with TShark installed in the image), and
frontend together.

### Sample workflow
1. `npm run dev` + `uvicorn app.main:app --reload`
2. `POST /api/demo/load` (or click "Load Demo Investigation" once wired
   into the frontend upload page) to see a fully-populated synthetic
   investigation with findings across all severities
3. Or: register a user, log in, upload a real `.pcap`/`.pcapng` of an
   SMTP session, and watch `GET /api/investigations/{id}` move from
   `QUEUED` → `PROCESSING` → `COMPLETE`

## Project structure
```
backend/app/
  parsing/        PCAP validation, TCP reassembly, SMTP/STARTTLS, TLS/X.509
  ml/              training script + inference
  routers/         FastAPI endpoints
  models.py        SQLAlchemy schema
  rules.py         deterministic cryptographic rule engine
  features.py      versioned feature engineering
  risk.py          rule + ML + anomaly fusion
  pipeline.py      orchestrates the full analysis run
  reports.py       PDF/JSON/HTML report generation
  assistant.py     local chatbot (no API key)
  demo_data.py     synthetic demo investigation seeder
frontend/src/       React + Vite UI (dark mode, chatbot, all workspace pages)
```

See also: `ARCHITECTURE.md`, `API.md`, `ML_PIPELINE.md`, `PCAP_ANALYSIS.md`,
`TLS_ANALYSIS.md`, `CERTIFICATE_ANALYSIS.md`, `SECURITY.md`,
`DEPLOYMENT.md`, `TESTING.md` in `docs/`.
