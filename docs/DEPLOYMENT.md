# Deployment

## Docker Compose (recommended for demo/SIH judging)
```bash
docker-compose up --build
```
Services: `postgres`, `backend` (FastAPI + TShark baked into the image),
`frontend` (built + served static). Redis/worker are commented out in
`docker-compose.yml` — uncomment if you move background jobs to Celery
(see `ARCHITECTURE.md`).

## Manual / bare-metal
See `README.md`'s Installation section. In short: Python 3.11+ venv +
`pip install -r requirements.txt` for the backend, Node 20+ + `npm install`
for the frontend, PostgreSQL 16 reachable at `DATABASE_URL`.

## Before a real (non-hackathon) deployment
1. **Set real secrets.** `SECRET_KEY`/`JWT_SECRET` in `.env` must not be
   the dev defaults.
2. **Alembic migrations** instead of `create_all()` — track schema
   changes explicitly.
3. **Object-level authorization** — see the gap noted in `SECURITY.md`.
4. **Audit log wiring** — see the gap noted in `SECURITY.md`.
5. **Rate limits on login/upload** — `slowapi` is already a dependency,
   just needs `@limiter.limit(...)` decorators added.
6. **TLS termination** in front of the API (nginx/Caddy/cloud LB) — the
   app itself speaks plain HTTP; don't expose it directly to the internet.
7. **PCAP retention policy** — decide how long uploaded PCAPs (sensitive
   forensic evidence) live in `UPLOAD_DIR`, and automate deletion.

## Scaling background jobs
FastAPI `BackgroundTasks` (current implementation) run in-process and are
fine for a single-instance deployment with moderate PCAP volume. If you
need to scale horizontally or handle very large captures without risking
a lost job on process restart, move `app.pipeline.run_analysis` into a
Celery task backed by the `redis`/`worker` services already sketched (but
commented out) in `docker-compose.yml`.
