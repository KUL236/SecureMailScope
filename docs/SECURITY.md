# Security

## Auth
- Password hashing: Argon2id via `argon2-cffi` (`app/auth.py`)
- Sessions: JWT in an HttpOnly, Secure, SameSite=Strict cookie
  (`session_token`), 8-hour expiry by default (`JWT_EXPIRE_MINUTES`)
- CSRF: `SameSite=Strict` cookies provide baseline protection for this
  cookie-auth setup; if you add any cross-site form posts, add an
  explicit CSRF token too
- RBAC: `require_roles([...])` dependency factory in `app/auth.py`;
  currently used for `/audit-log` (admin-only) — apply it to any other
  route that should be role-restricted as the product grows

## Rate limiting
`slowapi` is wired into `app/main.py` (`Limiter`/`RateLimitExceeded`
handler). No per-route limits are set yet — add
`@limiter.limit("10/minute")` decorators to the login and upload routes
as a first pass; those are the most abuse-prone endpoints.

## Secrets
- Nothing is hardcoded. `SECRET_KEY`/`JWT_SECRET` come from environment
  variables with **insecure dev defaults** that must be overridden before
  any real deployment (`.env.example` calls this out explicitly)
- `.env` is git-ignored (see `.gitignore`); only `.env.example` is
  committed, with all values empty or clearly dev-only

## PCAPs are sensitive forensic evidence
- Uploaded files are stored under `UPLOAD_DIR` with a randomized filename
  (`{investigation_id}_{uuid8}{ext}`) — the original filename is preserved
  only as metadata, never trusted for path construction
- `FileResponse` is used for report downloads (not raw path exposure to
  the client)
- Object-level authorization: every session/finding/evidence lookup should
  be scoped by the requesting user's access to the parent investigation
  before returning data. **Current gap**: the routers as written check
  "is authenticated" but not yet "is this investigation visible to this
  user" — add an ownership/ACL check in each router before any multi-tenant
  deployment. This is flagged deliberately rather than silently assumed.

## Audit logging
`AuditLog` model exists with `user_id`, `action`, `target_type/id`,
`detail`, `ip_address`, `created_at`. **Current gap**: routers don't yet
write to it. Add an `AuditLog` insert in each state-changing endpoint
(login, upload, report generation) — the schema is ready, the call sites
aren't wired yet.

## What's never exposed
Database passwords, JWT/session secrets, and any configured optional API
keys are read only from environment variables server-side and never
returned in any API response or logged. Certificate private keys are
never collected, stored, or transmitted — the system only ever sees
public certificates presented in a TLS handshake.
