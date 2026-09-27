"""
SecureMailScope configuration.

Core analysis NEVER requires an external API key. Anything under
OPTIONAL_* is enrichment only and the app must run fully without it.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


BASE_DIR = Path(__file__).resolve().parent.parent

# ---- Required-but-defaulted (safe for local/dev use) ----
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://smsuser:smspass@localhost:5432/securemailscope")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-only-change-me-too")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))

# ---- Deployment mode + session cookie flags ----
# "development" (default) covers `docker-compose up` / vite dev / any plain-HTTP
# setup -- including the LAN IP a phone hits during mobile testing. "production"
# covers a real deployment that terminates HTTPS in front of the app.
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()


def resolve_cookie_secure(environment: str, override: str = None) -> bool:
    """Whether the session cookie should carry the `Secure` flag.

    Pure/testable on purpose: browsers -- Safari in particular, with no
    "localhost is secure" exception the way Chrome has -- refuse to *set*
    a Secure cookie on a plain-HTTP connection, so `Secure=True` while the
    app is only ever served over HTTP silently breaks login there (the
    request looks fine; the cookie just never gets stored). An explicit
    COOKIE_SECURE env var always wins; otherwise it follows ENVIRONMENT.
    """
    if override is not None and override != "":
        return override.strip().lower() == "true"
    return environment.strip().lower() == "production"


COOKIE_SECURE = resolve_cookie_secure(ENVIRONMENT, os.getenv("COOKIE_SECURE"))

# ---- Optional infra ----
REDIS_URL = os.getenv("REDIS_URL", "")  # empty => background jobs run inline via asyncio, not celery

# ---- OPTIONAL enrichment only. Core pipeline works with these unset. ----
THREAT_INTEL_API_KEY = os.getenv("THREAT_INTEL_API_KEY", "")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
CT_API_KEY = os.getenv("CT_API_KEY", "")

# ---- Certificate chain / revocation validation ----
# Chain signature verification (app/parsing/chain_validation.py) is always
# on and purely local: it verifies signatures against certs observed in
# the capture plus a local root CA bundle (certifi) on disk. No network
# calls are made for this.
#
# Revocation checking (app/parsing/revocation.py) is a genuine live
# network call to an OCSP responder / CRL distribution point named in
# the certificate. That's a deliberate departure from "passive capture
# only", so it stays OFF by default -- an operator must explicitly opt
# in. When off, revocation_status stays NOT_DETERMINED_FROM_PCAP, exactly
# as before.
ENABLE_LIVE_REVOCATION_CHECKS = os.getenv("ENABLE_LIVE_REVOCATION_CHECKS", "false").strip().lower() == "true"
REVOCATION_CHECK_TIMEOUT_SECONDS = float(os.getenv("REVOCATION_CHECK_TIMEOUT_SECONDS", "5"))

# ---- Storage ----
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(BASE_DIR / "data" / "pcaps")))
REPORT_DIR = Path(os.getenv("REPORT_DIR", str(BASE_DIR / "data" / "reports")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_PCAP_SIZE_BYTES = int(os.getenv("MAX_PCAP_SIZE_BYTES", str(500 * 1024 * 1024)))  # 500MB
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng"}

# ---- Versioning: every finding/report is stamped with these ----
PARSER_VERSION = "1.0.0"
FEATURE_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
MODEL_VERSION = "1.0.0"
POLICY_VERSION = "1.0.0"
