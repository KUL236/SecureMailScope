import logging

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session

from app.database import get_db, Base, engine
from app import models
from app.routers import (
    auth_router, investigations_router, sessions_router, misc_router,
    reports_router, assistant_router, intel_router, tools_router,
)
from app.demo_data import load_demo_investigation
from app.auth import get_current_user

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="SecureMailScope API", version="1.0.0")

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(investigations_router.router)
app.include_router(sessions_router.router)
app.include_router(misc_router.router)
app.include_router(reports_router.router)
app.include_router(assistant_router.router)
app.include_router(intel_router.router)
app.include_router(tools_router.router)


@app.on_event("startup")
def on_startup():
    # For production use Alembic migrations instead of create_all (see ARCHITECTURE.md).
    Base.metadata.create_all(bind=engine)


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/demo/load")
def load_demo(db: Session = Depends(get_db)):
    """LOAD DEMO INVESTIGATION button target (section 49). No auth required for the demo."""
    inv = load_demo_investigation(db)
    return {"investigation_id": inv.id, "title": inv.title, "is_demo": True}


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    logging.exception("Unhandled error")
    return JSONResponse(status_code=500, content={"error": "Internal error", "detail": str(exc)})
