from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.assistant import answer
from app.auth import get_current_user

router = APIRouter(prefix="/api", tags=["assistant"])


class AssistantRequest(BaseModel):
    message: str
    investigation_id: Optional[str] = None
    session_id: Optional[str] = None


@router.post("/assistant")
def ask_assistant(body: AssistantRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    """PCAP-aware forensic assistant. Every fact in the reply is read from
    this investigation's real DB rows (sessions/findings/TLS/certs) -- see
    app/assistant.py. Returns {answer, sources[]} where each source is a
    concrete {type, id} the frontend can link to (session, finding,
    investigation)."""
    return answer(db, body.message, body.investigation_id, body.session_id)
