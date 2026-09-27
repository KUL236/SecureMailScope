import re

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app import models
from app.auth import verify_password, create_access_token, get_current_user, hash_password
from app.config import COOKIE_SECURE

router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class UpdateProfileRequest(BaseModel):
    full_name: str | None = None
    email: str | None = None


def _user_out(user: models.User):
    return {
        "id": user.id, "username": user.username, "email": user.email,
        "full_name": user.full_name, "roles": [r.name for r in user.roles],
    }


@router.post("/register")
def register(body: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    """Self-service account creation so a fresh install/demo has a way to get
    a first analyst account without shell access to the DB. In a real
    production deployment this would normally be admin-invite-only --
    left open here so judges/evaluators can create an account immediately."""
    if db.query(models.User).filter(models.User.username == body.username).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username already taken")
    if db.query(models.User).filter(models.User.email == body.email).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")
    if len(body.password) < 8:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must be at least 8 characters")

    analyst_role = db.query(models.Role).filter_by(name="analyst").first()
    if not analyst_role:
        analyst_role = models.Role(name="analyst")
        db.add(analyst_role)
        db.flush()

    user = models.User(username=body.username, email=body.email, password_hash=hash_password(body.password))
    user.roles.append(analyst_role)
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(user.id)
    response.set_cookie(
        "session_token", token, httponly=True, secure=COOKIE_SECURE, samesite="strict",
        max_age=8 * 3600,
    )
    return _user_out(user)


@router.post("/login")
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = create_access_token(user.id)
    response.set_cookie(
        "session_token", token, httponly=True, secure=COOKIE_SECURE, samesite="strict",
        max_age=8 * 3600,
    )
    return _user_out(user)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("session_token")
    return {"ok": True}


@router.get("/me")
def me(user: models.User = Depends(get_current_user)):
    return _user_out(user)


@router.put("/me")
def update_profile(
    body: UpdateProfileRequest,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Backs the Settings page's "Save profile" button. Only full_name and
    email are editable here; username/password/roles have their own flows."""
    if body.email is not None:
        email = body.email.strip()
        if email == "":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email cannot be blank")
        if not EMAIL_RE.match(email):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Not a valid email address")
        existing = db.query(models.User).filter(models.User.email == email, models.User.id != user.id).first()
        if existing:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already in use by another account")
        user.email = email

    if body.full_name is not None:
        full_name = body.full_name.strip()
        user.full_name = full_name or None

    db.add(user)
    db.commit()
    db.refresh(user)
    return _user_out(user)
