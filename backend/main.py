"""
Password Manager API - Modern FastAPI Backend
Features: Argon2 hashing, JWT sessions, Fernet encryption, SQLAlchemy ORM, rate limiting
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
import time
import logging

from database import init_db, get_db
from models import User, VaultEntry
from schemas import (
    MasterPasswordSet, MasterPasswordVerify, TokenResponse,
    VaultEntryCreate, VaultEntryUpdate, VaultEntryResponse,
    PasswordGenerateRequest, PasswordGenerateResponse,
    HealthResponse, MessageResponse
)
from auth import (
    hash_master_password, verify_master_password,
    create_access_token, verify_token,
    encrypt_password, decrypt_password,
    generate_password
)
from config import settings

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger(__name__)


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    logger.info("✅  Database initialized")
    yield
    logger.info("🛑  Shutting down")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="🔐 Password Manager API",
    version="2.0.0",
    description="Secure, modern password vault with JWT authentication",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Simple in-memory rate limiter ─────────────────────────────────────────────
_rate_store: dict[str, list[float]] = {}

def rate_limit(request: Request, max_calls: int = 10, window: int = 60):
    ip = request.client.host
    now = time.time()
    calls = [t for t in _rate_store.get(ip, []) if now - t < window]
    if len(calls) >= max_calls:
        raise HTTPException(status_code=429, detail="Too many requests. Slow down.")
    calls.append(now)
    _rate_store[ip] = calls

# ── Auth dependency ────────────────────────────────────────────────────────────
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health", response_model=HealthResponse, tags=["System"])
async def health():
    return {"status": "ok", "version": "2.0.0", "timestamp": datetime.now(timezone.utc).isoformat()}


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/auth/setup", response_model=MessageResponse, tags=["Auth"])
async def setup_master_password(body: MasterPasswordSet, request: Request, db=Depends(get_db)):
    rate_limit(request, max_calls=5, window=60)
    existing = db.query(User).first()
    if existing:
        raise HTTPException(status_code=409, detail="Master password already set. Use /api/auth/change to update.")
    hashed = hash_master_password(body.password)
    user = User(password_hash=hashed)
    db.add(user)
    db.commit()
    logger.info("Master password configured")
    return {"message": "Master password set successfully"}


@app.post("/api/auth/login", response_model=TokenResponse, tags=["Auth"])
async def login(body: MasterPasswordVerify, request: Request, db=Depends(get_db)):
    rate_limit(request, max_calls=5, window=60)
    user = db.query(User).first()
    if not user:
        raise HTTPException(status_code=404, detail="No master password set. POST /api/auth/setup first.")
    if not verify_master_password(body.password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        user.last_attempt = datetime.now(timezone.utc)
        db.commit()
        logger.warning(f"Failed login attempt #{user.failed_attempts}")
        raise HTTPException(status_code=401, detail="Incorrect master password")
    user.failed_attempts = 0
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "expires_in": settings.JWT_EXPIRE_MINUTES * 60}


@app.post("/api/auth/change", response_model=MessageResponse, tags=["Auth"])
async def change_master_password(body: MasterPasswordSet, db=Depends(get_db), _=Depends(get_current_user)):
    user = db.query(User).first()
    if not user:
        raise HTTPException(status_code=404, detail="No master password set. POST /api/auth/setup first.")
    user.password_hash = hash_master_password(body.password)
    db.commit()
    return {"message": "Master password updated successfully"}


@app.get("/api/auth/status", tags=["Auth"])
async def auth_status(db=Depends(get_db)):
    user = db.query(User).first()
    return {"configured": user is not None}


# ── Vault ─────────────────────────────────────────────────────────────────────

@app.get("/api/vault", response_model=list[VaultEntryResponse], tags=["Vault"])
async def list_entries(
    search: Optional[str] = None,
    db=Depends(get_db),
    current_user=Depends(get_current_user)
):
    query = db.query(VaultEntry)
    if search:
        query = query.filter(
            VaultEntry.website.ilike(f"%{search}%") |
            VaultEntry.username.ilike(f"%{search}%") |
            VaultEntry.label.ilike(f"%{search}%")
        )
    entries = query.order_by(VaultEntry.created_at.desc()).all()
    result = []
    for e in entries:
        result.append(VaultEntryResponse(
            id=e.id,
            website=e.website,
            username=e.username,
            label=e.label,
            notes=e.notes,
            created_at=e.created_at,
            updated_at=e.updated_at,
        ))
    return result


@app.get("/api/vault/{entry_id}/password", tags=["Vault"])
async def get_password(entry_id: int, db=Depends(get_db), _=Depends(get_current_user)):
    entry = db.query(VaultEntry).filter(VaultEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    decrypted = decrypt_password(entry.encrypted_password)
    return {"password": decrypted}


@app.post("/api/vault", response_model=VaultEntryResponse, status_code=201, tags=["Vault"])
async def create_entry(body: VaultEntryCreate, db=Depends(get_db), _=Depends(get_current_user)):
    password = body.password or generate_password(body.generate_length or 16)
    encrypted = encrypt_password(password)
    entry = VaultEntry(
        website=body.website,
        username=body.username,
        label=body.label,
        notes=body.notes,
        encrypted_password=encrypted,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    logger.info(f"Created vault entry for {body.website}")
    return VaultEntryResponse(
        id=entry.id, website=entry.website, username=entry.username,
        label=entry.label, notes=entry.notes,
        created_at=entry.created_at, updated_at=entry.updated_at,
    )


@app.put("/api/vault/{entry_id}", response_model=VaultEntryResponse, tags=["Vault"])
async def update_entry(entry_id: int, body: VaultEntryUpdate, db=Depends(get_db), _=Depends(get_current_user)):
    entry = db.query(VaultEntry).filter(VaultEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if body.website is not None:
        entry.website = body.website
    if body.username is not None:
        entry.username = body.username
    if body.label is not None:
        entry.label = body.label
    if body.notes is not None:
        entry.notes = body.notes
    if body.password is not None:
        entry.encrypted_password = encrypt_password(body.password)
    entry.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(entry)
    return VaultEntryResponse(
        id=entry.id, website=entry.website, username=entry.username,
        label=entry.label, notes=entry.notes,
        created_at=entry.created_at, updated_at=entry.updated_at,
    )


@app.delete("/api/vault/{entry_id}", response_model=MessageResponse, tags=["Vault"])
async def delete_entry(entry_id: int, db=Depends(get_db), _=Depends(get_current_user)):
    entry = db.query(VaultEntry).filter(VaultEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    db.delete(entry)
    db.commit()
    return {"message": f"Entry {entry_id} deleted"}


# ── Password Generator ─────────────────────────────────────────────────────────

@app.post("/api/generate", response_model=PasswordGenerateResponse, tags=["Tools"])
async def generate(body: PasswordGenerateRequest, _=Depends(get_current_user)):
    pw = generate_password(
        length=body.length,
        use_uppercase=body.use_uppercase,
        use_digits=body.use_digits,
        use_symbols=body.use_symbols,
        exclude_ambiguous=body.exclude_ambiguous,
    )
    return {"password": pw, "length": len(pw), "strength": _score_password(pw)}


def _score_password(pw: str) -> str:
    score = 0
    if len(pw) >= 12: score += 1
    if len(pw) >= 16: score += 1
    if any(c.isupper() for c in pw): score += 1
    if any(c.islower() for c in pw): score += 1
    if any(c.isdigit() for c in pw): score += 1
    if any(not c.isalnum() for c in pw): score += 1
    return ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"][min(score, 5)]
