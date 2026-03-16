"""Pydantic v2 schemas for request/response validation"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime


# ── Auth ──────────────────────────────────────────────────────────────────────

class MasterPasswordSet(BaseModel):
    password: str = Field(..., min_length=8, max_length=256)

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class MasterPasswordVerify(BaseModel):
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


# ── Vault ─────────────────────────────────────────────────────────────────────

class VaultEntryCreate(BaseModel):
    website: str = Field(..., min_length=1, max_length=255)
    username: str = Field(..., min_length=1, max_length=255)
    label: Optional[str] = Field(None, max_length=100)
    notes: Optional[str] = Field(None, max_length=1000)
    password: Optional[str] = None          # if blank, auto-generate
    generate_length: Optional[int] = Field(16, ge=8, le=128)


class VaultEntryUpdate(BaseModel):
    website: Optional[str] = Field(None, min_length=1, max_length=255)
    username: Optional[str] = Field(None, min_length=1, max_length=255)
    label: Optional[str] = Field(None, max_length=100)
    notes: Optional[str] = Field(None, max_length=1000)
    password: Optional[str] = None


class VaultEntryResponse(BaseModel):
    id: int
    website: str
    username: str
    label: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Password Generator ─────────────────────────────────────────────────────────

class PasswordGenerateRequest(BaseModel):
    length: int = Field(16, ge=8, le=128)
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False


class PasswordGenerateResponse(BaseModel):
    password: str
    length: int
    strength: str


# ── Generic ───────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class MessageResponse(BaseModel):
    message: str
