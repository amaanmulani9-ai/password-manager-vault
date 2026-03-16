"""
Authentication & Cryptography utilities
- Argon2id for master password hashing (OWASP recommended)
- JWT for session tokens
- Fernet (AES-128-CBC + HMAC-SHA256) for vault encryption
- secrets module for password generation
"""

import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from jose import JWTError, jwt

from config import settings

# ── Argon2id hasher (OWASP recommended params) ─────────────────────────────────
_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_master_password(password: str) -> str:
    return _ph.hash(password)


def verify_master_password(password: str, stored_hash: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


# ── JWT ────────────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None


# ── Fernet vault encryption ────────────────────────────────────────────────────

def _get_fernet() -> Fernet:
    key = settings.FERNET_KEY
    if not key:
        # Auto-generate and persist for development (NOT for production)
        key_file = os.getenv("FERNET_KEY_FILE", "fernet.key")
        key_path = Path(key_file)
        if key_path.exists():
            key = key_path.read_text(encoding="utf-8").strip()
        else:
            key = Fernet.generate_key().decode()
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(key, encoding="utf-8")
            print(f"⚠️  Generated Fernet key saved to {key_file}. Set FERNET_KEY env var in production!")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_password(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_password(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ── Password generator ─────────────────────────────────────────────────────────
_AMBIGUOUS = set("0O1lI|")


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    pool = string.ascii_lowercase
    required = [secrets.choice(string.ascii_lowercase)]

    if use_uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in _AMBIGUOUS)
        pool += chars
        required.append(secrets.choice(chars))

    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in _AMBIGUOUS)
        pool += chars
        required.append(secrets.choice(chars))

    if use_symbols:
        chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pool += chars
        required.append(secrets.choice(chars))

    if exclude_ambiguous:
        pool = "".join(c for c in pool if c not in _AMBIGUOUS)

    remaining = [secrets.choice(pool) for _ in range(length - len(required))]
    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
