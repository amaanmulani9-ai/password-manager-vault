"""SQLAlchemy ORM Models"""

from sqlalchemy import Column, Integer, String, DateTime, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timezone

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    password_hash = Column(String, nullable=False)
    failed_attempts = Column(Integer, default=0)
    last_attempt = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class VaultEntry(Base):
    __tablename__ = "vault"

    id = Column(Integer, primary_key=True, index=True)
    website = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    label = Column(String, nullable=True)             # e.g. "Work Gmail"
    notes = Column(String, nullable=True)             # encrypted notes / TOTP seed hint
    encrypted_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
