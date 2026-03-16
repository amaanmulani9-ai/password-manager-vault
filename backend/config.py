"""
Configuration — reads from environment variables with safe defaults.
Copy .env.example → .env and fill in your values before deploying.
"""

import os
import secrets


class Settings:
    def __init__(self) -> None:
        # Environment
        self.ENV: str = os.getenv("ENV", "development")

        # Security
        self._jwt_secret_env: str = os.getenv("JWT_SECRET", "")
        self.JWT_SECRET: str = self._jwt_secret_env or secrets.token_hex(32)
        self.JWT_ALGORITHM: str = "HS256"
        self.JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

        # Encryption key for vault passwords (Fernet)
        # Generate once: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
        self.FERNET_KEY: str = os.getenv("FERNET_KEY", "")  # MUST be set in production

        # Database
        self.DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./vault.db")

        # CORS — comma-separated list of allowed origins
        cors_raw: str = os.getenv(
            "CORS_ORIGINS",
            ",".join(
                [
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                    "http://localhost:5173",
                    "http://127.0.0.1:5173",
                    "http://localhost:8080",
                    "http://127.0.0.1:8080",
                ]
            ),
        )
        origins = [o.strip() for o in cors_raw.split(",") if o.strip()]

        # Allow local file:// testing during development.
        # Browsers send `Origin: null` for file:// pages.
        if not self.is_production and "null" not in origins:
            origins.append("null")

        seen: set[str] = set()
        self.CORS_ORIGINS: list[str] = []
        for origin in origins:
            if origin not in seen:
                seen.add(origin)
                self.CORS_ORIGINS.append(origin)

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    def validate(self):
        if self.is_production and not self.FERNET_KEY:
            raise RuntimeError("FERNET_KEY env var must be set in production!")
        if self.is_production and not self._jwt_secret_env:
            raise RuntimeError("JWT_SECRET env var must be set in production!")


settings = Settings()
