# 🔐 VaultX — Password Manager v2

A fully modernized, production-ready password manager rebuilt from the original CLI script into a secure **FastAPI + HTML** web application.

---

## ✨ What's New vs Original

| Feature | Original | VaultX v2 |
|---|---|---|
| Interface | CLI only | Web UI (dark, responsive) |
| Hashing | SHA-256 ❌ | **Argon2id** ✅ (OWASP rec.) |
| Sessions | None | **JWT Bearer tokens** |
| Vault encryption | Fernet (file key) | Fernet + **env-var key** |
| API | None | Full **REST API** with Swagger docs |
| Input validation | None | **Pydantic v2** schemas |
| Rate limiting | None | IP-based rate limiting |
| Password strength | None | Real-time strength meter |
| Search | None | Full-text search across all fields |
| Labels / Notes | None | Supported |
| Docker | None | Docker + Compose ready |
| Audit trail | None | Created/updated timestamps |

---

## 🚀 Quick Start (Local Development)

### 1. Install Python dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Set environment variables (optional for dev)
The app auto-generates a Fernet key in development mode and saves it to `fernet.key`.
For production, always set `FERNET_KEY` explicitly.

### 3. Run the API
```bash
cd backend
uvicorn main:app --reload --port 8000
```

API docs available at: http://localhost:8000/api/docs

### 4. Open the frontend
Open `frontend/index.html` in a browser, or serve it:
```bash
cd frontend
python -m http.server 8080
```

Then visit: http://localhost:8080

---

## 🐳 Docker Deployment

### 1. Set your secrets
```bash
cp .env.example .env
# Edit .env with real JWT_SECRET and FERNET_KEY
```

Generate secrets:
```bash
# JWT secret
python -c "import secrets; print(secrets.token_hex(32))"

# Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Build and run
```bash
cd docker
docker compose --env-file ../.env up -d
```

- Frontend: http://localhost:8080
- API docs: http://localhost:8000/api/docs

---

## 🌐 Cloud Deployment Options

### Render.com (free tier)
1. Push to GitHub
2. New Web Service → connect repo → Root: `backend/`
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add env vars: `JWT_SECRET`, `FERNET_KEY`, `ENV=production`

### Railway
1. `railway up` from `backend/` directory
2. Set env vars in dashboard

### VPS (DigitalOcean, Hetzner, etc.)
```bash
# Install deps, then run with gunicorn for production
gunicorn main:app -w 2 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```
Put Nginx in front for HTTPS.

---

## 🔒 Security Architecture

```
User → JWT (1hr) → API → Argon2id verify → Fernet decrypt → plaintext
```

- **Master password**: Hashed with Argon2id (memory=64MB, time=3, parallelism=2)
- **Vault passwords**: Encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- **Sessions**: HS256 JWT, 1hr expiry, bearer token
- **Rate limiting**: 5 auth attempts / 60s per IP
- **Validation**: All inputs validated via Pydantic v2

---

## 📡 API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | No | Health check |
| POST | `/api/auth/setup` | No | Set master password |
| POST | `/api/auth/login` | No | Get JWT token |
| POST | `/api/auth/change` | ✅ | Change master password |
| GET | `/api/vault` | ✅ | List all entries (supports `?search=`) |
| POST | `/api/vault` | ✅ | Create entry |
| GET | `/api/vault/{id}/password` | ✅ | Reveal password |
| PUT | `/api/vault/{id}` | ✅ | Update entry |
| DELETE | `/api/vault/{id}` | ✅ | Delete entry |
| POST | `/api/generate` | ✅ | Generate password |

Full interactive docs at `/api/docs` (Swagger UI).

---

## 📁 Project Structure

```
password_manager/
├── backend/
│   ├── main.py          # FastAPI app & routes
│   ├── auth.py          # Argon2, JWT, Fernet, generator
│   ├── models.py        # SQLAlchemy ORM models
│   ├── database.py      # DB session management
│   ├── schemas.py       # Pydantic v2 schemas
│   ├── config.py        # Environment config
│   └── requirements.txt
├── frontend/
│   └── index.html       # Self-contained SPA
├── docker/
│   ├── Dockerfile.backend
│   └── docker-compose.yml
├── .env.example
└── README.md
```
