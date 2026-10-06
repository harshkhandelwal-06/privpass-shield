from __future__ import annotations
import os, secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
RUNTIME.mkdir(exist_ok=True)

def _load_dotenv(path: Path) -> None:
    if not path.exists(): return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k,v=line.split("=",1); k=k.strip(); v=v.strip().strip('"').strip("'")
        os.environ.setdefault(k,v)

_load_dotenv(ROOT / ".env")

def env(name: str, default: str = "") -> str:
    return os.getenv(name, default)

APP_ENV = env("APP_ENV", "development")
HOST = env("HOST", "127.0.0.1")
PORT = int(env("PORT", "8000"))
APP_SECRET = env("APP_SECRET") or secrets.token_urlsafe(48)
COOKIE_SECURE = env("COOKIE_SECURE", "false").lower() == "true"
DATABASE_URL = env("DATABASE_URL", "").strip() or f"sqlite:///{RUNTIME / 'privpass.db'}"
# Hosted Postgres (Neon, Render, Railway, Supabase) hands out postgres:// or postgresql:// URLs;
# SQLAlchemy needs the driver named, and this project ships psycopg 3.
for _prefix in ("postgres://", "postgresql://"):
    if DATABASE_URL.startswith(_prefix):
        DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len(_prefix):]
REDIS_URL = env("REDIS_URL", "")
HIBP_USER_AGENT = env("HIBP_USER_AGENT", "PrivPass-Shield/6.0")
MAX_SCAN_MB = int(env("MAX_SCAN_MB", "25"))
SESSION_MINUTES = int(env("SESSION_MINUTES", "60"))
RESET_MINUTES = int(env("RESET_MINUTES", "15"))
CLIENT_PBKDF2_ITERATIONS = int(env("CLIENT_PBKDF2_ITERATIONS", "310000"))

# Public demo: a production deployment (real security settings) that still hosts the shared demo workspace,
# demo assets and simulations, so judges can use a public link. Real accounts stay fully separate.
PUBLIC_DEMO = env("PRIVPASS_PUBLIC_DEMO", "false").lower() == "true"
DEMO_AUTOSEED = env("PRIVPASS_DEMO_AUTOSEED", "false").lower() == "true"


def demo_enabled() -> bool:
    """Demo accounts, demo assets and simulations are available (read at call time so tests can toggle it)."""
    return APP_ENV != "production" or PUBLIC_DEMO
