import os
import sys
from pathlib import Path

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("APP_SECRET", "privpass-test-secret-fixed-2026")
# The real (live-workspace) admin used by tests; the demo admin only ever sees the demo workspace.
REAL_ADMIN_EMAIL = "owner@example.com"
REAL_ADMIN_PASSWORD = "Test-Owner-Passphrase-2026-Real"
os.environ["PRIVPASS_ADMIN_EMAIL"] = REAL_ADMIN_EMAIL
os.environ["PRIVPASS_ADMIN_PASSWORD"] = REAL_ADMIN_PASSWORD

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
runtime = ROOT / "runtime"
runtime.mkdir(exist_ok=True)
# Tests use their own database file, so running scripts\VERIFY-PRIVPASS.bat never touches your real accounts or data.
# Set PRIVPASS_TEST_DATABASE_URL to run the same suite against an empty PostgreSQL database instead.
db = runtime / "privpass-test.db"
if os.getenv("PRIVPASS_TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["PRIVPASS_TEST_DATABASE_URL"]
else:
    os.environ["DATABASE_URL"] = f"sqlite:///{db.as_posix()}"
    if db.exists():
        db.unlink()

# ---- test helpers -------------------------------------------------------------------------
# The API enforces CSRF on every state-changing request. This TestClient subclass behaves like
# the real browser client: it fetches the double-submit cookie once and echoes pp_csrf (which the
# server rebinds to the session token at login) in the X-CSRF-Token header.
import fastapi.testclient as _ftc

class CsrfAwareTestClient(_ftc.TestClient):
    def request(self, method, url, *args, **kwargs):
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and not kwargs.pop("skip_csrf", False):
            if "pp_csrf" not in self.cookies:
                super().request("GET", "/api/csrf")
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault("X-CSRF-Token", self.cookies.get("pp_csrf"))
            kwargs["headers"] = headers
        return super().request(method, url, *args, **kwargs)

_ftc.TestClient = CsrfAwareTestClient


def breach_gate(client, purpose="signup", length=40):
    """Evidence the official browser client sends after a clean live HIBP range check."""
    ticket = client.post("/api/auth/breach-ticket", json={"purpose": purpose}).json()["ticket"]
    return {"ticket": ticket, "hibp_status": "safe", "hibp_mode": "live", "password_length": length}


import pytest

@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Each test starts with fresh in-memory rate-limit buckets (the limiter itself is tested separately)."""
    from app.main import app
    app.state.rl = {}
    yield


def login_as(client, email, password, otp=None):
    """Sign in like the browser: derive the login secret from the challenge, then an HMAC proof over the nonce."""
    import hashlib, hmac as _hmac
    ch = client.post("/api/auth/challenge", json={"email": email}).json()
    v = verifier_for(password, ch)
    body = {"email": email, "nonce": ch["nonce"], "proof": _hmac.new(v, ch["nonce"].encode(), hashlib.sha256).hexdigest()}
    if otp: body["otp"] = otp
    if ch.get("kdf", 1) < 2:
        m = material(password); body["upgrade"] = {k: m[k] for k in ("watch_salt_b64", "prefix", "watch_b64")}
    return client.post("/api/auth/login", json=body)


def real_admin(client):
    r = login_as(client, REAL_ADMIN_EMAIL, REAL_ADMIN_PASSWORD)
    assert r.status_code == 200, r.text
    return r


# ---- 7.3: fake HIBP for the server-side breach check + browser-equivalent credential helpers ----------------
import hashlib as _hashlib
import unicodedata as _ud


class FakeHIBP:
    """Stands in for api.pwnedpasswords.com. Mark passwords as breached with .breach(pw); .down simulates an outage."""
    def __init__(self):
        self.breached: dict[str, int] = {}
        self.down = False
        self.calls = 0

    def breach(self, password: str, count: int = 1234):
        self.breached[_sha1(password)] = count

    def fetch_range(self, prefix: str, fresh: bool = False):
        self.calls += 1
        if self.down:
            return None
        rows = [(h[5:], c) for h, c in self.breached.items() if h.startswith(prefix.upper())]
        rows += [(f"{i:035X}", 1) for i in range(40)]          # unrelated hashes in the same range
        return rows


def _sha1(password: str) -> str:
    return _hashlib.sha1(_ud.normalize("NFKC", password).encode()).hexdigest().upper()


@pytest.fixture(autouse=True)
def hibp(monkeypatch):
    fake = FakeHIBP()
    import app.breachwatch as bw
    monkeypatch.setattr(bw, "fetch_range", fake.fetch_range)
    return fake


def material(password: str) -> dict:
    """Exactly what the browser sends for a new password (see static/app.js newCredential)."""
    import base64, os as _os
    from app.breachwatch import derive_watch
    e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    h = _sha1(password); salt, ws = _os.urandom(16), _os.urandom(16)
    return {"salt_b64": e(salt), "watch_salt_b64": e(ws), "prefix": h[:5], "watch_b64": e(derive_watch(h, ws))}


def verifier_for(password: str, challenge: dict) -> bytes:
    """The login secret the browser derives from a challenge (v2 bound credential, or v1 legacy)."""
    import base64
    from app.breachwatch import derive_verifier, derive_watch
    d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    pw = _ud.normalize("NFKC", password)
    if challenge.get("kdf", 1) >= 2:
        h = _sha1(password)
        return derive_verifier(derive_watch(h, d(challenge["watch_salt_b64"])), h[:5], d(challenge["salt_b64"]))
    return _hashlib.pbkdf2_hmac("sha256", pw.encode(), d(challenge["salt_b64"]), 310000, 32)


def signup_as(client, email: str, password: str, score: int = 90):
    body = {"email": email, **material(password), "score": score, "score_label": "Excellent", "breached": False,
            "breach_gate": breach_gate(client, length=len(password))}
    return client.post("/api/auth/signup", json=body)
