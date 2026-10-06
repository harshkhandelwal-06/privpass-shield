from __future__ import annotations
import asyncio, base64, hashlib, hmac, json, os, secrets, time, zipfile, io
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Depends, Request, Response, UploadFile, File, HTTPException, Form
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc, and_
from pydantic import BaseModel, Field
from . import config as cfg
from .config import ROOT, RUNTIME, MAX_SCAN_MB, COOKIE_SECURE, APP_ENV, RESET_MINUTES, APP_SECRET
from . import breachwatch as bw
from . import exposure as exposure_map
from .db import db, init_db, current_workspace, workspace_scope, DEMO, LIVE
from .models import User, Session as DbSession, PasswordEvent, Scan, SecretFinding, AuditEvent, VaultItem, EphemeralToken, AccountAuditReport, LoginEvent
from .security import uid, b64e, b64d, sha256_hex, hmac_hex, encrypt_verifier, decrypt_verifier, verifier_integrity, verify_verifier_hash, new_session_token, token_hash, csrf_token, session_expiry, cookie_kwargs, security_headers, require_same_origin, new_totp_secret, verify_totp
from .scanner import scan_zip, scan_dir
from .db import SessionLocal

def valid_email(v: str) -> bool:
    return bool(v and "@" in v and "." in v.split("@")[-1] and len(v) <= 320)

app = FastAPI(title="PrivPass Shield", version="6.2.0", docs_url="/docs", redoc_url=None)
STATIC = ROOT / "static"
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")

PASSWORD_MIN_LENGTH = 15   # NIST SP 800-63B rev.4: password-only authenticators
PASSWORD_MAX_LENGTH = 128  # NIST: allow at least 64 characters

class BreachGateEvidence(BaseModel):
    """What the official client reports after running the breach gate.

    The server never receives the password, its full SHA-1, or even the 5-character HIBP
    prefix (the prefix would let a database thief pre-filter guesses against the verifier).
    See docs/THREAT-MODEL.md for what this can and cannot prove.
    """
    ticket: str = Field(min_length=20, max_length=200)
    hibp_status: str  # "safe" | "breached" | "unavailable"
    hibp_mode: str = "live"  # "live" | "offline-demo" | "unavailable"
    password_length: int = Field(ge=0, le=4096)

class CredentialMaterial(BaseModel):
    """What the browser derives from a NEW password (7.3). Never the password, its SHA-1 or the SHA-1 suffix."""
    salt_b64: str
    watch_salt_b64: str
    prefix: str = Field(min_length=5, max_length=5)   # k-anonymity prefix, the same 5 characters HIBP receives
    watch_b64: str                                    # PBKDF2(SHA-1 hex, watch_salt, 2000)

class SignupBody(CredentialMaterial):
    email: str
    verifier_b64: str = ""                            # ignored since 7.3: the server derives the verifier itself
    verifier_hash: str = ""
    score: int = Field(ge=0, le=100)
    score_label: str
    breached: bool
    breach_gate: BreachGateEvidence

class BreachTicketBody(BaseModel):
    purpose: str  # "signup" | "reset"

class BreachRejectBody(BaseModel):
    ticket: str
    reason: str  # "breached" | "below_policy" | "unavailable"

class ChallengeBody(BaseModel):
    email: str

class UpgradeMaterial(BaseModel):
    watch_salt_b64: str
    prefix: str = Field(min_length=5, max_length=5)
    watch_b64: str

class LoginBody(BaseModel):
    email: str
    nonce: str
    proof: str
    otp: str | None = None
    upgrade: UpgradeMaterial | None = None            # legacy (v1) accounts move to the bound v2 credential at sign-in

class ResetRequestBody(BaseModel):
    email: str

class ResetCompleteBody(CredentialMaterial):
    token: str
    verifier_b64: str = ""
    verifier_hash: str = ""
    score: int = Field(ge=0, le=100)
    score_label: str
    breached: bool
    breach_gate: BreachGateEvidence

class PolicyBody(BaseModel):
    min_length: int = Field(ge=8, le=128)
    block_breached: bool = True
    require_mfa: bool = False
    max_scan_mb: int = Field(ge=1, le=100)
    secret_block_threshold: str = "HIGH"

# simple in-memory limiter for local; production can use Redis in front of the API
def rate_limited(request: Request, bucket: str, limit: int, window: int = 60):
    ip = request.client.host if request.client else "local"
    key = f"privpass:rl:{bucket}:{ip}"
    if os.getenv("REDIS_URL"):
        try:
            import redis
            r = redis.from_url(os.getenv("REDIS_URL"), decode_responses=True)
            count = r.incr(key)
            if count == 1: r.expire(key, window)
            if count > limit: raise HTTPException(429, "rate limit exceeded")
            return
        except HTTPException: raise
        except Exception:
            pass
    store = getattr(app.state, "rl", None)
    if store is None:
        app.state.rl = {}; store = app.state.rl
    now = time.time(); start, count = store.get(key, (now, 0))
    if now - start > window: start, count = now, 0
    count += 1; store[key] = (start, count)
    if count > limit: raise HTTPException(429, "rate limit exceeded")

def get_current_session(request: Request, session: Session) -> tuple[User, DbSession]:
    token = request.cookies.get("pp_session")
    if not token: raise HTTPException(401, "not authenticated")
    rec = session.scalar(select(DbSession).where(DbSession.token_hash == token_hash(token)))
    owner = session.get(User, rec.user_id) if rec else None
    if owner is not None and owner.breach_locked:
        raise HTTPException(423, locked_detail(owner))        # even a session opened before the lock can't be used
    if not rec or rec.revoked_at is not None or rec.expires_at < datetime.now(timezone.utc).replace(tzinfo=None): raise HTTPException(401, "session expired")
    user = owner
    if not user or not user.is_active: raise HTTPException(401, "account inactive")
    return user, rec

# While a password is flagged as breached, only what is needed to change it is reachable.
PASSWORD_CHANGE_ALLOWED = ("/api/auth/me", "/api/auth/logout", "/api/auth/change-password", "/api/vault/", "/api/notifications", "/api/auth/passkeys",
                           "/api/admin/simulations")  # an admin who simulated a breach on themselves can still undo it (admin-only, simulation-only)

def gate_event(session: Session, **kw) -> None:
    """Record a breach-gate PasswordEvent. Anonymous visitors (the public signup/reset form) are counted in the
    live workspace and, outside production, mirrored into the demo workspace so the demo Command Center shows them too."""
    session.add(PasswordEvent(id=uid(), **kw))
    if current_workspace.get() is None and cfg.demo_enabled():
        session.add(PasswordEvent(id=uid(), workspace=DEMO, **kw))

def audit(session: Session, user_id: str | None, event_type: str, severity: str = "INFO", meta: dict | None = None):
    session.add(AuditEvent(id=uid(), user_id=user_id, event_type=event_type, severity=severity, metadata_json=json.dumps(meta or {})))

def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

def issue_token(session: Session, kind: str, ttl_seconds: int, user_id: str | None = None, payload: dict | None = None, raw: str | None = None) -> str:
    """Persist a single-use token (hash only) so every worker/replica can validate it."""
    raw = raw or secrets.token_urlsafe(32)
    session.query(EphemeralToken).filter(EphemeralToken.expires_at < _now()).delete(synchronize_session=False)
    session.add(EphemeralToken(id=uid(), kind=kind, token_hash=sha256_hex(f"{kind}:{raw}"), user_id=user_id,
                               payload_json=json.dumps(payload or {}), expires_at=_now() + timedelta(seconds=ttl_seconds)))
    return raw

def consume_token(session: Session, kind: str, raw: str | None, user_id: str | None = None) -> EphemeralToken | None:
    """Atomically mark a token consumed. Returns None if missing, expired, reused or bound to another user."""
    if not raw:
        return None
    row = session.scalar(select(EphemeralToken).where(EphemeralToken.kind == kind, EphemeralToken.token_hash == sha256_hex(f"{kind}:{raw}")))
    if not row or row.consumed_at is not None or row.expires_at < _now():
        return None
    if user_id is not None and row.user_id != user_id:
        return None
    updated = session.query(EphemeralToken).filter(EphemeralToken.id == row.id, EphemeralToken.consumed_at.is_(None)).update({EphemeralToken.consumed_at: _now()}, synchronize_session=False)
    if updated != 1:
        return None
    return row

def decoy_salt(email: str) -> str:
    """Deterministic fake salt for unknown accounts so /challenge cannot enumerate users."""
    return b64e(hmac.new(APP_SECRET.encode(), f"decoy-salt:{email.lower()}".encode(), hashlib.sha256).digest()[:16])

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Account-level flows identify the account by email/credential, so they must see every workspace
# (e.g. an email address is unique across demo and live). They set the workspace themselves once the
# account is known. The CSRF check below still applies to them.
UNSCOPED_PATHS = ("/api/auth/signup", "/api/auth/challenge", "/api/auth/login", "/api/auth/reset/", "/api/auth/passkeys/login/", "/api/canary/")

@app.middleware("http")
async def middleware(request: Request, call_next):
    # CSRF: every state-changing API call must echo a token in X-CSRF-Token.
    #  - signed-in requests: the token bound to the server-side session
    #  - anonymous requests: the double-submit pp_csrf cookie
    # Combined with SameSite=Lax cookies and the Origin check, this blocks cross-site form/fetch forgery.
    # Workspace: a signed-in request only ever sees its own workspace (demo or live); see db.workspace_scope.
    session_csrf, workspace = None, None
    session_cookie = request.cookies.get("pp_session")
    if session_cookie and request.url.path.startswith("/api/") and not request.url.path.startswith(UNSCOPED_PATHS):
        with SessionLocal() as s:
            rec = s.scalar(select(DbSession).where(DbSession.token_hash == token_hash(session_cookie), DbSession.revoked_at.is_(None)))
            if rec and rec.expires_at > _now():
                session_csrf = rec.csrf_token
                owner = s.get(User, rec.user_id)
                workspace = owner.workspace if owner else None
    elif session_cookie and request.url.path.startswith("/api/"):
        with SessionLocal() as s:
            rec = s.scalar(select(DbSession).where(DbSession.token_hash == token_hash(session_cookie), DbSession.revoked_at.is_(None)))
            if rec and rec.expires_at > _now():
                session_csrf = rec.csrf_token
    current_workspace.set(workspace)
    if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/") and not request.url.path.startswith("/api/canary/"):
        header = request.headers.get("x-csrf-token", "")
        expected = session_csrf
        if expected is None:
            expected = request.cookies.get("pp_csrf")
        if not header or not expected or not hmac.compare_digest(header, expected):
            return security_headers(JSONResponse({"detail": "csrf token missing or invalid"}, status_code=403))
    response = await call_next(request)
    security_headers(response)
    return response

BREACH_WATCH_MINUTES = int(os.getenv("PRIVPASS_BREACH_WATCH_MINUTES", "360"))

async def _breach_watch_loop():
    import asyncio
    await asyncio.sleep(45)
    while True:
        try:
            await asyncio.to_thread(breach_watch_sweep, None)
        except Exception as exc:  # the watch must never take the app down
            print(f"breach watch: {exc}")
        await asyncio.sleep(max(5, BREACH_WATCH_MINUTES) * 60)

@asynccontextmanager
async def lifespan(app_obj):
    init_db()
    if cfg.demo_enabled():
        from .bootstrap import ensure_demo_admin
        ensure_demo_admin()          # demo workspace + the real admin
        if cfg.DEMO_AUTOSEED:
            from .demo_seed import seed_if_empty
            seed_if_empty()
    else:
        from .bootstrap import ensure_real_admin
        ensure_real_admin()
    import asyncio
    watch = asyncio.create_task(_breach_watch_loop()) if BREACH_WATCH_MINUTES > 0 and APP_ENV != "test" else None
    yield
    if watch:
        watch.cancel()

app.router.lifespan_context = lifespan

@app.get("/", response_class=HTMLResponse)
def home(): return FileResponse(STATIC / "index.html")

@app.get("/api/health")
def health(): return {"status":"ok","version":"7.3.0","env":APP_ENV,"demo":cfg.demo_enabled()}

@app.get("/api/ready")
def ready(session: Session = Depends(db)):
    session.execute(select(func.count(User.id))).scalar_one()
    return {"status":"ready","database":"ok"}

@app.get("/api/csrf")
def csrf(request: Request, session: Session = Depends(db)):
    token = request.cookies.get("pp_csrf") or secrets.token_urlsafe(32)
    resp = JSONResponse({"csrf": token})
    resp.set_cookie("pp_csrf", token, httponly=False, secure=COOKIE_SECURE, samesite="lax", path="/")
    return resp

def accepted_breach_modes() -> set[str]:
    """'live' (HIBP k-anonymity) is always accepted. PRIVPASS_BREACH_FALLBACK=local additionally accepts
    the offline Bloom-filter corpus when HIBP is unreachable (air-gapped / availability trade-off)."""
    return {"live", "local-corpus"} if os.getenv("PRIVPASS_BREACH_FALLBACK", "").lower() == "local" else {"live"}

def _policy_gate(gate: BreachGateEvidence, declared_breached: bool) -> None:
    """Server-side policy contract. Fails closed on anything other than a clean accepted check."""
    if declared_breached or gate.hibp_status == "breached":
        raise HTTPException(400, "compromised password blocked")
    if gate.hibp_status != "safe" or gate.hibp_mode not in accepted_breach_modes():
        raise HTTPException(400, "breach verification unavailable - password not accepted (fail-closed)")
    if gate.password_length < PASSWORD_MIN_LENGTH:
        raise HTTPException(400, f"password must be at least {PASSWORD_MIN_LENGTH} characters")
    if gate.password_length > PASSWORD_MAX_LENGTH:
        raise HTTPException(400, f"password must be at most {PASSWORD_MAX_LENGTH} characters")

def _material(body) -> tuple[bytes, bytes, str, bytes]:
    """Validate browser-derived credential material; returns (salt, watch_salt, prefix, watch)."""
    try:
        salt = b64d(body.salt_b64) if hasattr(body, "salt_b64") else os.urandom(16)
        watch_salt, watch = b64d(body.watch_salt_b64), b64d(body.watch_b64)
    except Exception:
        raise HTTPException(400, "invalid credential encoding")
    if len(salt) != 16 or len(watch_salt) != 16 or len(watch) != 32 or not bw.valid_prefix(body.prefix):
        raise HTTPException(400, "invalid credential material")
    return salt, watch_salt, body.prefix.upper(), watch

BREACHED_MSG = "This password appears in known data breaches (verified by the server). Choose a different one."

def _server_breach_check(salt: bytes, watch_salt: bytes, prefix: str, watch: bytes, gate: "BreachGateEvidence | None") -> "bw.Result":
    """Authoritative check: the server asks HIBP itself and never trusts the browser's verdict."""
    res = bw.check_new(prefix, watch_salt, watch)
    if res.status == "breached":
        raise HTTPException(400, BREACHED_MSG)
    if res.status == "unavailable" and not (gate and gate.hibp_mode == "local-corpus" and "local-corpus" in accepted_breach_modes()):
        raise HTTPException(503, "The server could not reach the breach database, so the password can't be accepted yet (fail-closed). Try again shortly.")
    return res

def lock_for_breach(session: Session, user: User, source: str, count: int = 0) -> None:
    """Lock an account whose password appeared in a breach: every session ends and only a password reset unlocks it."""
    if user.breach_locked:
        return
    user.breach_locked = True; user.breach_locked_at = _now(); user.breach_count = count or 0; user.breach_flag_source = source
    session.query(DbSession).filter(DbSession.user_id == user.id, DbSession.revoked_at.is_(None)).update({DbSession.revoked_at: _now()}, synchronize_session=False)
    sim = source == "simulation"
    seen = f" (seen {count:,} times)" if count else ""
    notify(session, "simulation" if sim else "breach", f"{'[SIMULATION] ' if sim else ''}Your password appeared in a data breach",
           f"Your password was found in breach data{seen}. For your safety every session was signed out and the account is locked until you reset the password.",
           "CRITICAL", "account", user_id=user.id)
    notify(session, "simulation" if sim else "breach", f"{'[SIMULATION] ' if sim else ''}Account locked: breached password",
           f"{user.email} was locked by the breach watch and must reset their password.", "HIGH", "command")
    audit(session, user.id, "ACCOUNT_LOCKED_BREACHED_PASSWORD", severity="HIGH", meta={"source": source, "count": count})

def run_breach_check(session: Session, user: User, fresh: bool = False) -> "bw.Result":
    """Server-side re-check of a stored account (sign-in, schedule, admin button). Locks on a match.
    fresh=True skips the short range cache (explicit re-checks and the scheduled sweep)."""
    res = bw.check_user(user, fresh=fresh)
    if res.status != "unavailable":
        user.breach_checked_at = _now(); user.breach_check_status = res.status
    if res.status == "breached":
        lock_for_breach(session, user, "hibp", res.count)
    return res

def breach_watch_sweep(workspace: str | None = None) -> dict:
    """Re-check every active account's stored breach-watch value against HIBP (signed in or not). Locks on a match.
    workspace=None sweeps all workspaces (the background job); each user's rows are written in their own workspace."""
    stats = {"checked": 0, "safe": 0, "locked": 0, "unavailable": 0, "legacy": 0}
    with workspace_scope(workspace), SessionLocal() as s:
        ids = [u.id for u in s.scalars(select(User).where(User.is_active.is_(True), User.breach_locked.is_(False)))]
    for uid_ in ids:
        with workspace_scope(None), SessionLocal() as s:
            u = s.get(User, uid_)
            if u is None or u.breach_locked:
                continue
            if not u.watch_mac:
                stats["legacy"] += 1; continue          # upgraded automatically at the next sign-in
            with workspace_scope(u.workspace):
                res = run_breach_check(s, u, fresh=True)
                s.commit()                              # inside the scope, so alerts land in the right workspace
            stats["checked"] += 1
            stats["locked" if res.status == "breached" else res.status] += 1
    return stats

LOCKED_DETAIL = "password breached: this account is locked. Reset your password to unlock it."

def locked_detail(user: User) -> str:
    if user.workspace == DEMO and user.breach_flag_source == "simulation":
        return LOCKED_DETAIL[:-len("Reset your password to unlock it.")] + "This is a simulation on a shared demo account: the demo admin can remove it in Command Center."
    return LOCKED_DETAIL

def _validate_verifier(salt_b64: str, verifier_b64: str) -> None:
    try:
        salt, verifier = b64d(salt_b64), b64d(verifier_b64)
    except Exception:
        raise HTTPException(400, "invalid verifier encoding")
    if len(salt) != 16: raise HTTPException(400, "invalid salt")
    if len(verifier) != 32: raise HTTPException(400, "invalid verifier")

@app.post("/api/auth/breach-ticket")
def breach_ticket(body: BreachTicketBody, request: Request, session: Session = Depends(db)):
    """Issue a single-use ticket that must accompany a signup/reset. The client spends it
    either on the account write or on /breach-gate/reject, so every attempt is counted."""
    rate_limited(request, "breach-ticket", 30, 60); require_same_origin(request)
    if body.purpose not in {"signup", "reset", "change"}: raise HTTPException(400, "invalid purpose")
    ticket = issue_token(session, f"breach_gate_{body.purpose}", 300)
    session.commit()
    return {"ticket": ticket, "expires_in": 300, "policy": {"min_length": PASSWORD_MIN_LENGTH, "max_length": PASSWORD_MAX_LENGTH,
            "block_breached": True, "fail_closed": True, "composition_rules": False, "normalization": "NFKC",
            "accepted_modes": sorted(accepted_breach_modes())}}

@app.post("/api/auth/breach-gate/reject")
def breach_gate_reject(body: BreachRejectBody, request: Request, session: Session = Depends(db)):
    """Record a blocked signup/reset attempt (aggregate only - no password data)."""
    rate_limited(request, "breach-reject", 30, 60); require_same_origin(request)
    if body.reason not in {"breached", "below_policy", "unavailable"}: raise HTTPException(400, "invalid reason")
    row = consume_token(session, "breach_gate_signup", body.ticket) or consume_token(session, "breach_gate_reset", body.ticket) or consume_token(session, "breach_gate_change", body.ticket)
    if not row: raise HTTPException(400, "invalid or expired breach ticket")
    purpose = row.kind.rsplit("_", 1)[-1]
    gate_event(session, user_id=None, event_type=f"{purpose}_blocked", breached=body.reason == "breached", score=0, score_label=body.reason, guess_log10=0)
    audit(session, None, "BREACH_GATE_REJECTED", severity="WARN", meta={"purpose": purpose, "reason": body.reason})
    session.commit()
    return {"ok": True}

@app.post("/api/auth/signup")
def signup(body: SignupBody, request: Request, session: Session = Depends(db)):
    rate_limited(request, "signup", 10, 300); require_same_origin(request)
    if not valid_email(body.email): raise HTTPException(400, "invalid email")
    if not consume_token(session, "breach_gate_signup", body.breach_gate.ticket):
        raise HTTPException(400, "breach check ticket missing, expired or already used")
    try:
        _policy_gate(body.breach_gate, body.breached)
        material = _material(body)
        _server_breach_check(*material, body.breach_gate)
    except HTTPException as exc:
        gate_event(session, user_id=None, event_type="signup_blocked", breached=body.breached or body.breach_gate.hibp_status == "breached" or exc.detail == BREACHED_MSG, score=body.score, score_label=body.score_label, guess_log10=0)
        audit(session, None, "BREACH_GATE_REJECTED", severity="WARN", meta={"purpose": "signup", "reason": exc.detail})
        session.commit()
        raise
    email = body.email.lower()
    if session.scalar(select(User).where(User.email == email)):
        session.commit(); raise HTTPException(409, "account already exists")
    user = User(id=uid(), email=email, vault_salt_b64=b64e(secrets.token_bytes(16)), breach_checked_at=_now(), breach_check_status="safe")
    bw.install(user, *material)          # the verifier is derived from the value the server just checked
    session.add(user)
    gate_event(session, user_id=user.id, event_type="signup", breached=False, score=body.score, score_label=body.score_label, guess_log10=0)
    audit(session, user.id, "ACCOUNT_CREATED", meta={"score": body.score, "label": body.score_label, "breach_gate": "passed"})
    session.commit()
    return {"ok":True,"user_id":user.id}

@app.post("/api/auth/challenge")
def challenge(body: ChallengeBody, request: Request, session: Session = Depends(db)):
    rate_limited(request, "challenge", 30, 60); require_same_origin(request)
    if not valid_email(body.email): raise HTTPException(400, "invalid email")
    user = session.scalar(select(User).where(User.email == body.email.lower()))
    if not user:
        # Same response shape for unknown accounts: a decoy salt and an unusable nonce (no enumeration).
        return {"nonce": secrets.token_urlsafe(32), "salt_b64": decoy_salt(body.email), "watch_salt_b64": decoy_salt("watch:" + body.email),
                "kdf": 2, "mfa_enabled": False}
    nonce = issue_token(session, "login_challenge", 120, user_id=user.id)
    session.commit()
    return {"nonce": nonce, "salt_b64": user.salt_b64, "watch_salt_b64": user.watch_salt_b64 or decoy_salt("watch:" + body.email),
            "kdf": user.kdf_version or 1, "mfa_enabled": user.mfa_enabled}

def record_login(session: Session, request: Request, email: str, known: bool, success: bool, reason: str) -> None:
    """Aggregate-safe sign-in telemetry for the anomaly detector (HMAC of the email only)."""
    session.add(LoginEvent(id=uid(), ip=request.client.host if request.client else "local",
                           account_hash=hmac.new(APP_SECRET.encode(), f"acct:{email.lower()}".encode(), hashlib.sha256).hexdigest()[:32],
                           known_account=known, success=success, reason=reason,
                           agent_hash=hashlib.sha256((request.headers.get("user-agent") or "").encode()).hexdigest()[:16]))

@app.post("/api/auth/login")
def login(body: LoginBody, request: Request, response: Response, session: Session = Depends(db)):
    try:
        rate_limited(request, "login", 20, 60)
    except HTTPException:
        record_login(session, request, body.email, False, False, "rate_limited"); session.commit()
        raise
    require_same_origin(request)
    user = session.scalar(select(User).where(User.email == body.email.lower()))
    if user: current_workspace.set(user.workspace)  # telemetry + audit rows land in the account's workspace
    if not user or not user.is_active:
        record_login(session, request, body.email, bool(user), False, "unknown_account" if not user else "inactive"); session.commit()
    # One generic error for unknown accounts, suspended accounts and stale challenges (no enumeration).
        raise HTTPException(401, "invalid credentials or expired challenge")
    if not consume_token(session, "login_challenge", body.nonce, user_id=user.id):
        record_login(session, request, body.email, True, False, "stale_challenge")
        session.commit(); raise HTTPException(401, "invalid credentials or expired challenge")
    try: verifier_b64 = decrypt_verifier(user.verifier_ciphertext).decode()
    except Exception: raise HTTPException(500, "credential store error")
    if not verify_verifier_hash(user.verifier_hash, verifier_b64): raise HTTPException(500, "credential integrity failure")
    expected = hmac_hex(b64d(verifier_b64), body.nonce)
    if not hmac.compare_digest(expected, body.proof):
        audit(session, user.id, "LOGIN_FAILED", severity="WARN"); record_login(session, request, body.email, True, False, "bad_password"); session.commit()
        raise HTTPException(401, "invalid credentials")
    if user.mfa_enabled:
        if not body.otp or not user.mfa_secret or not verify_totp(user.mfa_secret, body.otp):
            record_login(session, request, body.email, True, False, "mfa_failed"); session.commit(); raise HTTPException(401, "mfa verification required")
    if (user.kdf_version or 1) < 2 and body.upgrade is not None:
        # The legacy proof was valid; move to the bound credential (derived from the value checked below).
        salt, watch_salt, prefix, watch = b64d(user.salt_b64), *_material(body.upgrade)[1:]
        bw.install(user, salt, watch_salt, prefix, watch)
        audit(session, user.id, "CREDENTIAL_UPGRADED", meta={"kdf": 2})
    if not user.breach_locked:
        run_breach_check(session, user, fresh=True)   # the server itself re-checks the password at every sign-in, uncached
    if user.breach_locked:
        record_login(session, request, body.email, True, False, "breach_locked"); session.commit()
        raise HTTPException(423, locked_detail(user))
    record_login(session, request, body.email, True, True, "ok")
    return start_session(session, response, user, "password")

def start_session(session: Session, response: Response, user: User, method: str) -> dict:
    """Create a server-side session and set the session + CSRF cookies (shared by password and passkey sign-in)."""
    tok = new_session_token(); rec=DbSession(id=uid(), user_id=user.id, token_hash=token_hash(tok), csrf_token=csrf_token(), expires_at=session_expiry())
    user.last_login_at=_now(); session.add(rec); audit(session,user.id,"LOGIN_SUCCESS",meta={"method":method}); session.commit()
    response.set_cookie("pp_session", tok, **cookie_kwargs(), max_age=60*60)
    # The CSRF cookie now mirrors the session-bound token so the browser can echo it.
    response.set_cookie("pp_csrf", rec.csrf_token, httponly=False, secure=COOKIE_SECURE, samesite="lax", path="/")
    return {"ok":True,"email":user.email,"role":user.role,"mfa_enabled":user.mfa_enabled,"csrf":rec.csrf_token,"method":method,
            "must_change_password":False,"breach_locked":bool(user.breach_locked),"workspace":user.workspace}


@app.post("/api/auth/mfa/setup")
def mfa_setup(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session); require_same_origin(request)
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already enabled; disable it with a valid code before enrolling a new authenticator")
    secret=new_totp_secret()
    user.mfa_secret=secret; session.commit()
    issuer="PrivPass Shield"; uri=f"otpauth://totp/{issuer}:{user.email}?secret={secret}&issuer={issuer}&digits=6&period=30"
    return {"secret":secret,"otpauth_uri":uri}

class MfaCodeBody(BaseModel):
    code: str

@app.post("/api/auth/mfa/enable")
def mfa_enable(body:MfaCodeBody, request:Request, session:Session=Depends(db)):
    user,_=get_current_session(request,session)
    if not user.mfa_secret or not verify_totp(user.mfa_secret, body.code): raise HTTPException(400,"invalid MFA code")
    user.mfa_enabled=True; audit(session,user.id,"MFA_ENABLED"); session.commit(); return {"ok":True}

@app.post("/api/auth/mfa/disable")
def mfa_disable(body:MfaCodeBody, request:Request, session:Session=Depends(db)):
    user,_=get_current_session(request,session)
    if not user.mfa_secret or not verify_totp(user.mfa_secret, body.code): raise HTTPException(400,"invalid MFA code")
    user.mfa_enabled=False; user.mfa_secret=None; audit(session,user.id,"MFA_DISABLED"); session.commit(); return {"ok":True}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response, session: Session = Depends(db)):
    require_same_origin(request)
    try: user, rec = get_current_session(request, session); rec.revoked_at=_now(); audit(session,user.id,"LOGOUT"); session.commit()
    except HTTPException: pass
    response.delete_cookie("pp_session", path="/")
    response.set_cookie("pp_csrf", secrets.token_urlsafe(32), httponly=False, secure=COOKIE_SECURE, samesite="lax", path="/")
    return {"ok":True}

@app.get("/api/auth/me")
def me(request: Request, session: Session = Depends(db)):
    user, rec=get_current_session(request, session)
    from .models import Passkey
    passkeys = session.scalar(select(func.count(Passkey.id)).where(Passkey.user_id == user.id)) or 0
    return {"email":user.email,"role":user.role,"mfa_enabled":user.mfa_enabled,"csrf":rec.csrf_token,"vault_salt_b64":user.vault_salt_b64,
            "must_change_password":False,"breach_locked":bool(user.breach_locked),"breach_flag_source":user.breach_flag_source,"passkeys":passkeys,
            "breach_checked_at":user.breach_checked_at.isoformat() if user.breach_checked_at else None,"breach_check_status":user.breach_check_status,
            "password_changed_at":user.password_changed_at.isoformat() if user.password_changed_at else None,
            "workspace":user.workspace}

@app.post("/api/auth/reset/request")
def reset_request(body: ResetRequestBody, request: Request, session: Session = Depends(db)):
    rate_limited(request,"reset",8,300); require_same_origin(request)
    user=session.scalar(select(User).where(User.email==body.email.lower()))
    token=None
    if user and user.workspace == DEMO:
        raise HTTPException(403, "Demo accounts are shared, so password reset is disabled. Create your own account to try the reset flow.")
    if user:
        token=issue_token(session, "password_reset", RESET_MINUTES*60, user_id=user.id)
        audit(session, user.id, "PASSWORD_RESET_REQUESTED")
        session.commit()
    # Same response either way. Demo mode returns the token; production would email it.
    return {"ok":True,"demo_token": token if user and APP_ENV!="production" else None}

@app.post("/api/auth/reset/complete")
def reset_complete(body: ResetCompleteBody, request: Request, session: Session = Depends(db)):
    rate_limited(request,"reset-complete",8,300); require_same_origin(request)
    if not consume_token(session, "breach_gate_reset", body.breach_gate.ticket):
        raise HTTPException(400, "breach check ticket missing, expired or already used")
    try:
        _policy_gate(body.breach_gate, body.breached)
        material = _material(body)
        _server_breach_check(*material, body.breach_gate)
    except HTTPException as exc:
        gate_event(session, user_id=None, event_type="reset_blocked", breached=body.breached or body.breach_gate.hibp_status == "breached" or exc.detail == BREACHED_MSG, score=body.score, score_label=body.score_label, guess_log10=0)
        audit(session, None, "BREACH_GATE_REJECTED", severity="WARN", meta={"purpose": "reset", "reason": exc.detail})
        session.commit()
        raise
    item=consume_token(session, "password_reset", body.token)
    if not item: session.commit(); raise HTTPException(400,"invalid or expired reset token")
    user=session.get(User,item.user_id)
    if not user: raise HTTPException(400,"invalid reset target")
    if user.workspace == DEMO: raise HTTPException(403, "Demo accounts are shared, so password reset is disabled.")
    current_workspace.set(user.workspace)
    bw.install(user, *material); user.vault_salt_b64=b64e(secrets.token_bytes(16)); user.vault_check_ciphertext=None
    was_locked = bool(user.breach_locked)
    user.breach_locked=False; user.breach_locked_at=None; user.breach_count=0; user.breach_flag_source=None
    user.breach_checked_at=_now(); user.breach_check_status="safe"; user.password_changed_at=_now()
    session.query(DbSession).filter(DbSession.user_id==user.id,DbSession.revoked_at.is_(None)).update({DbSession.revoked_at:_now()})
    # Zero-knowledge vaults cannot be re-encrypted during a forgot-password reset because the old master secret is unavailable.
    # We therefore invalidate the encrypted blobs instead of weakening the design by adding a server-side recovery key.
    session.query(VaultItem).filter(VaultItem.owner_user_id==user.id).delete(synchronize_session=False)
    session.add(PasswordEvent(id=uid(),user_id=user.id,event_type="reset",breached=False,score=body.score,score_label=body.score_label,guess_log10=0))
    audit(session,user.id,"PASSWORD_RESET",meta={"breach_gate":"passed (server-verified)","unlocked":was_locked}); session.commit()
    return {"ok":True}



class VaultBlobBody(BaseModel):
    ciphertext_b64: str = Field(min_length=40, max_length=200000)

@app.get("/api/vault/config")
def vault_config(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    if not user.vault_salt_b64:
        user.vault_salt_b64 = b64e(secrets.token_bytes(16)); session.commit()
    return {"vault_salt_b64": user.vault_salt_b64, "vault_check_ciphertext": user.vault_check_ciphertext, "auth_salt_b64": user.salt_b64, "auth_watch_salt_b64": user.watch_salt_b64, "auth_kdf": user.kdf_version or 1, "kdf": "PBKDF2-SHA-256", "iterations": 600000, "cipher": "AES-GCM-256"}

@app.post("/api/vault/challenge")
def vault_challenge(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    nonce = issue_token(session, "vault_challenge", 120, user_id=user.id)
    session.commit()
    return {"nonce": nonce}

class VaultUnlockBody(BaseModel):
    proof: str
    nonce: str

@app.post("/api/vault/unlock")
def vault_unlock(body: VaultUnlockBody, request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session); require_same_origin(request); rate_limited(request, "vault-unlock", 10, 300)
    challenge_nonce = body.nonce
    if not consume_token(session, "vault_challenge", challenge_nonce, user_id=user.id):
        session.commit(); raise HTTPException(401, "vault challenge expired")
    try:
        verifier_b64 = decrypt_verifier(user.verifier_ciphertext).decode()
    except Exception:
        raise HTTPException(500, "credential store error")
    expected = hmac_hex(b64d(verifier_b64), challenge_nonce)
    if not hmac.compare_digest(expected, body.proof):
        audit(session, user.id, "VAULT_UNLOCK_FAILED", severity="WARN"); session.commit()
        raise HTTPException(401, "vault unlock failed")
    session.commit()
    return {"ok": True, "vault_salt_b64": user.vault_salt_b64, "vault_check_ciphertext": user.vault_check_ciphertext, "iterations": 600000, "cipher": "AES-GCM-256"}

class VaultCheckBody(BaseModel):
    ciphertext_b64: str = Field(min_length=40, max_length=12000)

@app.put("/api/vault/check")
def vault_check(body: VaultCheckBody, request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session); require_same_origin(request)
    if user.vault_check_ciphertext:
        return {"ok": True, "stored": True}
    user.vault_check_ciphertext = body.ciphertext_b64
    audit(session, user.id, "VAULT_CHECK_INITIALIZED", severity="INFO")
    session.commit()
    return {"ok": True, "stored": True}

@app.get("/api/vault/items")
def vault_items(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    rows = session.scalars(select(VaultItem).where(VaultItem.owner_user_id == user.id).order_by(desc(VaultItem.updated_at))).all()
    # Only opaque ciphertext and timestamps leave the server. The server never receives titles/usernames/passwords.
    return [{"id": r.id, "ciphertext_b64": r.ciphertext_b64, "version": r.version, "created_at": r.created_at.isoformat(), "updated_at": r.updated_at.isoformat()} for r in rows]

@app.post("/api/vault/items")
def vault_item_create(body: VaultBlobBody, request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session); require_same_origin(request); rate_limited(request, "vault-write", 120, 60)
    item = VaultItem(id=uid(), owner_user_id=user.id, ciphertext_b64=body.ciphertext_b64, version=1)
    session.add(item); audit(session, user.id, "VAULT_ITEM_CREATED", severity="INFO"); session.commit()
    return {"id": item.id, "created_at": item.created_at.isoformat(), "updated_at": item.updated_at.isoformat()}

@app.put("/api/vault/items/{item_id}")
def vault_item_update(item_id: str, body: VaultBlobBody, request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session); require_same_origin(request); rate_limited(request, "vault-write", 120, 60)
    item = session.get(VaultItem, item_id)
    if not item or item.owner_user_id != user.id: raise HTTPException(404, "vault item not found")
    item.ciphertext_b64 = body.ciphertext_b64; item.version += 1; item.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    audit(session, user.id, "VAULT_ITEM_UPDATED", severity="INFO"); session.commit()
    return {"ok": True, "updated_at": item.updated_at.isoformat()}

@app.delete("/api/vault/items/{item_id}")
def vault_item_delete(item_id: str, request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session); require_same_origin(request); rate_limited(request, "vault-write", 120, 60)
    item = session.get(VaultItem, item_id)
    if not item or item.owner_user_id != user.id: raise HTTPException(404, "vault item not found")
    session.delete(item); audit(session, user.id, "VAULT_ITEM_DELETED", severity="INFO"); session.commit()
    return {"ok": True}

class PasswordEventBody(BaseModel):
    event_type: str = "analysis"
    breached: bool = False
    score: int = Field(ge=0, le=100)
    score_label: str
    guess_log10: float = 0.0

@app.post("/api/password-event")
def password_event(body: PasswordEventBody, request: Request, session: Session = Depends(db)):
    # Metadata only: never accept/store a password or password hash here.
    user_id = None
    try:
        user,_ = get_current_session(request, session)
        user_id = user.id
    except HTTPException:
        pass
    session.add(PasswordEvent(id=uid(), user_id=user_id, event_type=body.event_type, breached=body.breached, score=body.score, score_label=body.score_label, guess_log10=body.guess_log10))
    session.commit()
    return {"ok": True}

from .features import sla_info, sla_metrics, stamp_transition, honeytoken_fingerprints  # noqa: E402
from .notify import notify  # noqa: E402


def _finding_json(f: SecretFinding) -> dict:
    return {"id": f.id, "scan_id": f.scan_id, "file": f.file_path, "line": f.line_no, "type": f.secret_type, "secret_type": f.secret_type,
            "severity": f.severity, "confidence": f.confidence, "entropy": f.entropy, "validity": f.validity, "preview": f.redacted_preview,
            "reason": f.reason or _finding_reason(f.secret_type, f.severity), "status": f.status or "DETECTED", "kind": f.kind or "secret",
            "commit": f.commit_sha, "author": f.commit_author, "commit_date": f.commit_date, "commits_seen": f.commits_seen or 0,
            "in_head": f.in_head, "ml_probability": f.ml_probability, "ml_reasons": json.loads(f.ml_reasons_json or "[]"),
            "context": f.context_masked or "", "ai_verdict": f.ai_verdict, "ai_reason": f.ai_reason, "sla": sla_info(f),
            "updated_at": f.updated_at.isoformat() if f.updated_at else None}

def _persist_scan(session: Session, user: User, repo_name: str, count: int, findings) -> tuple[Scan, list[SecretFinding]]:
    from dataclasses import replace as _replace
    baits = honeytoken_fingerprints(session)
    findings = [_replace(f, severity="LOW", confidence=0.2, validity="HONEYTOKEN", reason=f"This is your honeytoken “{baits[f.fingerprint].label}” - leave it in place; any use of it raises an alert")
                if f.fingerprint in baits else f for f in findings]
    scan = Scan(id=uid(), owner_user_id=user.id, repo_name=repo_name, file_count=count, finding_count=len(findings))
    session.add(scan)
    rows = []
    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    if crit:
        notify(session, "scan", f"{crit} CRITICAL secret(s) found in {repo_name}", f"Fix deadline: {4} hours each. Rotate at the provider, then move each finding to ROTATED.", "CRITICAL", "secrets", user_id=user.id)
    for f in findings:
        row = SecretFinding(id=uid(), scan_id=scan.id, owner_user_id=user.id, file_path=f.file_path, line_no=f.line_no, secret_type=f.secret_type,
                            severity=f.severity, confidence=f.confidence, fingerprint=f.fingerprint, redacted_preview=f.redacted_preview,
                            reason=f.reason, entropy=f.entropy, validity=f.validity, kind=f.kind, commit_sha=f.commit, commit_author=f.author,
                            commit_date=f.commit_date, commits_seen=f.commits_seen, in_head=f.in_head,
                            ml_probability=f.ml_probability, ml_reasons_json=json.dumps(list(f.ml_reasons)), context_masked=f.context)
        session.add(row); rows.append(row)
    return scan, rows

def _scan_response(scan: Scan, rows: list[SecretFinding]) -> dict:
    return {"scan_id": scan.id, "files": scan.file_count, "history_only": sum(1 for r in rows if r.in_head is False),
            "risky_code": sum(1 for r in rows if r.kind == "code"), "findings": [_finding_json(r) for r in rows]}

@app.post("/api/judge/demo-scan")
def judge_demo_scan(request: Request, session: Session = Depends(db)):
    user,_=get_current_session(request,session)
    if user.role!="admin": raise HTTPException(403,"admin required")
    demo_root=ROOT/"data"/"demo-repo"
    findings,count=scan_dir(demo_root,APP_SECRET[:24])
    scan,rows=_persist_scan(session,user,"PrivPass Demo Repository",count,findings)
    audit(session,user.id,"JUDGE_DEMO_SCAN",severity="HIGH",meta={"files":count,"findings":len(findings)})
    session.commit()
    return _scan_response(scan,rows)

@app.post("/api/scans/upload")
async def upload_scan(request: Request, file: UploadFile = File(...), session: Session = Depends(db)):
    user,_=get_current_session(request,session)
    require_same_origin(request); rate_limited(request,"scan",10,60)
    if not file.filename or not file.filename.lower().endswith(".zip"): raise HTTPException(400,"upload a ZIP repository")
    data=await file.read()
    if len(data)>MAX_SCAN_MB*1024*1024: raise HTTPException(413,"archive too large")
    try:
        findings, count=scan_zip(data, APP_SECRET[:24])
    except (zipfile.BadZipFile, ValueError) as exc:
        raise HTTPException(400, f"could not scan archive: {exc}")
    scan,rows=_persist_scan(session,user,file.filename,count,findings)
    history_only=sum(1 for f in findings if f.in_head is False)
    audit(session,user.id,"REPOSITORY_SCAN",severity="HIGH" if any(x.severity=="CRITICAL" for x in findings) else "INFO",meta={"files":count,"findings":len(findings),"history_only":history_only})
    session.commit()
    return _scan_response(scan,rows)

@app.get("/api/scans")
def scans(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session)
    rows=session.scalars(select(Scan).where(Scan.owner_user_id==user.id).order_by(desc(Scan.created_at)).limit(25)).all()
    return [{"id":r.id,"repo_name":r.repo_name,"files":r.file_count,"findings":r.finding_count,"created_at":r.created_at.isoformat()} for r in rows]

def _finding_reason(secret_type: str, severity: str) -> str:
    known = {
        "AWS access key": "Recognized provider credential format; treat as exposed until rotated.",
        "GitHub token": "Recognized source-control credential format; repository exposure can enable account or CI abuse.",
        "Stripe secret key": "Recognized payment credential format; rotate/revoke before merge.",
        "Private key": "Private key material can enable impersonation; containment and rotation are mandatory.",
        "Connection string": "Contains service credentials or connection material; redact and rotate before deployment.",
        "JWT": "Token-like bearer credential detected in source code.",
    }
    return known.get(secret_type, f"{severity.title()} secret-like material detected with contextual analysis.")

def _severity_weight(severity: str) -> int:
    return {"CRITICAL": 45, "HIGH": 30, "MEDIUM": 15}.get((severity or "MEDIUM").upper(), 10)

def _scan_for_user(session: Session, user_id: str):
    return session.scalar(
        select(Scan)
        .where(Scan.owner_user_id == user_id)
        .order_by(desc(Scan.created_at))
        .limit(1)
    )

@app.get("/api/exposure/graph")
def exposure_graph(request: Request, session: Session = Depends(db)):
    """Build the exposure view from the user's latest persisted telemetry.

    The graph deliberately reuses existing PasswordEvent, Scan, SecretFinding and
    Session records rather than introducing a second copy of the same security data.
    """
    user, _ = get_current_session(request, session)
    latest_scan = _scan_for_user(session, user.id)
    latest_findings = []
    if latest_scan:
        latest_findings = session.scalars(
            select(SecretFinding)
            .where(SecretFinding.owner_user_id == user.id, SecretFinding.scan_id == latest_scan.id)
            .order_by(desc(SecretFinding.confidence), desc(SecretFinding.created_at))
        ).all()

    latest_password = session.scalar(
        select(PasswordEvent)
        .where(PasswordEvent.user_id == user.id)
        .order_by(desc(PasswordEvent.created_at))
        .limit(1)
    )
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_sessions = session.scalar(
        select(func.count(DbSession.id)).where(
            DbSession.user_id == user.id,
            DbSession.revoked_at.is_(None),
            DbSession.expires_at > now,
        )
    ) or 0

    critical = sum(1 for f in latest_findings if f.severity == "CRITICAL")
    high = sum(1 for f in latest_findings if f.severity == "HIGH")
    medium = sum(1 for f in latest_findings if f.severity == "MEDIUM")
    status_counts = {status: sum(1 for f in latest_findings if (f.status or "DETECTED") == status) for status in _FINDING_STATUSES}

    highest = latest_findings[0] if latest_findings else None
    confidence = round(float(max((f.confidence for f in latest_findings), default=0.0)) * 100)
    secret_risk = min(70, critical * 7 + high * 4 + medium * 1)
    password_risk = 25 if latest_password and latest_password.breached else 0
    mfa_risk = 0 if user.mfa_enabled else 8
    risk_score = min(99, secret_risk + password_risk + mfa_risk)
    risk_label = "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 50 else "ELEVATED" if risk_score >= 25 else "GUARDED"
    affected_files = len({f.file_path for f in latest_findings})
    blast_radius = affected_files + active_sessions
    completed = status_counts.get("CONTAINED", 0) + status_counts.get("ROTATED", 0) + status_counts.get("VERIFIED", 0)
    password_text = "No password telemetry yet"
    if latest_password:
        state = "BREACHED" if latest_password.breached else latest_password.score_label.upper()
        password_text = f"{state} · {latest_password.score}/100"

    return {
        "account": {"label": "Account", "value": user.email},
        "password": {"label": "Password", "value": password_text},
        "repository": {"label": "Repository", "value": latest_scan.repo_name if latest_scan else "No repository scan yet"},
        "secret": {"label": "Secret", "value": f"{highest.secret_type} · {len(latest_findings)} findings" if highest else "No active secret finding"},
        "sessions": {"label": "Sessions", "value": f"{active_sessions} active"},
        "mfa": {"label": "MFA", "value": "Enabled" if user.mfa_enabled else "Not enabled"},
        "risk": risk_label,
        "risk_score": risk_score,
        "confidence": confidence,
        "blast_radius": blast_radius,
        "affected_files": affected_files,
        "remediation_completed": completed,
        "remediation_total": len(latest_findings),
        "scan": {
            "id": latest_scan.id if latest_scan else None,
            "repo_name": latest_scan.repo_name if latest_scan else None,
            "files": latest_scan.file_count if latest_scan else 0,
            "findings": latest_scan.finding_count if latest_scan else 0,
            "created_at": latest_scan.created_at.isoformat() if latest_scan else None,
        },
        "severity": {"critical": critical, "high": high, "medium": medium},
        "status": status_counts,
        **exposure_map.build(session, user),
    }

_FINDING_STATUSES = ("DETECTED", "TRIAGED", "CONTAINED", "ROTATED", "VERIFIED")

@app.get("/api/incidents")
def incidents(request: Request, session: Session = Depends(db)):
    """Return incident-center cards from findings in the user's latest scan."""
    user, _ = get_current_session(request, session)
    latest_scan = _scan_for_user(session, user.id)
    if not latest_scan:
        return {"scan": None, "total": 0, "counts": {status: 0 for status in _FINDING_STATUSES}, "incidents": []}

    count_rows = session.execute(
        select(SecretFinding.status, func.count(SecretFinding.id))
        .where(SecretFinding.owner_user_id == user.id, SecretFinding.scan_id == latest_scan.id)
        .group_by(SecretFinding.status)
    ).all()
    counts = {status: 0 for status in _FINDING_STATUSES}
    for status, count in count_rows:
        normalized = status or "DETECTED"
        counts[normalized if normalized in counts else "DETECTED"] += int(count)

    rows = session.execute(
        select(SecretFinding)
        .where(SecretFinding.owner_user_id == user.id, SecretFinding.scan_id == latest_scan.id)
        .order_by(desc(SecretFinding.confidence), desc(SecretFinding.created_at))
        .limit(250)
    ).scalars().all()
    result = []
    for finding in rows:
        status = finding.status or "DETECTED"
        if status not in counts:
            status = "DETECTED"
        result.append({
            "id": finding.id,
            "scan_id": finding.scan_id,
            "repo_name": latest_scan.repo_name,
            "type": finding.secret_type,
            "severity": finding.severity,
            "confidence": round(float(finding.confidence) * 100),
            "entropy": round(float(finding.entropy), 2),
            "validity": finding.validity,
            "file": finding.file_path,
            "line": finding.line_no,
            "preview": finding.redacted_preview,
            "reason": finding.reason or _finding_reason(finding.secret_type, finding.severity),
            "status": status,
            "kind": finding.kind or "secret",
            "commit": finding.commit_sha,
            "in_head": finding.in_head,
            "sla": sla_info(finding),
            "updated_at": finding.updated_at.isoformat(),
        })
    return {
        "scan": {"id": latest_scan.id, "repo_name": latest_scan.repo_name, "files": latest_scan.file_count, "findings": latest_scan.finding_count, "created_at": latest_scan.created_at.isoformat()},
        "total": latest_scan.finding_count,
        "counts": counts,
        "incidents": result,
    }

@app.get("/api/findings")
def findings(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session)
    rows=session.scalars(select(SecretFinding).where(SecretFinding.owner_user_id==user.id).order_by(desc(SecretFinding.created_at)).limit(100)).all()
    return [_finding_json(r) for r in rows]

_FINDING_NEXT_STATUS = {
    "DETECTED": "TRIAGED",
    "TRIAGED": "CONTAINED",
    "CONTAINED": "ROTATED",
    "ROTATED": "VERIFIED",
}

async def _parse_transition_status(request: Request) -> str:
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        payload = await request.json()
        status = payload.get("status") if isinstance(payload, dict) else None
    else:
        form = await request.form()
        status = form.get("status")
    if not isinstance(status, str):
        raise HTTPException(422, "status is required")
    return status.strip().upper()

def _apply_finding_transition(finding_id: str, status: str, request: Request, session: Session):
    user,_=get_current_session(request,session); require_same_origin(request)
    f=session.get(SecretFinding,finding_id)
    if not f or f.owner_user_id!=user.id: raise HTTPException(404,"finding not found")
    current = f.status or "DETECTED"
    if current == status:
        return {"ok":True,"status":current,"unchanged":True}
    expected = _FINDING_NEXT_STATUS.get(current)
    if expected != status:
        raise HTTPException(409, f"invalid lifecycle transition: {current} -> {status}; expected {expected or 'none'}")
    f.status=status; f.updated_at=datetime.now(timezone.utc).replace(tzinfo=None); stamp_transition(f, status)
    audit(session,user.id,"FINDING_TRANSITION",meta={"finding_id":f.id,"from":current,"status":status})
    session.commit()
    return {"ok":True,"status":status,"from":current}

@app.post("/api/findings/{finding_id}/transition")
async def finding_transition(finding_id: str, request: Request, session: Session=Depends(db)):
    status = await _parse_transition_status(request)
    return _apply_finding_transition(finding_id, status, request, session)

@app.patch("/api/findings/{finding_id}/transition")
async def finding_transition_patch(finding_id: str, request: Request, session: Session=Depends(db)):
    status = await _parse_transition_status(request)
    return _apply_finding_transition(finding_id, status, request, session)

GATE_EVENTS = ("signup", "signup_blocked", "reset", "reset_blocked")

def _latest_account_audit(session: Session) -> dict | None:
    row = session.scalar(select(AccountAuditReport).order_by(desc(AccountAuditReport.created_at)).limit(1))
    if not row:
        return None
    verified = max(0, row.total - row.unverified)
    return {"id": row.id, "source_name": row.source_name, "total": row.total, "breached": row.breached,
            "unverified": row.unverified, "below_policy": row.below_policy, "hibp_mode": row.hibp_mode,
            "breached_percent": round(row.breached / verified * 100, 1) if verified else 0.0,
            "created_at": row.created_at.isoformat()}

def _gate_stats(session: Session) -> dict:
    attempts = session.scalar(select(func.count(PasswordEvent.id)).where(PasswordEvent.event_type.in_(GATE_EVENTS))) or 0
    blocked = session.scalar(select(func.count(PasswordEvent.id)).where(PasswordEvent.event_type.in_(("signup_blocked", "reset_blocked")))) or 0
    breached = session.scalar(select(func.count(PasswordEvent.id)).where(PasswordEvent.event_type.in_(GATE_EVENTS), PasswordEvent.breached.is_(True))) or 0
    return {"attempts": attempts, "blocked": blocked, "breached": breached,
            "breached_percent": round(breached / attempts * 100, 2) if attempts else 0.0}

@app.get("/api/admin/overview")
def admin_overview(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    if user.role != "admin":
        raise HTTPException(403, "admin required")
    gate = _gate_stats(session)
    findings_count = session.scalar(select(func.count(SecretFinding.id))) or 0
    critical = session.scalar(select(func.count(SecretFinding.id)).where(SecretFinding.severity == "CRITICAL")) or 0
    high = session.scalar(select(func.count(SecretFinding.id)).where(SecretFinding.severity == "HIGH")) or 0
    open_critical = session.scalar(select(func.count(SecretFinding.id)).where(SecretFinding.severity == "CRITICAL", SecretFinding.status.in_(("DETECTED", "TRIAGED")))) or 0
    users = session.scalar(select(func.count(User.id))) or 0
    mfa = session.scalar(select(func.count(User.id)).where(User.mfa_enabled.is_(True))) or 0
    avg_score = session.scalar(select(func.avg(PasswordEvent.score)).where(PasswordEvent.event_type.in_(("signup", "reset")))) or 0
    posture = max(0, min(100, 94 - open_critical * 4 - high * 1.5 + mfa * 3))
    all_rows = session.scalars(select(SecretFinding)).all()
    from .models import Honeytoken
    trips = sum(h.trips for h in session.scalars(select(Honeytoken)))
    return {
        "sla": sla_metrics(all_rows),
        "honeytoken_trips": trips,
        "password_events": gate["attempts"],
        "breached_attempt_percent": gate["breached_percent"],
        "gate": gate,
        "account_audit": _latest_account_audit(session),
        "secret_findings": findings_count,
        "critical_findings": critical,
        "high_findings": high,
        "user_count": users,
        "mfa_adoption_percent": round((mfa / users * 100) if users else 0, 1),
        "average_password_score": round(float(avg_score), 1),
        "control_posture": round(posture, 1),
    }

class AccountAuditBody(BaseModel):
    source_name: str = Field(min_length=1, max_length=200)
    total: int = Field(ge=1, le=1_000_000)
    breached: int = Field(ge=0)
    unverified: int = Field(ge=0)
    below_policy: int = Field(ge=0)
    hibp_mode: str = "live"

@app.post("/api/audit/accounts")
def account_audit_create(body: AccountAuditBody, request: Request, session: Session = Depends(db)):
    """Store the aggregate result of a browser-side test-account audit. Counts only."""
    user, _ = get_current_session(request, session); require_same_origin(request)
    if user.role not in {"admin", "analyst"}: raise HTTPException(403, "admin or analyst required")
    if body.breached + body.unverified > body.total or body.below_policy > body.total: raise HTTPException(400, "inconsistent counts")
    if body.hibp_mode not in {"live", "offline-demo", "mixed", "unavailable"}: raise HTTPException(400, "invalid mode")
    row = AccountAuditReport(id=uid(), owner_user_id=user.id, source_name=body.source_name, total=body.total, breached=body.breached,
                             unverified=body.unverified, below_policy=body.below_policy, hibp_mode=body.hibp_mode)
    session.add(row)
    audit(session, user.id, "ACCOUNT_BREACH_AUDIT", severity="HIGH" if body.breached else "INFO",
          meta={"source": body.source_name, "total": body.total, "breached": body.breached, "unverified": body.unverified})
    session.commit()
    return _latest_account_audit(session)

@app.get("/api/audit/accounts/latest")
def account_audit_latest(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    if user.role not in {"admin", "analyst"}: raise HTTPException(403, "admin or analyst required")
    return {"report": _latest_account_audit(session)}

@app.get("/api/admin/audit")
def admin_audit(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session)
    if user.role!="admin": raise HTTPException(403,"admin required")
    rows=session.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(100)).all()
    return [{"event":r.event_type,"severity":r.severity,"created_at":r.created_at.isoformat(),"meta":json.loads(r.metadata_json or "{}")} for r in rows]

@app.get("/api/admin/report.csv")
def admin_csv(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session)
    if user.role!="admin": raise HTTPException(403,"admin required")
    gate=_gate_stats(session); rep=_latest_account_audit(session) or {}
    lines=["metric,value",
           "breach_gate_attempts,%d" % gate["attempts"], "breach_gate_blocked,%d" % gate["blocked"], "breach_gate_breached_percent,%s" % gate["breached_percent"],
           "test_account_audit_source,%s" % str(rep.get("source_name","none")).replace(",", " "), "test_account_total,%s" % rep.get("total",0),
           "test_account_breached,%s" % rep.get("breached",0), "test_account_unverified,%s" % rep.get("unverified",0),
           "test_account_breached_percent,%s" % rep.get("breached_percent",0), "test_account_hibp_mode,%s" % rep.get("hibp_mode","n/a"),
           "secret_findings,%d" % (session.scalar(select(func.count(SecretFinding.id))) or 0)]
    return Response("\n".join(lines), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=privpass-report.csv"})

@app.get("/api/admin/policy")
def policy_get(request: Request, session: Session=Depends(db)):
    user,_=get_current_session(request,session)
    if user.role!="admin": raise HTTPException(403)
    return {"min_length":15,"block_breached":True,"require_mfa":False,"max_scan_mb":MAX_SCAN_MB,"secret_block_threshold":"HIGH"}


@app.get("/api/demo/info")
def demo_info():
    if not cfg.demo_enabled():
        return {"demo_mode": False}
    from .bootstrap import DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD, DEMO_ANALYST_EMAIL, DEMO_ANALYST_PASSWORD, DEMO_USER_EMAIL, DEMO_USER_PASSWORD
    return {
        "demo_mode": True,
        "admin": {"email": DEMO_ADMIN_EMAIL, "password": DEMO_ADMIN_PASSWORD, "role": "admin", "mfa": "disabled for demo"},
        "analyst": {"email": DEMO_ANALYST_EMAIL, "password": DEMO_ANALYST_PASSWORD, "role": "analyst", "mfa": "disabled for demo"},
        "user": {"email": DEMO_USER_EMAIL, "password": DEMO_USER_PASSWORD, "role": "user", "mfa": "disabled for demo"},
        "demo_repository": "/api/demo/repository.zip",
        "safe_for_demo": True,
    }

@app.get("/api/demo/repository.zip")
def demo_repository():
    if not cfg.demo_enabled():
        raise HTTPException(404, "demo assets disabled in production")
    demo = ROOT / "demo-assets" / "PrivPass-Demo-Leak-Repo.zip"
    if not demo.exists():
        raise HTTPException(404, "demo repository not packaged")
    return FileResponse(demo, media_type="application/zip", filename="PrivPass-Demo-Leak-Repo.zip")

@app.get("/api/demo/history-repository.zip")
def demo_history_repository():
    if not cfg.demo_enabled():
        raise HTTPException(404, "demo assets disabled in production")
    demo = ROOT / "demo-assets" / "PrivPass-History-Leak-Repo.zip"
    if not demo.exists():
        raise HTTPException(404, "history demo repository not packaged (run tools/build_demo_assets.py)")
    return FileResponse(demo, media_type="application/zip", filename="PrivPass-History-Leak-Repo.zip")

@app.get("/api/demo/sample-accounts.csv")
def demo_sample_accounts():
    if not cfg.demo_enabled():
        raise HTTPException(404, "demo assets disabled in production")
    return FileResponse(ROOT / "data" / "sample-accounts.csv", media_type="text/csv", filename="sample-accounts.csv")

@app.get("/api/admin/users")
def admin_users(request: Request, session: Session = Depends(db)):
    user, _ = get_current_session(request, session)
    if user.role != "admin":
        raise HTTPException(403, "admin required")
    rows = session.scalars(select(User).order_by(User.created_at.asc())).all()
    return [{
        "id": r.id,
        "email": r.email,
        "role": r.role,
        "mfa_enabled": r.mfa_enabled,
        "active": r.is_active,
        "created_at": r.created_at.isoformat(),
        "last_login_at": r.last_login_at.isoformat() if r.last_login_at else None,
        "vault_items": session.scalar(select(func.count(VaultItem.id)).where(VaultItem.owner_user_id == r.id)) or 0,
        "breach_locked": bool(r.breach_locked), "breach_check_status": r.breach_check_status,
        "breach_checked_at": r.breach_checked_at.isoformat() if r.breach_checked_at else None,
    } for r in rows]


@app.post("/api/admin/breach-watch/run")
def admin_breach_watch(request: Request, session: Session = Depends(db)):
    """Re-check every account in this workspace now (the same job runs automatically in the background)."""
    admin, _ = get_current_session(request, session); require_same_origin(request); rate_limited(request, "breach-watch", 6, 60)
    if admin.role != "admin": raise HTTPException(403, "admin required")
    stats = breach_watch_sweep(admin.workspace)
    audit(session, admin.id, "BREACH_WATCH_RUN", meta=stats); session.commit()
    return {**stats, "interval_minutes": BREACH_WATCH_MINUTES}


@app.post("/api/admin/users/{user_id}/deactivate")
def admin_deactivate_user(user_id: str, request: Request, session: Session = Depends(db)):
    admin, _ = get_current_session(request, session)
    if admin.role != "admin": raise HTTPException(403, "admin required")
    target = session.get(User, user_id)
    if not target: raise HTTPException(404, "user not found")
    if target.id == admin.id: raise HTTPException(400, "admin cannot deactivate self")
    if admin.workspace == DEMO: raise HTTPException(403, "The demo admin cannot suspend or delete accounts. Sign in with the real admin account to manage users.")
    target.is_active = False
    session.query(DbSession).filter(DbSession.user_id == target.id, DbSession.revoked_at.is_(None)).update({DbSession.revoked_at:datetime.now(timezone.utc).replace(tzinfo=None)})
    audit(session, admin.id, "ADMIN_USER_DEACTIVATED", severity="HIGH", meta={"target": target.email}); session.commit()
    return {"ok": True}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, request: Request, session: Session = Depends(db)):
    admin, _ = get_current_session(request, session)
    if admin.role != "admin": raise HTTPException(403, "admin required")
    target = session.get(User, user_id)
    if not target: raise HTTPException(404, "user not found")
    if target.id == admin.id: raise HTTPException(400, "admin cannot delete self")
    if admin.workspace == DEMO: raise HTTPException(403, "The demo admin cannot suspend or delete accounts. Sign in with the real admin account to manage users.")
    session.query(VaultItem).filter(VaultItem.owner_user_id == target.id).delete(synchronize_session=False)
    session.query(DbSession).filter(DbSession.user_id == target.id).delete(synchronize_session=False)
    session.query(PasswordEvent).filter(PasswordEvent.user_id == target.id).delete(synchronize_session=False)
    session.query(SecretFinding).filter(SecretFinding.owner_user_id == target.id).delete(synchronize_session=False)
    session.query(Scan).filter(Scan.owner_user_id == target.id).delete(synchronize_session=False)
    session.query(AuditEvent).filter(AuditEvent.user_id == target.id).delete(synchronize_session=False)
    email = target.email
    session.delete(target); audit(session, admin.id, "ADMIN_USER_DELETED", severity="CRITICAL", meta={"target": email}); session.commit()
    return {"ok": True}

@app.get("/api/analytics/public")
def public_analytics(session: Session=Depends(db)):
    # Signed-in visitors see their own workspace; anonymous visitors see the demo showcase (live in production).
    with workspace_scope(current_workspace.get() or (DEMO if cfg.demo_enabled() else LIVE)):
        return _public_numbers(session)

def _public_numbers(session: Session) -> dict:
    gate=_gate_stats(session)
    return {"checks":gate["attempts"],"breached_percent":gate["breached_percent"],"blocked":gate["blocked"],"secret_findings":session.scalar(select(func.count(SecretFinding.id))) or 0}

# AI / ML and platform-feature routes must be registered before the SPA catch-all below.
from .ai.routes import router as ai_router  # noqa: E402
from .features import router as features_router  # noqa: E402
from .account import router as account_router  # noqa: E402
from .github import router as github_router  # noqa: E402
app.include_router(ai_router)
app.include_router(account_router)
app.include_router(github_router)
app.include_router(features_router)

@app.get("/{path:path}", response_class=HTMLResponse)
def spa(path: str):
    if path.startswith("api/"): raise HTTPException(404)
    return FileResponse(STATIC / "index.html")
