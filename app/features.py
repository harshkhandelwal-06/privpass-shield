"""6.2 platform features: notifications, honeytokens, fix deadlines (SLA) and time-to-fix metrics."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, or_, select
from sqlalchemy.orm import Session

from .config import APP_SECRET
from .db import db, current_workspace, DEMO
from .models import Honeytoken, HoneytokenTrip, Notification, SecretFinding, User
from .notify import notify
from .scanner import fingerprint as secret_fingerprint
from .security import uid

router = APIRouter()

# ------------------------------------------------------------------ SLA / time-to-fix
SLA_HOURS = {"CRITICAL": 4, "HIGH": 24, "MEDIUM": 24 * 7, "LOW": 24 * 30}
DONE = {"ROTATED", "VERIFIED"}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def sla_info(f: SecretFinding) -> dict:
    hours = SLA_HOURS.get(f.severity, 24 * 7)
    due = f.created_at + timedelta(hours=hours)
    status = f.status or "DETECTED"
    done_at = f.rotated_at if status in DONE else None
    if status in DONE:
        met = bool(done_at and done_at <= due)
        return {"sla_hours": hours, "due_at": due.isoformat(), "state": "met" if met else "missed", "remaining_hours": None}
    remaining = (due - _now()).total_seconds() / 3600
    return {"sla_hours": hours, "due_at": due.isoformat(), "state": "overdue" if remaining < 0 else "at_risk" if remaining < hours * 0.25 else "on_track",
            "remaining_hours": round(remaining, 2)}


def stamp_transition(f: SecretFinding, status: str) -> None:
    now = _now()
    setattr(f, {"TRIAGED": "triaged_at", "CONTAINED": "contained_at", "ROTATED": "rotated_at", "VERIFIED": "verified_at"}[status], now)


def sla_metrics(rows: list[SecretFinding]) -> dict:
    def mean_hours(pairs):
        vals = [(b - a).total_seconds() / 3600 for a, b in pairs if a and b]
        return round(sum(vals) / len(vals), 2) if vals else None
    infos = [sla_info(r) for r in rows]
    closed = [i for i in infos if i["state"] in {"met", "missed"}]
    return {
        "mean_hours_to_contain": mean_hours([(r.created_at, r.contained_at) for r in rows]),
        "mean_hours_to_rotate": mean_hours([(r.created_at, r.rotated_at) for r in rows]),
        "overdue": sum(i["state"] == "overdue" for i in infos),
        "at_risk": sum(i["state"] == "at_risk" for i in infos),
        "sla_compliance_percent": round(sum(i["state"] == "met" for i in closed) / len(closed) * 100, 1) if closed else None,
        "sla_hours": SLA_HOURS,
    }


# ------------------------------------------------------------------ notifications
def _auth(request: Request, session: Session):
    from .main import get_current_session
    return get_current_session(request, session)[0]


def _visible(user: User):
    cond = Notification.user_id == user.id
    return or_(cond, Notification.user_id.is_(None)) if user.role in {"admin", "analyst"} else cond


@router.get("/api/notifications")
def notifications(request: Request, session: Session = Depends(db)):
    user = _auth(request, session)
    rows = session.scalars(select(Notification).where(_visible(user)).order_by(desc(Notification.created_at)).limit(30)).all()
    unread = sum(1 for r in rows if r.read_at is None)
    return {"unread": unread, "items": [{"id": r.id, "kind": r.kind, "severity": r.severity, "title": r.title, "body": r.body, "link": r.link,
                                          "read": r.read_at is not None, "created_at": r.created_at.isoformat()} for r in rows]}


@router.post("/api/notifications/read-all")
def notifications_read(request: Request, session: Session = Depends(db)):
    user = _auth(request, session)
    for r in session.scalars(select(Notification).where(_visible(user), Notification.read_at.is_(None))):
        r.read_at = _now()
    session.commit()
    return {"ok": True}


# ------------------------------------------------------------------ honeytokens
class HoneytokenBody(BaseModel):
    label: str = Field(min_length=2, max_length=120)
    kind: str = "api_key"  # "api_key" | "url"


def _token_hash(raw: str) -> str:
    return hmac.new(APP_SECRET.encode(), f"honeytoken:{raw}".encode(), hashlib.sha256).hexdigest()


def honeytoken_fingerprints(session: Session, owner_id: str | None = None) -> dict[str, Honeytoken]:
    q = select(Honeytoken)
    if owner_id:
        q = q.where(Honeytoken.owner_user_id == owner_id)
    return {h.fingerprint: h for h in session.scalars(q)}


def _base_url(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host', 'localhost')}"


@router.post("/api/honeytokens")
def honeytoken_create(body: HoneytokenBody, request: Request, session: Session = Depends(db)):
    from .main import audit, require_same_origin
    user = _auth(request, session); require_same_origin(request)
    if body.kind not in {"api_key", "url"}:
        raise HTTPException(400, "kind must be api_key or url")
    raw = "ppk_live_" + secrets.token_urlsafe(24).replace("-", "x").replace("_", "y") if body.kind == "api_key" else secrets.token_urlsafe(18)
    base = _base_url(request)
    if body.kind == "api_key":
        snippet = (f"# {body.label}\nBILLING_INTERNAL_API={base}/api/canary/v1\nBILLING_INTERNAL_API_KEY={raw}\n")
        preview = raw[:13] + "…" + raw[-4:]
        value_for_scanner = raw
    else:
        url = f"{base}/c/{raw}"
        snippet = f"# {body.label}\n# Nightly DB backup (restricted): {url}\nBACKUP_DOWNLOAD_URL={url}\n"
        preview = f"/c/{raw[:6]}…"
        value_for_scanner = url
    h = Honeytoken(id=uid(), owner_user_id=user.id, label=body.label, kind=body.kind, token_hash=_token_hash(raw),
                   fingerprint=secret_fingerprint(value_for_scanner, APP_SECRET[:24]), preview=preview)
    session.add(h)
    audit(session, user.id, "HONEYTOKEN_CREATED", meta={"kind": body.kind, "label": body.label})
    session.commit()
    # The raw token is returned exactly once so it can be planted; only its HMAC is stored.
    return {"id": h.id, "label": h.label, "kind": h.kind, "token": raw, "snippet": snippet, "preview": preview}


@router.get("/api/honeytokens")
def honeytoken_list(request: Request, session: Session = Depends(db)):
    user = _auth(request, session)
    q = select(Honeytoken).order_by(desc(Honeytoken.created_at))
    if user.role != "admin":
        q = q.where(Honeytoken.owner_user_id == user.id)
    out = []
    for h in session.scalars(q):
        trips = session.scalars(select(HoneytokenTrip).where(HoneytokenTrip.honeytoken_id == h.id).order_by(desc(HoneytokenTrip.created_at)).limit(5)).all()
        out.append({"id": h.id, "label": h.label, "kind": h.kind, "preview": h.preview, "trips": h.trips,
                    "last_trip_at": h.last_trip_at.isoformat() if h.last_trip_at else None, "created_at": h.created_at.isoformat(),
                    "recent": [{"ip": t.ip, "user_agent": t.user_agent[:120], "path": t.path, "at": t.created_at.isoformat()} for t in trips]})
    return out


@router.delete("/api/honeytokens/{token_id}")
def honeytoken_delete(token_id: str, request: Request, session: Session = Depends(db)):
    from .main import require_same_origin
    user = _auth(request, session); require_same_origin(request)
    h = session.get(Honeytoken, token_id)
    if not h or (h.owner_user_id != user.id and user.role != "admin"):
        raise HTTPException(404, "honeytoken not found")
    session.query(HoneytokenTrip).filter(HoneytokenTrip.honeytoken_id == h.id).delete(synchronize_session=False)
    session.delete(h); session.commit()
    return {"ok": True}


def _trip(session: Session, request: Request, raw: str) -> bool:
    h = session.scalar(select(Honeytoken).where(Honeytoken.token_hash == _token_hash(raw)))
    if not h:
        return False
    current_workspace.set(h.workspace)  # the trip, alert and audit row belong to the token owner's workspace
    ip = request.client.host if request.client else "unknown"
    ua = (request.headers.get("user-agent") or "")[:300]
    session.add(HoneytokenTrip(id=uid(), honeytoken_id=h.id, ip=ip, user_agent=ua, path=str(request.url.path)[:300]))
    h.trips += 1; h.last_trip_at = _now()
    body = f"Honeytoken “{h.label}” was just used from {ip} ({ua[:60] or 'no user agent'}). Someone has your leaked code or config — treat the source as compromised."
    notify(session, "honeytoken", f"Honeytoken tripped: {h.label}", body, "CRITICAL", "secrets")
    notify(session, "honeytoken", f"Honeytoken tripped: {h.label}", body, "CRITICAL", "secrets", user_id=h.owner_user_id)
    from .main import audit
    audit(session, h.owner_user_id, "HONEYTOKEN_TRIPPED", severity="CRITICAL", meta={"label": h.label, "ip": ip})
    session.commit()
    return True


def _decoy():
    # Looks like an ordinary auth failure to the attacker - they learn nothing.
    return JSONResponse({"error": "invalid_api_key", "message": "The API key provided is invalid or has been revoked."}, status_code=401)


@router.api_route("/api/canary/v1/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"], include_in_schema=False)
def canary_api(rest: str, request: Request, session: Session = Depends(db)):
    auth = request.headers.get("authorization", "")
    raw = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key", "") or request.query_params.get("api_key", "")
    if raw:
        _trip(session, request, raw)
    return _decoy()


@router.get("/c/{raw}", include_in_schema=False)
def canary_url(raw: str, request: Request, session: Session = Depends(db)):
    _trip(session, request, raw)
    return JSONResponse({"error": "not_found"}, status_code=404)


@router.get("/demo/acme", include_in_schema=False)
def acme_demo():
    """Fictional company signup page demonstrating the drop-in <privpass-password-field> widget."""
    from .config import ROOT
    return FileResponse(ROOT / "static" / "demo" / "acme.html")


# ------------------------------------------------------------------ admin demo simulations
def _admin(request: Request, session: Session) -> User:
    from .config import APP_ENV
    from .main import require_same_origin
    user = _auth(request, session)
    if user.role != "admin":
        raise HTTPException(403, "admin required")
    if request.method != "GET":
        require_same_origin(request)
    from . import config as cfg
    if not cfg.demo_enabled():
        raise HTTPException(404, "simulations are disabled in production")
    if user.workspace != DEMO:
        raise HTTPException(403, "Simulations only run in the demo workspace, so real accounts never receive fake alerts.")
    return user


def simulation_counts(session: Session) -> dict:
    from .models import LoginEvent
    from .demo_seed import seeded_count
    return {
        "seeded_items": seeded_count(session),
        "simulated_login_events": session.query(LoginEvent).filter(LoginEvent.reason.like("sim_%")).count(),
        "simulated_breached_users": session.query(User).filter(User.breach_flag_source == "simulation", User.breach_locked.is_(True)).count(),
        "simulation_alerts": session.query(Notification).filter(Notification.kind == "simulation").count(),
    }


@router.get("/api/admin/simulations")
def simulations_status(request: Request, session: Session = Depends(db)):
    _admin(request, session)
    users = session.scalars(select(User).where(User.breach_flag_source == "simulation", User.breach_locked.is_(True))).all()
    return {**simulation_counts(session), "breached_users": [u.email for u in users]}


class SimBreachBody(BaseModel):
    user_id: str


@router.post("/api/admin/simulate/breach")
def simulate_breach(body: SimBreachBody, request: Request, session: Session = Depends(db)):
    """Demo: pretend the user's current password just appeared in a new breach. Their account is locked
    into the password-change flow exactly as a real breach re-check would do. Undo with /simulations/clear."""
    from .main import audit
    admin_user = _admin(request, session)
    target = session.get(User, body.user_id)
    if not target:
        raise HTTPException(404, "user not found")
    if target.id == admin_user.id:
        raise HTTPException(400, "Pick another account: locking yourself out would end this admin session.")
    if target.breach_locked:
        raise HTTPException(409, "this account is already locked")
    from .main import lock_for_breach
    lock_for_breach(session, target, "simulation", 48213)
    audit(session, admin_user.id, "SIMULATION_BREACH", severity="WARN", meta={"target": target.email})
    session.commit()
    return {"ok": True, "target": target.email, "self": False, **simulation_counts(session)}


@router.post("/api/admin/simulations/clear")
def simulations_clear(request: Request, session: Session = Depends(db)):
    """Remove every piece of simulated data. Real data (real breach flags, real sign-ins, real alerts)
    is never touched; the audit log keeps a record that simulations happened and were removed."""
    from .main import audit
    from .models import LoginEvent
    admin_user = _admin(request, session)
    events = session.query(LoginEvent).filter(LoginEvent.reason.like("sim_%")).delete(synchronize_session=False)
    unlocked = 0
    for u in session.scalars(select(User).where(User.breach_flag_source == "simulation", User.breach_locked.is_(True))):
        u.breach_locked = False; u.breach_locked_at = None; u.breach_count = 0; u.breach_flag_source = None; unlocked += 1
    alerts = session.query(Notification).filter(Notification.kind == "simulation").delete(synchronize_session=False)
    from .demo_seed import clear as clear_seed
    seeded = clear_seed(session)
    audit(session, admin_user.id, "SIMULATIONS_CLEARED", meta={"login_events": events, "users_unlocked": unlocked, "alerts": alerts, "demo_data": seeded})
    session.commit()
    return {"ok": True, "removed_login_events": events, "users_unlocked": unlocked, "removed_alerts": alerts, "removed_demo_data": seeded, **simulation_counts(session)}


@router.post("/api/admin/simulate/seed")
def simulate_seed(request: Request, session: Session = Depends(db)):
    """Demo workspace only: load a complete, labelled sample story (replaces any earlier sample data)."""
    from .main import audit
    from .demo_seed import seed
    admin_user = _admin(request, session)
    try:
        result = seed(session)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    audit(session, admin_user.id, "SIMULATION_DEMO_DATA", severity="WARN", meta=result)
    session.commit()
    return {"ok": True, **result, **simulation_counts(session)}
