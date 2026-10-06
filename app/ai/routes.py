"""HTTP API for PrivPass AI/ML features (mounted by app.main)."""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..config import APP_ENV, ROOT
from ..db import db
from ..main import _gate_stats, _latest_account_audit, audit, get_current_session, rate_limited, require_same_origin
from ..models import AuditEvent, Honeytoken, LoginEvent, Scan, SecretFinding, User
from ..features import sla_info, sla_metrics
from ..security import uid
from . import assist, provider, remediation
from ..ml import anomaly

router = APIRouter(prefix="/api/ai")
OPEN = ("DETECTED", "TRIAGED", "CONTAINED")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _require(request: Request, session: Session, roles: set[str] | None = None) -> User:
    user, _ = get_current_session(request, session)
    if roles and user.role not in roles:
        raise HTTPException(403, f"requires role: {', '.join(sorted(roles))}")
    return user


def _finding_dict(f: SecretFinding, repo: str | None = None) -> dict:
    return {"id": f.id, "type": f.secret_type, "severity": f.severity, "kind": f.kind or "secret", "file": f.file_path, "line": f.line_no,
            "status": f.status or "DETECTED", "confidence": f.confidence, "validity": f.validity, "reason": f.reason,
            "in_head": f.in_head, "commit": f.commit_sha, "commit_date": f.commit_date, "commits_seen": f.commits_seen,
            "ml_probability": f.ml_probability, "ml_reasons": json.loads(f.ml_reasons_json or "[]"), "context": f.context_masked or "",
            "preview": f.redacted_preview, "repo": repo, "age_hours": round((_now() - f.created_at).total_seconds() / 3600, 1), "sla": sla_info(f)}


def _owned_finding(session: Session, user: User, finding_id: str) -> SecretFinding:
    f = session.get(SecretFinding, finding_id)
    if not f or (f.owner_user_id != user.id and user.role not in {"admin", "analyst"}):
        raise HTTPException(404, "finding not found")
    return f


# ------------------------------------------------------------------ status & model cards
@router.get("/status")
def ai_status(request: Request, session: Session = Depends(db)):
    from ..ml import secret_model
    return {**provider.status(), "secret_classifier": secret_model.available(),
            "password_model": (ROOT / "static" / "ml" / "password-model.json").exists(), "anomaly_detector": True}


@router.get("/models")
def model_cards():
    def load(name):
        p = ROOT / "ml" / "reports" / name
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    try:
        anomaly_card = anomaly.evaluate()
    except Exception:
        anomaly_card = None
    return {"secret_classifier": load("secret-classifier-card.json"), "password_model": load("password-model-card.json"),
            "anomaly_detector": anomaly_card}


# ------------------------------------------------------------------ remediation & triage
@router.post("/remediate/{finding_id}")
def remediate(finding_id: str, request: Request, session: Session = Depends(db)):
    user = _require(request, session); require_same_origin(request); rate_limited(request, "ai", 30, 60)
    f = _owned_finding(session, user, finding_id)
    repo = session.scalar(select(Scan.repo_name).where(Scan.id == f.scan_id))
    result = remediation.remediate(_finding_dict(f, repo))
    audit(session, user.id, "AI_REMEDIATION", meta={"finding_id": f.id, "mode": result["mode"]}); session.commit()
    return result


class TriageBody(BaseModel):
    finding_ids: Optional[list[str]] = None


@router.post("/triage")
def triage(body: TriageBody, request: Request, session: Session = Depends(db)):
    user = _require(request, session); require_same_origin(request); rate_limited(request, "ai", 30, 60)
    if body.finding_ids:
        rows = [_owned_finding(session, user, i) for i in body.finding_ids[:50]]
    else:
        latest = session.scalar(select(Scan).where(Scan.owner_user_id == user.id).order_by(desc(Scan.created_at)).limit(1))
        rows = session.scalars(select(SecretFinding).where(SecretFinding.scan_id == latest.id)).all() if latest else []
        rows = [r for r in rows if assist.in_grey_zone(_finding_dict(r))][:50]
    out = []
    for r in rows:
        res = assist.triage(_finding_dict(r))
        r.ai_verdict, r.ai_reason = res["verdict"], f"{res['explanation']} [{res['mode']}]"
        out.append({"id": r.id, "type": r.secret_type, "file": r.file_path, "line": r.line_no, "severity": r.severity, **res})
    audit(session, user.id, "AI_TRIAGE", meta={"count": len(out)}); session.commit()
    return {"triaged": out, "grey_zone": [assist.GREY_LOW, assist.GREY_HIGH]}


# ------------------------------------------------------------------ password coach (flags only)
FlagName = Literal["common", "identity_like", "dictionary_like", "year", "keyboard", "sequence", "repeat_substring", "digit_only",
                   "breached", "generated", "alternating", "letter_only", "separator_phrase"]


class CoachBody(BaseModel):
    """Strict schema: numbers, booleans and fixed labels only - there is no field that could carry a password."""
    model_config = ConfigDict(extra="forbid")
    length: int = Field(ge=0, le=512)
    score: int = Field(ge=0, le=100)
    label: Literal["Waiting", "Critical", "Weak", "Fair", "Strong", "Excellent"]
    log10_guesses: float = Field(ge=0, le=200)
    neural_log10: Optional[float] = Field(default=None, ge=0, le=200)
    char_classes: int = Field(ge=0, le=4)
    flags: dict[FlagName, bool] = {}


@router.post("/password-coach")
def password_coach(body: CoachBody, request: Request):
    require_same_origin(request); rate_limited(request, "ai-coach", 30, 60)
    return assist.coach(body.model_dump())


# ------------------------------------------------------------------ copilot tools (read-only, role-scoped)
def _tools(session: Session, user: User) -> dict:
    def scope(q):
        return q if user.role in {"admin", "analyst"} else q.where(SecretFinding.owner_user_id == user.id)

    def get_security_overview():
        rows = session.scalars(scope(select(SecretFinding))).all()
        users = session.scalar(select(func.count(User.id))) or 0
        mfa = session.scalar(select(func.count(User.id)).where(User.mfa_enabled.is_(True))) or 0
        return {"gate": _gate_stats(session), "account_audit": _latest_account_audit(session),
                "findings": {"total": len(rows), "open_critical": sum(r.severity == "CRITICAL" and (r.status or "DETECTED") in OPEN for r in rows),
                             "open_high": sum(r.severity == "HIGH" and (r.status or "DETECTED") in OPEN for r in rows),
                             "history_only": sum(r.in_head is False for r in rows), "risky_code": sum((r.kind or "") == "code" for r in rows)},
                "mfa_adoption_percent": round(mfa / users * 100, 1) if users else 0,
                "fix_deadlines": sla_metrics(rows),
                "honeytokens": [{"label": h.label, "trips": h.trips, "last_trip_at": h.last_trip_at.isoformat() if h.last_trip_at else None}
                                for h in session.scalars(select(Honeytoken))]}

    def list_findings(severity=None, status=None, kind=None, history_only=None, older_than_hours=None, limit=25):
        q = scope(select(SecretFinding, Scan.repo_name).join(Scan, Scan.id == SecretFinding.scan_id))
        if severity: q = q.where(SecretFinding.severity == severity)
        if status == "OPEN": q = q.where(SecretFinding.status.in_(OPEN))
        elif status: q = q.where(SecretFinding.status == status)
        if kind: q = q.where(SecretFinding.kind == kind)
        if history_only: q = q.where(SecretFinding.in_head.is_(False))
        if older_than_hours: q = q.where(SecretFinding.created_at <= _now() - timedelta(hours=float(older_than_hours)))
        rows = session.execute(q.order_by(SecretFinding.created_at).limit(min(int(limit or 25), 100))).all()
        return {"findings": [{k: v for k, v in _finding_dict(f, repo).items() if k != "context"} for f, repo in rows]}

    def get_login_anomalies(hours=24):
        return _anomalies(session, float(hours or 24))

    def get_audit_events(event_type=None, limit=20):
        q = select(AuditEvent).order_by(desc(AuditEvent.created_at))
        if event_type: q = q.where(AuditEvent.event_type.like(f"{event_type.upper()}%"))
        return {"events": [{"event": e.event_type, "severity": e.severity, "created_at": e.created_at.isoformat()} for e in session.scalars(q.limit(min(int(limit or 20), 100)))]}

    return {"get_security_overview": get_security_overview, "list_findings": list_findings,
            "get_login_anomalies": get_login_anomalies, "get_audit_events": get_audit_events}


class CopilotBody(BaseModel):
    question: str = Field(min_length=2, max_length=500)


@router.post("/copilot")
def copilot(body: CopilotBody, request: Request, session: Session = Depends(db)):
    user = _require(request, session, {"admin", "analyst"}); require_same_origin(request); rate_limited(request, "ai", 30, 60)
    result = assist.copilot(body.question, _tools(session, user))
    audit(session, user.id, "AI_COPILOT_QUERY", meta={"mode": result["mode"], "tools": [c["tool"] for c in result["tool_calls"]]}); session.commit()
    return result


@router.post("/incident-report")
def incident_report(request: Request, session: Session = Depends(db)):
    user = _require(request, session, {"admin", "analyst"}); require_same_origin(request); rate_limited(request, "ai", 10, 60)
    tools = _tools(session, user)
    data = {"overview": tools["get_security_overview"](), "findings": tools["list_findings"](limit=100)["findings"],
            "anomalies": _anomalies(session, 24), "audit": tools["get_audit_events"](limit=30)["events"]}
    result = assist.incident_report(data)
    audit(session, user.id, "AI_INCIDENT_REPORT", meta={"mode": result["mode"]}); session.commit()
    return result


# ------------------------------------------------------------------ login anomaly detection
def _anomalies(session: Session, hours: float) -> dict:
    try:
        import sklearn  # noqa: F401
    except Exception:
        return {"hours": hours, "events": 0, "windows_scored": 0, "anomalous": 0, "windows": [], "error": "scikit-learn is not installed"}
    rows = session.scalars(select(LoginEvent).where(LoginEvent.created_at >= _now() - timedelta(hours=hours))).all()
    events = [anomaly.Event(r.created_at, r.ip, r.account_hash, r.known_account, r.success, r.reason, r.agent_hash) for r in rows]
    scored = anomaly.score_windows(anomaly.group_windows(events))
    return {"hours": hours, "events": len(events), "windows_scored": len(scored), "anomalous": sum(w["anomalous"] for w in scored), "windows": scored[:40]}


@router.get("/anomalies")
def anomalies(request: Request, hours: float = 24, session: Session = Depends(db)):
    _require(request, session, {"admin", "analyst"})
    return _anomalies(session, max(1.0, min(hours, 24 * 14)))


@router.post("/anomalies/simulate")
def simulate(request: Request, session: Session = Depends(db)):
    """Demo only: inject clearly-labelled simulated traffic (normal users + three attack patterns)."""
    user = _require(request, session, {"admin"}); require_same_origin(request)
    from .. import config as cfg
    if not cfg.demo_enabled():
        raise HTTPException(404, "simulation disabled in production")
    if user.workspace != "demo":
        raise HTTPException(403, "Simulations only run in the demo workspace, so real accounts never receive fake alerts.")
    rng = random.Random()
    now = _now()

    def add(ip, minutes_ago, acct, known, ok, reason, agent="sim-browser"):
        session.add(LoginEvent(id=uid(), created_at=now - timedelta(minutes=minutes_ago), ip=ip, account_hash=f"sim{acct:029d}"[:32],
                               known_account=known, success=ok, reason=f"sim_{reason}", agent_hash=agent[:16]))
    for i in range(40):                                   # ordinary users
        base = rng.uniform(5, 180); ip = f"10.20.{rng.randint(0, 9)}.{rng.randint(2, 250)}"
        for k in range(rng.randint(1, 3)):
            add(ip, base - k * 0.3, 1000 + i, True, k > 0 or rng.random() > .1, "normal")
    for k in range(70):                                   # credential stuffing: many accounts, one IP
        add("203.0.113.7", 12 - k * 0.04, 5000 + k, rng.random() > .35, False, "stuffing", "python-requests")
    for k in range(35):                                   # brute force: one account
        add("198.51.100.23", 30 - k * 0.1, 42, True, False, "bruteforce", "curl")
    for k in range(60):                                   # account enumeration: unknown accounts
        add("192.0.2.99", 50 - k * 0.05, 9000 + k, False, False, "enumeration", "go-http")
    from ..notify import notify
    notify(session, "simulation", "[SIMULATION] Login attacks detected", "Credential stuffing from 203.0.113.7, brute force from 198.51.100.23 and account enumeration from 192.0.2.99 (simulated traffic).", "HIGH", "ai")
    audit(session, user.id, "ANOMALY_SIMULATION", severity="WARN", meta={"events": 205}); session.commit()
    return _anomalies(session, 24)


@router.delete("/anomalies/simulated")
def clear_simulated(request: Request, session: Session = Depends(db)):
    _require(request, session, {"admin"}); require_same_origin(request)
    n = session.query(LoginEvent).filter(LoginEvent.reason.like("sim_%")).delete(synchronize_session=False)
    from ..models import Notification
    session.query(Notification).filter(Notification.kind == "simulation", Notification.title.like("%Login attacks%")).delete(synchronize_session=False)
    session.commit()
    return {"deleted": n}
