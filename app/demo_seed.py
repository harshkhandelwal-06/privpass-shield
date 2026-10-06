"""One-click demo data for the DEMO workspace only.

Fills the demo workspace with a realistic, clearly-labelled story so a judge's first screen is alive:
two scanned repositories (one with a key that survives only in git history), findings at every lifecycle
stage with fix deadlines (one overdue), a tripped honeytoken, breach-gate attempts, a test-account audit,
login-attack traffic for the anomaly detector and matching alerts.

Everything seeded is marked, and "Remove simulation data" deletes all of it:
  scans.source_ref = "demo-seed" (+ their findings) · honeytokens labelled "[DEMO] …" (+ trips)
  password_events.guess_log10 = -1 · account_audit_reports.source_name "[DEMO] …"
  login_events.reason "sim_*" · notifications.kind "simulation"
"""
from __future__ import annotations

import random
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import APP_SECRET, ROOT
from .db import DEMO, SessionLocal, workspace_scope
from .models import (AccountAuditReport, Honeytoken, HoneytokenTrip, LoginEvent, Notification, PasswordEvent, Scan,
                     SecretFinding, User)
from .security import uid

SEED_REF = "demo-seed"
SEED_LOG10 = -1.0
DEMO_ADMIN, DEMO_USER = "admin@privpass.local", "user@privpass.local"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def seeded_count(session: Session) -> int:
    return (session.query(Scan).filter(Scan.source_ref == SEED_REF).count()
            + session.query(Honeytoken).filter(Honeytoken.label.like("[DEMO]%")).count()
            + session.query(AccountAuditReport).filter(AccountAuditReport.source_name.like("[DEMO]%")).count())


def clear(session: Session) -> int:
    """Delete everything the seeder created (caller commits)."""
    n = 0
    scan_ids = [s.id for s in session.scalars(select(Scan).where(Scan.source_ref == SEED_REF))]
    if scan_ids:
        n += session.query(SecretFinding).filter(SecretFinding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        n += session.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    tok_ids = [h.id for h in session.scalars(select(Honeytoken).where(Honeytoken.label.like("[DEMO]%")))]
    if tok_ids:
        session.query(HoneytokenTrip).filter(HoneytokenTrip.honeytoken_id.in_(tok_ids)).delete(synchronize_session=False)
        n += session.query(Honeytoken).filter(Honeytoken.id.in_(tok_ids)).delete(synchronize_session=False)
    n += session.query(PasswordEvent).filter(PasswordEvent.guess_log10 == SEED_LOG10).delete(synchronize_session=False)
    n += session.query(AccountAuditReport).filter(AccountAuditReport.source_name.like("[DEMO]%")).delete(synchronize_session=False)
    return n


def _scan(session: Session, user: User, zip_name: str) -> list[SecretFinding]:
    from .main import _persist_scan
    from .scanner import scan_zip
    data = (ROOT / "demo-assets" / zip_name).read_bytes()
    findings, count = scan_zip(data, APP_SECRET[:24])
    scan, rows = _persist_scan(session, user, zip_name, count, findings)
    scan.source_ref = SEED_REF
    return rows


def seed(session: Session) -> dict:
    """Seed the demo workspace. Must run with the DEMO workspace active. Replaces any earlier seed."""
    from .features import _token_hash
    from .scanner import fingerprint as secret_fingerprint
    from .notify import notify
    t0 = _now()
    clear(session)
    admin = session.scalar(select(User).where(User.email == DEMO_ADMIN))
    user = session.scalar(select(User).where(User.email == DEMO_USER))
    if not admin or not user:
        raise RuntimeError("demo accounts are missing")
    rng = random.Random(2026)

    # 1) Two repositories: the admin's leak repo and the demo user's "deleted but still in history" repo.
    leak = _scan(session, admin, "PrivPass-Demo-Leak-Repo.zip")
    hist = _scan(session, user, "PrivPass-History-Leak-Repo.zip")
    # Findings at every lifecycle stage, with realistic timestamps (one CRITICAL is overdue).
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    leak.sort(key=lambda f: order.get(f.severity, 9))
    plan = [("ROTATED", 20), ("CONTAINED", 9), ("TRIAGED", 3), ("DETECTED", 6)]
    for f, (status, hours_ago) in zip(leak, plan):
        f.created_at = t0 - timedelta(hours=hours_ago)
        f.status = status
        if status in ("TRIAGED", "CONTAINED", "ROTATED"):
            f.triaged_at = f.created_at + timedelta(minutes=25)
        if status in ("CONTAINED", "ROTATED"):
            f.contained_at = f.created_at + timedelta(hours=1, minutes=10)
        if status == "ROTATED":
            f.rotated_at = f.created_at + timedelta(hours=2, minutes=40)
    for f in hist:
        f.created_at = t0 - timedelta(hours=2)

    # 2) A honeytoken planted in a config file, then used by "someone" from a documentation IP.
    raw = "ppk_live_" + secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")
    h = Honeytoken(id=uid(), owner_user_id=admin.id, label="[DEMO] payments-api .env", kind="api_key", token_hash=_token_hash(raw),
                   fingerprint=secret_fingerprint(raw, APP_SECRET[:24]), preview=raw[:13] + "…" + raw[-4:], created_at=t0 - timedelta(days=3))
    session.add(h)
    for mins, ip, ua in ((95, "203.0.113.50", "curl/8.4.0"), (40, "203.0.113.50", "python-requests/2.32")):
        session.add(HoneytokenTrip(id=uid(), honeytoken_id=h.id, ip=ip, user_agent=ua, path="/api/canary/v1/charges", created_at=t0 - timedelta(minutes=mins)))
    h.trips, h.last_trip_at = 2, t0 - timedelta(minutes=40)

    # 3) Breach-gate traffic: 37 signup/reset attempts, 9 blocked (6 breached, 3 below the 15-character policy).
    for i in range(37):
        kind = "signup_blocked" if i < 9 else ("reset" if i % 7 == 0 else "signup")
        breached = i < 6
        session.add(PasswordEvent(id=uid(), user_id=None, event_type=kind, breached=breached,
                                  score=0 if kind.endswith("blocked") else rng.randint(72, 97),
                                  score_label="breached" if breached else ("below_policy" if kind.endswith("blocked") else "Strong"),
                                  guess_log10=SEED_LOG10, created_at=t0 - timedelta(hours=rng.uniform(1, 70))))

    # 4) The "X% of test accounts use a breached password" report (aggregate counts only).
    session.add(AccountAuditReport(id=uid(), owner_user_id=admin.id, source_name="[DEMO] sample-accounts.csv", total=40, breached=12,
                                   unverified=0, below_policy=16, hibp_mode="offline-demo", created_at=t0 - timedelta(hours=5)))

    # 5) Login-attack traffic for the Isolation Forest (same labelled "sim_" events the AI Lab button creates).
    def login(ip, minutes_ago, acct, known, ok, reason, agent):
        session.add(LoginEvent(id=uid(), created_at=t0 - timedelta(minutes=minutes_ago), ip=ip, account_hash=f"sim{acct:029d}"[:32],
                               known_account=known, success=ok, reason=f"sim_{reason}", agent_hash=agent[:16]))
    for i in range(40):
        base = rng.uniform(5, 180); ip = f"10.20.{rng.randint(0, 9)}.{rng.randint(2, 250)}"
        for k in range(rng.randint(1, 3)):
            login(ip, base - k * 0.3, 1000 + i, True, k > 0 or rng.random() > .1, "normal", "sim-browser")
    for k in range(70):
        login("203.0.113.7", 12 - k * 0.04, 5000 + k, rng.random() > .35, False, "stuffing", "python-requests")
    for k in range(35):
        login("198.51.100.23", 30 - k * 0.1, 42, True, False, "bruteforce", "curl")

    # 6) Alerts that match the story. Scan alerts raised above are re-labelled as simulation alerts so the
    #    "Remove simulation data" button clears them too.
    notify(session, "simulation", "Honeytoken tripped: [DEMO] payments-api .env",
           "Used twice from 203.0.113.50 (curl, python-requests). Someone has this config file: rotate every secret stored in it.", "CRITICAL", "secrets")
    notify(session, "simulation", "Login attacks detected", "Credential stuffing from 203.0.113.7 and brute force from 198.51.100.23 (demo traffic).", "HIGH", "ai")
    session.flush()
    session.query(Notification).filter(Notification.created_at >= t0 - timedelta(seconds=1), Notification.kind == "scan").update(
        {Notification.kind: "simulation"}, synchronize_session=False)
    return {"repositories": 2, "findings": len(leak) + len(hist), "honeytoken_trips": 2, "gate_attempts": 37, "login_events": session.query(LoginEvent).filter(LoginEvent.reason.like("sim_%")).count()}


def seed_if_empty() -> None:
    """Startup hook for public demos (PRIVPASS_DEMO_AUTOSEED=true): seed once when the demo workspace has no data."""
    with workspace_scope(DEMO), SessionLocal() as s:
        if seeded_count(s) or s.query(Scan).count():
            return
        try:
            seed(s); s.commit(); print("Demo workspace seeded with sample data.")
        except Exception as exc:  # never block startup on demo data
            s.rollback(); print(f"Demo seed skipped: {exc}")
