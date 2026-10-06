"""7.1 exposure map: one person's attack surface, correlated from data PrivPass already stores.

Everything is derived from existing rows (users, sessions, passkeys, password events, scans, findings, honeytokens,
notifications, audit). No secret values are returned: findings carry only their redacted metadata.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from .models import AuditEvent, Honeytoken, Notification, Passkey, PasswordEvent, Scan, SecretFinding, User, VaultItem
from .models import Session as DbSession

OPEN = ("DETECTED", "TRIAGED", "CONTAINED")
SEV_POINTS = {"CRITICAL": 18, "HIGH": 10, "MEDIUM": 4, "LOW": 1}

# What an attacker can do with each kind of leaked credential (shown in the attack paths).
IMPACT = [
    ("stripe", "charge cards, issue refunds and read customer payment data"),
    ("aws", "run servers on your bill and read or delete data in S3"),
    ("github", "read private code and push malicious commits"),
    ("slack", "read and post messages in your workspace"),
    ("openai", "run up your AI bill and read prompts"),
    ("anthropic", "run up your AI bill"),
    ("google", "call Google Cloud APIs as you"),
    ("jwt", "impersonate a signed-in user"),
    ("private key", "impersonate your servers or decrypt traffic"),
    ("connection", "read and modify your database"),
    ("database", "read and modify your database"),
    ("twilio", "send SMS and calls on your account"),
    ("sendgrid", "send phishing email from your domain"),
]
ROTATE_AT = {"stripe": "Stripe Dashboard → Developers → API keys → Roll key", "aws": "AWS IAM → Users → Security credentials → deactivate + create key",
             "github": "GitHub → Settings → Developer settings → revoke the token", "slack": "Slack app settings → Revoke and regenerate token",
             "openai": "OpenAI dashboard → API keys → Revoke", "google": "Google Cloud Console → Credentials → Regenerate key"}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _impact(secret_type: str, kind: str) -> str:
    t = (secret_type or "").lower()
    if kind == "code":
        return "turn this code path into an injection or data-leak bug"
    return next((text for key, text in IMPACT if key in t), "use this service exactly as you would")


def _rotate(secret_type: str) -> str:
    t = (secret_type or "").lower()
    return next((text for key, text in ROTATE_AT.items() if key in t), "Revoke it at the provider, issue a new one and store it in a secret manager")


def build(session: Session, user: User) -> dict:
    now = _now()
    sessions = session.scalar(select(func.count(DbSession.id)).where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None), DbSession.expires_at > now)) or 0
    passkeys = session.scalar(select(func.count(Passkey.id)).where(Passkey.user_id == user.id)) or 0
    vault = session.scalar(select(func.count(VaultItem.id)).where(VaultItem.owner_user_id == user.id)) or 0
    last_pw = session.scalar(select(PasswordEvent).where(PasswordEvent.user_id == user.id, PasswordEvent.event_type.in_(("signup", "reset", "change")))
                             .order_by(desc(PasswordEvent.created_at)).limit(1))
    last_check = session.scalar(select(PasswordEvent).where(PasswordEvent.user_id == user.id, PasswordEvent.event_type == "login_recheck")
                                .order_by(desc(PasswordEvent.created_at)).limit(1))
    breached = bool(user.breach_locked) or user.breach_check_status == "breached"

    # Repositories: the latest scan per repository name.
    scans = session.scalars(select(Scan).where(Scan.owner_user_id == user.id).order_by(desc(Scan.created_at)).limit(60)).all()
    latest_by_repo: dict[str, Scan] = {}
    for s in scans:
        latest_by_repo.setdefault(s.repo_name, s)
    repos, open_findings = [], []
    for s in list(latest_by_repo.values())[:6]:
        rows = session.scalars(select(SecretFinding).where(SecretFinding.scan_id == s.id, SecretFinding.owner_user_id == user.id)).all()
        opened = [f for f in rows if (f.status or "DETECTED") in OPEN]
        sev = {k: sum(1 for f in opened if f.severity == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        repos.append({"name": s.repo_name, "scan_id": s.id, "files": s.file_count, "findings": len(rows), "open": len(opened),
                      "severity": sev, "history_only": sum(1 for f in opened if f.in_head is False), "source_url": s.source_url,
                      "scanned_at": s.created_at.isoformat(), "state": "critical" if sev["CRITICAL"] else "warn" if sev["HIGH"] or sev["MEDIUM"] else "safe"})
        open_findings += [(f, s.repo_name) for f in opened]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    open_findings.sort(key=lambda x: (order.get(x[0].severity, 9), -(x[0].confidence or 0)))

    tokens = session.scalars(select(Honeytoken).where(Honeytoken.owner_user_id == user.id)).all()
    tripped = [h for h in tokens if h.trips]
    unread = session.scalar(select(func.count(Notification.id)).where(Notification.user_id == user.id, Notification.read_at.is_(None))) or 0

    # ---- exposure score (0 = nothing exposed, 100 = take action now) and the factors behind it
    factors = []
    def factor(key, label, points, fix, action, severity):
        if points > 0:
            factors.append({"key": key, "label": label, "points": int(points), "fix": fix, "action": action, "severity": severity})
    sev_all = {k: sum(1 for f, _ in open_findings if f.severity == k) for k in SEV_POINTS}
    secret_pts = min(55, sum(SEV_POINTS[k] * v for k, v in sev_all.items()))
    if open_findings:
        top = open_findings[0][0]
        factor("secrets", f"{len(open_findings)} open finding(s), worst: {top.severity.lower()} {top.secret_type}", secret_pts,
               "Rotate at the provider, then mark it ROTATED", f"finding:{top.id}", top.severity.lower())
    factor("breach", "Your current password appeared in a breach", 30 if breached else 0, "Change your password", "security", "critical")
    factor("mfa", "Password is your only sign-in factor", 12 if not (user.mfa_enabled or passkeys) else 0, "Add a passkey (fingerprint, face or PIN)", "security", "high")
    factor("sessions", f"{sessions} sessions are signed in at once", min(8, (sessions - 2) * 2) if sessions > 2 else 0, "Sign out, then back in, to end old sessions", "security", "medium")
    factor("honeytoken", f"{len(tripped)} bait key(s) were used by someone", 25 if tripped else 0, "Treat the source as leaked: rotate everything in it", "nav:secrets", "critical")
    factor("history", f"{sum(r['history_only'] for r in repos)} secret(s) survive only in git history", 0, "", "", "info")
    score = min(100, sum(f["points"] for f in factors))
    label = "CRITICAL" if score >= 60 else "HIGH" if score >= 35 else "ELEVATED" if score >= 12 else "GUARDED"
    factors.sort(key=lambda f: -f["points"])

    # ---- attack paths: entry point -> what it gives an attacker -> the fix
    paths = []
    for f, repo in open_findings[:4]:
        where = "only in git history (deleting the file did not remove it)" if f.in_head is False else f"{f.file_path}:{f.line_no}"
        paths.append({"severity": f.severity.lower(), "entry": f"{f.secret_type} in {repo}", "where": where,
                      "pivot": "Anyone with read access to the repo or a clone of it copies the value" if f.kind != "code" else "An attacker sends crafted input to this code",
                      "impact": f"They can {_impact(f.secret_type, f.kind)}",
                      "fix": _rotate(f.secret_type) if f.kind != "code" else "Fix the code pattern shown in the finding", "action": f"finding:{f.id}"})
    if breached:
        paths.insert(0, {"severity": "critical", "entry": "Your password is in breach data", "where": "found by the sign-in re-check",
                         "pivot": "Attackers try leaked passwords against every site (credential stuffing)",
                         "impact": "They can sign in as you and read your vault metadata and findings", "fix": "Change the password now", "action": "security"})
    if not (user.mfa_enabled or passkeys):
        paths.append({"severity": "high", "entry": "Password-only account", "where": "no MFA and no passkey",
                      "pivot": "A phished or guessed password is enough on its own",
                      "impact": "One mistake gives full account access", "fix": "Add a passkey; it cannot be phished", "action": "security"})
    for h in tripped[:2]:
        paths.insert(0, {"severity": "critical", "entry": f"Bait key “{h.label}” was used", "where": f"{h.trips} use(s), last on {h.last_trip_at.strftime('%d %b at %H:%M UTC') if h.last_trip_at else 'unknown date'}",
                         "pivot": "Whoever used it has the file or repo you planted it in",
                         "impact": "Any real secret stored next to it is exposed too", "fix": "Rotate every credential from that source", "action": "nav:secrets"})

    controls = [
        {"key": "breach", "label": "Password not found in breaches", "ok": not breached, "action": "security"},
        {"key": "length", "label": "Password meets the 15+ character policy", "ok": bool(last_pw) or user.workspace == "demo", "action": "security"},
        {"key": "phishing", "label": "Phishing-resistant sign-in (passkey) or MFA", "ok": bool(passkeys or user.mfa_enabled), "action": "security"},
        {"key": "vault", "label": "Credentials kept in the zero-knowledge vault", "ok": vault > 0, "action": "nav:vault"},
        {"key": "scanned", "label": "At least one repository scanned", "ok": bool(repos), "action": "nav:secrets"},
        {"key": "critical", "label": "No open critical findings", "ok": sev_all["CRITICAL"] == 0, "action": "nav:incidents"},
        {"key": "honey", "label": "Honeytokens planted as tripwires", "ok": bool(tokens), "action": "nav:secrets"},
    ]

    events = session.scalars(select(AuditEvent).where(AuditEvent.user_id == user.id).order_by(desc(AuditEvent.created_at)).limit(14)).all()
    timeline = []
    for e in events:
        try:
            meta = json.loads(e.metadata_json or "{}")
        except Exception:
            meta = {}
        timeline.append({"event": e.event_type, "severity": e.severity, "at": e.created_at.isoformat(),
                         "detail": {k: meta[k] for k in ("method", "files", "findings", "history_only", "status", "from", "label", "ip", "mode") if k in meta}})

    return {
        "identity": {"email": user.email, "role": user.role, "workspace": user.workspace, "mfa": bool(user.mfa_enabled), "passkeys": passkeys,
                     "sessions": sessions, "vault_items": vault, "breached": breached,
                     "password": {"score": last_pw.score if last_pw else None, "label": last_pw.score_label if last_pw else None,
                                  "set_at": (user.password_changed_at or (last_pw.created_at if last_pw else user.created_at)).isoformat(),
                                  "last_check": last_check.score_label if last_check else None}},
        "repos": repos,
        "open_findings": [{"id": f.id, "type": f.secret_type, "severity": f.severity, "kind": f.kind or "secret", "repo": repo, "file": f.file_path,
                           "line": f.line_no, "status": f.status or "DETECTED", "in_head": f.in_head, "preview": f.redacted_preview} for f, repo in open_findings[:24]],
        "honeytokens": {"count": len(tokens), "tripped": len(tripped), "trips": sum(h.trips for h in tokens)},
        "alerts_unread": unread,
        "exposure": {"score": score, "label": label, "factors": factors},
        "paths": paths[:6],
        "controls": controls,
        "timeline": timeline,
    }
