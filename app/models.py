from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Boolean, Integer, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, WORKSPACE_MODELS, default_workspace

def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), default="user")
    verifier_ciphertext: Mapped[str] = mapped_column(Text)
    verifier_hash: Mapped[str] = mapped_column(Text)
    salt_b64: Mapped[str] = mapped_column(String(128))
    vault_salt_b64: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    vault_check_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    breach_flag_source: Mapped[str | None] = mapped_column(String(20), nullable=True)  # "recheck" | "simulation"
    # 7.3 server-enforced breach protection (see app/breachwatch.py)
    kdf_version: Mapped[int] = mapped_column(Integer, default=1)          # 1 = legacy verifier, 2 = bound to the breach-watch value
    watch_salt_b64: Mapped[str | None] = mapped_column(String(64), nullable=True)
    watch_prefix_ct: Mapped[str | None] = mapped_column(Text, nullable=True)   # sealed 5-char SHA-1 prefix
    watch_mac: Mapped[str | None] = mapped_column(String(64), nullable=True)   # HMAC(pepper, watch)
    breach_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    breach_locked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    breach_count: Mapped[int] = mapped_column(Integer, default=0)
    breach_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    breach_check_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class PasswordEvent(Base):
    __tablename__ = "password_events"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(40))
    breached: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[int] = mapped_column(Integer, default=0)
    score_label: Mapped[str] = mapped_column(String(30))
    guess_log10: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Scan(Base):
    __tablename__ = "scans"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    repo_name: Mapped[str] = mapped_column(String(200))
    file_count: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    source_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    source_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class SecretFinding(Base):
    __tablename__ = "secret_findings"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    file_path: Mapped[str] = mapped_column(String(500))
    line_no: Mapped[int] = mapped_column(Integer, default=0)
    secret_type: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float, default=0)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    redacted_preview: Mapped[str] = mapped_column(String(240))
    reason: Mapped[str] = mapped_column(Text, default="")
    entropy: Mapped[float] = mapped_column(Float, default=0)
    validity: Mapped[str] = mapped_column(String(60), default="UNKNOWN")
    status: Mapped[str] = mapped_column(String(30), default="DETECTED")
    kind: Mapped[str] = mapped_column(String(20), default="secret")
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit_author: Mapped[str | None] = mapped_column(String(200), nullable=True)
    commit_date: Mapped[str | None] = mapped_column(String(40), nullable=True)
    commits_seen: Mapped[int] = mapped_column(Integer, default=0)
    in_head: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    context_masked: Mapped[str] = mapped_column(Text, default="")
    ai_verdict: Mapped[str | None] = mapped_column(String(40), nullable=True)
    ai_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    event_type: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20), default="INFO")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class VaultItem(Base):
    """Zero-knowledge vault blob.

    The server stores only an opaque ciphertext blob. Title, username, password,
    URL, notes, strength metadata and rotation reminders are encrypted client-side.
    """
    __tablename__ = "vault_items"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ciphertext_b64: Mapped[str] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class EphemeralToken(Base):
    """Short-lived, single-use tokens shared by every worker (login/vault challenges,
    reset tokens and breach-check tickets). Only a SHA-256 of the raw token is stored."""
    __tablename__ = "ephemeral_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class AccountAuditReport(Base):
    """Aggregate-only result of a browser-side breached-password audit of a test account list.
    No emails, passwords or hashes are stored - only counts."""
    __tablename__ = "account_audit_reports"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    source_name: Mapped[str] = mapped_column(String(200))
    total: Mapped[int] = mapped_column(Integer, default=0)
    breached: Mapped[int] = mapped_column(Integer, default=0)
    unverified: Mapped[int] = mapped_column(Integer, default=0)
    below_policy: Mapped[int] = mapped_column(Integer, default=0)
    hibp_mode: Mapped[str] = mapped_column(String(30), default="live")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class LoginEvent(Base):
    """Sign-in telemetry for anomaly detection. Stores an HMAC of the email - never the email,
    never anything derived from the password."""
    __tablename__ = "login_events"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    account_hash: Mapped[str] = mapped_column(String(32))
    known_account: Mapped[bool] = mapped_column(Boolean, default=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(40), default="")
    agent_hash: Mapped[str] = mapped_column(String(16), default="")

class Notification(Base):
    """In-app alert (bell icon). Also forwarded to ALERT_WEBHOOK_URL (Slack/Teams/Discord compatible)."""
    __tablename__ = "notifications"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)  # None = all admins/analysts
    kind: Mapped[str] = mapped_column(String(40))
    severity: Mapped[str] = mapped_column(String(20), default="INFO")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str] = mapped_column(String(60), default="")
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

class Honeytoken(Base):
    """A bait credential planted on purpose. Only an HMAC of the token is stored."""
    __tablename__ = "honeytokens"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    label: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(30))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    preview: Mapped[str] = mapped_column(String(80))
    trips: Mapped[int] = mapped_column(Integer, default=0)
    last_trip_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class HoneytokenTrip(Base):
    __tablename__ = "honeytoken_trips"
    workspace: Mapped[str] = mapped_column(String(10), default=default_workspace, index=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    honeytoken_id: Mapped[str] = mapped_column(ForeignKey("honeytokens.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    user_agent: Mapped[str] = mapped_column(String(300), default="")
    path: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Passkey(Base):
    """WebAuthn credential (public key only)."""
    __tablename__ = "passkeys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    public_key: Mapped[str] = mapped_column(Text)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(80), default="Passkey")
    transports: Mapped[str] = mapped_column(String(200), default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

WORKSPACE_MODELS.extend([User, PasswordEvent, Scan, SecretFinding, AuditEvent, AccountAuditReport, LoginEvent, Notification, Honeytoken, HoneytokenTrip])
