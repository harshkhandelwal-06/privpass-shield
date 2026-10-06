from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from sqlalchemy import bindparam, create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session as OrmSession, sessionmaker, with_loader_criteria
from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True, pool_recycle=1800)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass

# ---- Workspaces: "demo" (shared judge accounts + their data) and "live" (real accounts).
# The middleware sets the signed-in user's workspace for the whole request; every ORM SELECT,
# UPDATE and DELETE on a workspace-scoped model is then filtered automatically, so no endpoint
# can leak demo data into a real account or the other way round. None = unscoped (auth flows,
# startup, the honeytoken trap), used only where the code needs to look across workspaces.
DEMO, LIVE = "demo", "live"
current_workspace: ContextVar[str | None] = ContextVar("pp_workspace", default=None)
WORKSPACE_MODELS: list[type] = []

def default_workspace() -> str:
    return current_workspace.get() or LIVE

@contextmanager
def workspace_scope(ws: str | None):
    token = current_workspace.set(ws)
    try:
        yield
    finally:
        current_workspace.reset(token)

@event.listens_for(OrmSession, "do_orm_execute")
def _workspace_filter(state):
    ws = current_workspace.get()
    if ws is None or state.execution_options.get("all_workspaces"):
        return
    if state.is_select or state.is_update or state.is_delete:
        for cls in WORKSPACE_MODELS:
            state.statement = state.statement.options(
                with_loader_criteria(cls, cls.workspace == ws, include_aliases=True))

def _ensure_legacy_columns() -> None:
    """Add safe, nullable/defaulted columns to older local databases without Alembic."""
    insp = inspect(engine)
    if "users" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("users")}
    with engine.begin() as conn:
        if "vault_salt_b64" not in existing:
            if engine.dialect.name == "sqlite":
                conn.execute(text("ALTER TABLE users ADD COLUMN vault_salt_b64 VARCHAR(128) NOT NULL DEFAULT ''"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_salt_b64 VARCHAR(128) NOT NULL DEFAULT ''"))
        for col, ddl in [("must_change_password", "BOOLEAN NOT NULL DEFAULT 0"), ("password_changed_at", "TIMESTAMP"), ("breach_flag_source", "VARCHAR(20)"),
                         ("kdf_version", "INTEGER NOT NULL DEFAULT 1"), ("watch_salt_b64", "VARCHAR(64)"), ("watch_prefix_ct", "TEXT"),
                         ("watch_mac", "VARCHAR(64)"), ("breach_locked", "BOOLEAN NOT NULL DEFAULT 0"), ("breach_locked_at", "TIMESTAMP"),
                         ("breach_count", "INTEGER"), ("breach_checked_at", "TIMESTAMP"), ("breach_check_status", "VARCHAR(20)")]:
            if col not in existing:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {ddl}" if engine.dialect.name == "sqlite" else f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {ddl.replace('DEFAULT 0', 'DEFAULT FALSE')}"))
        if "vault_check_ciphertext" not in existing:
            if engine.dialect.name == "sqlite":
                conn.execute(text("ALTER TABLE users ADD COLUMN vault_check_ciphertext TEXT"))
            else:
                conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_check_ciphertext TEXT"))
        scan_existing = {c["name"] for c in inspect(engine).get_columns("scans")} if "scans" in inspect(engine).get_table_names() else set()
        for col in ("source_url", "source_ref"):
            if scan_existing and col not in scan_existing:
                conn.execute(text(f"ALTER TABLE scans ADD COLUMN {col} VARCHAR(300)"))
        sf_existing = {c["name"] for c in inspect(engine).get_columns("secret_findings")} if "secret_findings" in inspect(engine).get_table_names() else set()
        for col, ddl in [("reason", "TEXT NOT NULL DEFAULT ''"), ("entropy", "REAL NOT NULL DEFAULT 0"), ("validity", "VARCHAR(60) NOT NULL DEFAULT 'UNKNOWN'"),
                         ("kind", "VARCHAR(20) NOT NULL DEFAULT 'secret'"), ("commit_sha", "VARCHAR(64)"), ("commit_author", "VARCHAR(200)"),
                         ("commit_date", "VARCHAR(40)"), ("commits_seen", "INTEGER NOT NULL DEFAULT 0"), ("in_head", "BOOLEAN"),
                         ("ml_probability", "REAL"), ("ml_reasons_json", "TEXT NOT NULL DEFAULT '[]'"), ("context_masked", "TEXT NOT NULL DEFAULT ''"),
                         ("ai_verdict", "VARCHAR(40)"), ("ai_reason", "TEXT"), ("triaged_at", "TIMESTAMP"), ("contained_at", "TIMESTAMP"),
                         ("rotated_at", "TIMESTAMP"), ("verified_at", "TIMESTAMP")]:
            if col not in sf_existing:
                if engine.dialect.name == "sqlite":
                    conn.execute(text(f"ALTER TABLE secret_findings ADD COLUMN {col} {ddl}"))
                else:
                    conn.execute(text(f"ALTER TABLE secret_findings ADD COLUMN IF NOT EXISTS {col} {ddl}"))

WORKSPACE_TABLES = ("users", "password_events", "scans", "secret_findings", "audit_events", "account_audit_reports",
                    "login_events", "notifications", "honeytokens", "honeytoken_trips")
DEMO_EMAILS = ("admin@privpass.local", "analyst@privpass.local", "user@privpass.local")

def _carry_over_breach_flags() -> None:
    """7.3: accounts flagged by the old 'must change password' flow become breach-locked (reset required)."""
    insp = inspect(engine)
    if "users" not in insp.get_table_names():
        return
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET breach_locked = 1, must_change_password = 0 WHERE must_change_password = 1" if engine.dialect.name == "sqlite"
                          else "UPDATE users SET breach_locked = TRUE, must_change_password = FALSE WHERE must_change_password = TRUE"))

def _ensure_workspace_columns() -> None:
    """Add the workspace column to older databases. Existing data is treated as demo data (it was created
    while testing with the shared demo accounts) unless it belongs to a non-demo account."""
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    added = []
    with engine.begin() as conn:
        for t in WORKSPACE_TABLES:
            if t in tables and "workspace" not in {c["name"] for c in insp.get_columns(t)}:
                conn.execute(text(f"ALTER TABLE {t} ADD COLUMN workspace VARCHAR(10) NOT NULL DEFAULT 'demo'"))
                added.append(t)
        if not added:
            return
        if "users" in added:
            stmt = text("UPDATE users SET workspace='live' WHERE email NOT IN :demo").bindparams(bindparam("demo", expanding=True))
            conn.execute(stmt, {"demo": list(DEMO_EMAILS)})
        live_ids = "SELECT id FROM users WHERE workspace='live'"
        for t, col in (("password_events", "user_id"), ("scans", "owner_user_id"), ("secret_findings", "owner_user_id"),
                       ("audit_events", "user_id"), ("account_audit_reports", "owner_user_id"), ("notifications", "user_id"),
                       ("honeytokens", "owner_user_id")):
            if t in added:
                # Table and column names can't be bound parameters; both come from the fixed tuple above, never from input.
                conn.execute(text(f"UPDATE {t} SET workspace='live' WHERE {col} IN ({live_ids})"))  # nosec B608
        if "honeytoken_trips" in added:
            conn.execute(text("UPDATE honeytoken_trips SET workspace=(SELECT workspace FROM honeytokens h WHERE h.id=honeytoken_trips.honeytoken_id)"))

def init_db() -> None:
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _ensure_legacy_columns()
    _ensure_workspace_columns()
    _carry_over_breach_flags()

def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
