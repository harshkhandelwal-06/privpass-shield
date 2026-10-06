from __future__ import annotations
import base64, hashlib, os, unicodedata
from .db import SessionLocal, init_db, DEMO, LIVE
from .config import RUNTIME, APP_ENV
from .models import User, AuditEvent
from .security import uid, b64e, encrypt_verifier, verifier_integrity, decrypt_verifier, verify_verifier_hash

DEMO_ADMIN_EMAIL = "admin@privpass.local"
DEMO_ADMIN_PASSWORD = "PrivPass!Demo#2026-Admin"
DEMO_ANALYST_EMAIL = "analyst@privpass.local"
DEMO_ANALYST_PASSWORD = "PrivPass!Demo#2026-Analyst"
DEMO_USER_EMAIL = "user@privpass.local"
DEMO_USER_PASSWORD = "PrivPass!Demo#2026-User"
ITERATIONS = 310000

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def create_verifier(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", unicodedata.normalize("NFKC", password).encode(), salt, ITERATIONS, dklen=32)

def _password_matches(user, password: str) -> bool:
    from .breachwatch import derive_verifier, derive_watch
    try:
        existing = decrypt_verifier(user.verifier_ciphertext).decode()
        if not verify_verifier_hash(user.verifier_hash, existing):
            return False
        salt = _b64d(user.salt_b64)
        if (user.kdf_version or 1) >= 2 and user.watch_salt_b64:
            h = hashlib.sha1(unicodedata.normalize("NFKC", password).encode()).hexdigest().upper()  # nosec B324 secretguard:allow - HIBP k-anonymity format, never stored
            return hmac_equal(existing, b64e(derive_verifier(derive_watch(h, _b64d(user.watch_salt_b64)), h[:5], salt)))
        return hmac_equal(existing, b64e(create_verifier(password, salt)))
    except Exception:
        return False   # stale local account (e.g. created with an old APP_SECRET): reset it below


def ensure_demo_user(s, email: str, password: str, role: str, workspace: str = DEMO):
    """Create or repair a server-provisioned account (demo accounts, env-configured admin) with a v2 bound credential."""
    from .breachwatch import install, material_from_password
    user = s.query(User).filter(User.email == email).first()
    if user and _password_matches(user, password):
        if not getattr(user, "vault_salt_b64", ""):
            user.vault_salt_b64 = b64e(os.urandom(16))
        if (user.kdf_version or 1) < 2 or not user.watch_mac:
            install(user, *material_from_password(password))   # upgrade in place; the vault key is separate and unaffected
        user.workspace = workspace
        return user
    if user is None:
        user = User(id=uid(), email=email, role=role, workspace=workspace, vault_salt_b64=b64e(os.urandom(16)))
        s.add(user)
    else:
        user.vault_salt_b64 = b64e(os.urandom(16)); user.vault_check_ciphertext = None
    install(user, *material_from_password(password))
    user.role = role; user.is_active = True; user.workspace = workspace
    return user

def ensure_demo_admin():
    init_db()
    ensure_real_admin()
    with SessionLocal() as s:
        admin = ensure_demo_user(s, DEMO_ADMIN_EMAIL, DEMO_ADMIN_PASSWORD, "admin")
        analyst = ensure_demo_user(s, DEMO_ANALYST_EMAIL, DEMO_ANALYST_PASSWORD, "analyst")
        demo_user = ensure_demo_user(s, DEMO_USER_EMAIL, DEMO_USER_PASSWORD, "user")
        s.flush()   # write the accounts before rows that reference them (PostgreSQL enforces foreign keys)
        # No synthetic password telemetry is seeded: every metric in the Command Center comes from
        # real breach-gate attempts or an explicit test-account audit.
        s.add(AuditEvent(id=uid(), user_id=admin.id, event_type="DEMO_ENV_READY", severity="INFO", metadata_json='{"accounts":3}', workspace=DEMO))
        s.commit()
    print(f"Demo admin: {DEMO_ADMIN_EMAIL}")
    print(f"Demo admin password: {DEMO_ADMIN_PASSWORD}")
    print(f"Demo analyst: {DEMO_ANALYST_EMAIL}")
    print(f"Demo analyst password: {DEMO_ANALYST_PASSWORD}")
    print(f"Demo user: {DEMO_USER_EMAIL}")
    print(f"Demo user password: {DEMO_USER_PASSWORD}")


# ------------------------------------------------------------------ the real (non-demo) admin
ADMIN_FILE = RUNTIME / "ADMIN-CREDENTIALS.txt"
_WORDS = ("amber anchor atlas aurora beacon birch canyon cedar cobalt comet copper coral delta ember falcon forest galaxy harbor hazel "
          "lantern maple meadow meridian meteor nebula orbit otter quartz saffron signal silver solstice sparrow summit thunder topaz "
          "velvet violet willow zenith glacier granite lotus magnet mosaic pebble phoenix prairie raven ripple sable spruce tangerine").split()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hmac_equal(a: str, b: str) -> bool:
    import hmac as _h
    return _h.compare_digest(a.encode(), b.encode())


def generate_admin_password() -> str:
    import secrets
    words = [secrets.choice(_WORDS).capitalize() for _ in range(4)]
    return "-".join(words) + "-" + str(secrets.randbelow(900) + 100)


def ensure_real_admin(reset: bool = False) -> tuple[str, str | None]:
    """The real admin lives in the *live* workspace: it never sees demo data and is never listed in the Demo Center.

    Credentials come from PRIVPASS_ADMIN_EMAIL / PRIVPASS_ADMIN_PASSWORD in .env. Without them, a strong password is
    generated once and written to runtime/ADMIN-CREDENTIALS.txt (that folder is never packaged or committed).
    Returns (email, password-if-newly-set)."""
    from .db import workspace_scope
    email = (os.getenv("PRIVPASS_ADMIN_EMAIL") or "owner@privpass.local").strip().lower()
    env_password = os.getenv("PRIVPASS_ADMIN_PASSWORD", "").strip()
    if email in (DEMO_ADMIN_EMAIL, DEMO_ANALYST_EMAIL, DEMO_USER_EMAIL):
        raise SystemExit("PRIVPASS_ADMIN_EMAIL must not be one of the public demo accounts")
    from . import config as cfg
    if cfg.APP_ENV == "production" and not env_password:
        # A server's filesystem isn't somewhere you can read a generated password from, so production needs it set.
        print("NOTE: no real admin created. Set PRIVPASS_ADMIN_EMAIL and PRIVPASS_ADMIN_PASSWORD (15+ characters) to create one.")
        return email, None
    if env_password and len(env_password) < 15:
        print("WARNING: PRIVPASS_ADMIN_PASSWORD is shorter than 15 characters; the password policy requires 15+.")
    with workspace_scope(None), SessionLocal() as s:
        user = s.query(User).filter(User.email == email).first()
        new_password = None
        if env_password:
            ensure_demo_user(s, email, env_password, "admin", workspace=LIVE)
        elif user is None or reset:
            new_password = generate_admin_password()
            if user is None:
                ensure_demo_user(s, email, new_password, "admin", workspace=LIVE)
            else:
                from .breachwatch import install, material_from_password
                install(user, *material_from_password(new_password))
                user.vault_salt_b64 = b64e(os.urandom(16)); user.vault_check_ciphertext = None
                user.breach_locked = False; user.breach_flag_source = None
                user.is_active = True; user.role = "admin"; user.workspace = LIVE
            ADMIN_FILE.write_text(
                "PrivPass Shield - REAL admin account (private: not shown in the Demo Center)\n"
                f"Email:    {email}\nPassword: {new_password}\n\n"
                "Change it after signing in (account menu > Security settings), or set PRIVPASS_ADMIN_EMAIL and\n"
                "PRIVPASS_ADMIN_PASSWORD in .env. Delete this file once you have stored the password safely.\n", encoding="utf-8")
        else:
            user.role = "admin"; user.workspace = LIVE
        s.commit()
    if new_password:
        print(f"Real admin account: {email}  (password saved to {ADMIN_FILE})")
    return email, new_password
