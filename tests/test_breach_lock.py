"""7.3: server-enforced breach protection - legacy upgrade, storage safety, passkey lock, admin re-check."""
from __future__ import annotations

import base64
import hashlib
import os

from fastapi.testclient import TestClient

from app.main import app
from conftest import login_as, signup_as, real_admin


def _legacy_user(email: str, password: str) -> None:
    """An account created before 7.3 (v1 verifier, no breach-watch record)."""
    import app.db as dbmod
    from app.models import User
    from app.security import encrypt_verifier, uid, verifier_integrity
    e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    salt = os.urandom(16)
    vb = e(hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000, 32))
    with dbmod.SessionLocal() as s:
        s.add(User(id=uid(), email=email, role="user", workspace="live", verifier_ciphertext=encrypt_verifier(vb), verifier_hash=verifier_integrity(vb),
                   salt_b64=e(salt), vault_salt_b64=e(os.urandom(16)), kdf_version=1))
        s.commit()


def _user(email):
    import app.db as dbmod
    from app.models import User
    with dbmod.SessionLocal() as s:
        u = s.query(User).filter(User.email == email).first()
        s.expunge(u)
        return u


def test_legacy_accounts_upgrade_at_sign_in_and_are_checked_by_the_server(hibp):
    with TestClient(app) as c:
        email = "legacy-" + os.urandom(3).hex() + "@example.com"
        _legacy_user(email, "legacy clean passphrase 2026")
        assert c.post("/api/auth/challenge", json={"email": email}).json()["kdf"] == 1
        assert login_as(c, email, "legacy clean passphrase 2026").status_code == 200
        u = _user(email)
        assert u.kdf_version == 2 and u.watch_mac and u.breach_check_status == "safe"
        c.post("/api/auth/logout")
        assert login_as(c, email, "legacy clean passphrase 2026").status_code == 200     # works with the new bound credential

        email2 = "legacy-breached-" + os.urandom(3).hex() + "@example.com"
        _legacy_user(email2, "legacy breached passphrase")
        hibp.breach("legacy breached passphrase")
        assert login_as(c, email2, "legacy breached passphrase").status_code == 423       # upgraded, checked and locked at once
        assert _user(email2).breach_locked is True


def test_nothing_useful_to_a_password_cracker_is_stored_in_the_clear(hibp):
    with TestClient(app) as c:
        email = "store-" + os.urandom(3).hex() + "@example.com"
        pw = "storage check passphrase 2026"
        assert signup_as(c, email, pw).status_code == 200
        u = _user(email)
        sha1 = hashlib.sha1(pw.encode()).hexdigest().upper()
        row = " ".join(str(v) for v in (u.watch_prefix_ct, u.watch_mac, u.watch_salt_b64, u.verifier_ciphertext, u.verifier_hash)).upper()
        assert sha1[:5] not in u.watch_prefix_ct.upper()            # prefix sealed with the server key
        assert sha1 not in row and sha1[5:] not in row and pw.upper() not in row
        assert len(u.watch_mac) == 64                                # HMAC(pepper, watch) only


def test_passkeys_cannot_bypass_a_breach_lock(hibp):
    import app.main as m
    with TestClient(app) as c:
        email = "pk-" + os.urandom(3).hex() + "@example.com"
        pw = "passkey owner passphrase 2026"
        assert signup_as(c, email, pw).status_code == 200 and login_as(c, email, pw).status_code == 200
        hibp.breach(pw)
        m.breach_watch_sweep("live")
        # Every route, including passkey sign-in (checked in app/account.py), refuses a locked account.
        assert c.get("/api/auth/passkeys").status_code == 423
        assert login_as(c, email, pw).status_code == 423


def test_admin_can_run_the_breach_watch_now_and_sees_locked_accounts(hibp):
    with TestClient(app) as owner, TestClient(app) as c:
        email = "sweep-" + os.urandom(3).hex() + "@example.com"
        pw = "sweep target passphrase 2026"
        assert signup_as(c, email, pw).status_code == 200
        real_admin(owner)
        hibp.breach(pw)
        stats = owner.post("/api/admin/breach-watch/run").json()
        assert stats["locked"] >= 1 and stats["checked"] >= 2
        row = next(u for u in owner.get("/api/admin/users").json() if u["email"] == email)
        assert row["breach_locked"] is True and row["breach_check_status"] == "breached"
        assert any("locked" in n["title"].lower() for n in owner.get("/api/notifications").json()["items"])


def test_old_must_change_flags_become_locks_on_upgrade():
    import app.db as dbmod
    from sqlalchemy import text
    email = "flagged-" + os.urandom(3).hex() + "@example.com"
    _legacy_user(email, "old flagged passphrase 2026")
    with dbmod.engine.begin() as conn:
        conn.execute(text("UPDATE users SET must_change_password = :t WHERE email = :e"), {"t": True, "e": email})
    dbmod._carry_over_breach_flags()
    u = _user(email)
    assert u.breach_locked is True and not u.must_change_password
