"""6.0 security hardening: breach-gate tickets, CSRF, enumeration resistance, DB-backed tokens,
MFA enrolment guard, reset flow and the aggregate-only test-account audit."""
import base64
import hashlib
import hmac
import os

from fastapi.testclient import TestClient

from app.main import app
from conftest import breach_gate, material, verifier_for


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _pw(secret):
    return secret.hex() if isinstance(secret, bytes) else secret


def _signup_body(client, email, password, salt=None, **gate_overrides):
    gate = breach_gate(client)
    gate.update(gate_overrides)
    return {"email": email, **material(_pw(password)), "score": 90,
            "score_label": "Excellent", "breached": False, "breach_gate": gate}


def _new_user(client, pw="A long unique passphrase for tests 2026!"):
    email = "u-" + os.urandom(4).hex() + "@example.com"
    assert client.post("/api/auth/signup", json=_signup_body(client, email, pw)).status_code == 200
    return email, pw


def _proof(password, ch):
    return hmac.new(verifier_for(password, ch), ch["nonce"].encode(), hashlib.sha256).hexdigest()


def _login(client, email, password):
    ch = client.post("/api/auth/challenge", json={"email": email}).json()
    proof = _proof(password, ch)
    res = client.post("/api/auth/login", json={"email": email, "nonce": ch["nonce"], "proof": proof})
    assert res.status_code == 200, res.text
    return ch, proof


def _login_admin(client):
    _login(client, "admin@privpass.local", "PrivPass!Demo#2026-Admin")


def test_signup_requires_a_breach_ticket():
    with TestClient(app) as c:
        salt, verifier = os.urandom(16), os.urandom(32)
        body = _signup_body(c, "noticket@example.com", verifier, salt)
        del body["breach_gate"]
        assert c.post("/api/auth/signup", json=body).status_code == 422
        body = _signup_body(c, "fake-ticket@example.com", verifier, salt, ticket="x" * 43)
        res = c.post("/api/auth/signup", json=body)
        assert res.status_code == 400 and "ticket" in res.json()["detail"]


def test_breach_ticket_is_single_use():
    with TestClient(app) as c:
        salt, verifier = os.urandom(16), os.urandom(32)
        body = _signup_body(c, "once-" + os.urandom(3).hex() + "@example.com", verifier, salt)
        assert c.post("/api/auth/signup", json=body).status_code == 200
        body["email"] = "twice-" + os.urandom(3).hex() + "@example.com"
        assert c.post("/api/auth/signup", json=body).status_code == 400


def test_gate_fails_closed_and_blocks_breached_and_short_passwords():
    with TestClient(app) as c:
        salt, verifier = os.urandom(16), os.urandom(32)
        cases = [
            ({"hibp_status": "breached"}, "compromised"),
            ({"hibp_status": "unavailable", "hibp_mode": "unavailable"}, "fail-closed"),
            ({"hibp_status": "safe", "hibp_mode": "offline-demo"}, "fail-closed"),
            ({"password_length": 14}, "at least 15"),
            ({"password_length": 129}, "at most 128"),
        ]
        for override, message in cases:
            res = c.post("/api/auth/signup", json=_signup_body(c, "gate-" + os.urandom(3).hex() + "@example.com", verifier, salt, **override))
            assert res.status_code == 400, override
            assert message in res.json()["detail"], (override, res.json())
        # A client-declared breached flag is also honoured.
        body = _signup_body(c, "flag@example.com", verifier, salt)
        body["breached"] = True
        assert c.post("/api/auth/signup", json=body).status_code == 400


def test_rejected_attempts_are_counted_without_password_data():
    with TestClient(app) as c:
        ticket = c.post("/api/auth/breach-ticket", json={"purpose": "signup"}).json()["ticket"]
        assert c.post("/api/auth/breach-gate/reject", json={"ticket": ticket, "reason": "breached"}).status_code == 200
        # The same ticket cannot be spent twice (neither on reject nor on signup).
        assert c.post("/api/auth/breach-gate/reject", json={"ticket": ticket, "reason": "breached"}).status_code == 400
        _login_admin(c)
        gate = c.get("/api/admin/overview").json()["gate"]
        assert gate["blocked"] >= 1 and gate["breached"] >= 1


def test_csrf_is_enforced_on_state_changing_requests():
    with TestClient(app) as c:
        res = c.post("/api/auth/breach-ticket", json={"purpose": "signup"}, headers={"X-CSRF-Token": "wrong"})
        assert res.status_code == 403
        c.cookies.clear()
        res = c.request("POST", "/api/auth/challenge", json={"email": "a@example.com"}, skip_csrf=True)
        assert res.status_code == 403 and "csrf" in res.json()["detail"]
        # After login the anonymous cookie token is replaced by the session-bound token.
        email, verifier = _new_user(c)
        anon_token = c.cookies.get("pp_csrf")
        _login(c, email, verifier)
        session_token = c.cookies.get("pp_csrf")
        assert session_token != anon_token
        assert c.post("/api/vault/challenge", json={}, headers={"X-CSRF-Token": anon_token}).status_code == 403
        assert c.post("/api/vault/challenge", json={}).status_code == 200


def test_challenge_does_not_enumerate_accounts():
    with TestClient(app) as c:
        email, verifier = _new_user(c)
        real = c.post("/api/auth/challenge", json={"email": email})
        fake1 = c.post("/api/auth/challenge", json={"email": "nobody-here@example.com"})
        fake2 = c.post("/api/auth/challenge", json={"email": "nobody-here@example.com"})
        assert real.status_code == fake1.status_code == 200
        assert set(real.json()) == set(fake1.json())
        assert fake1.json()["salt_b64"] == fake2.json()["salt_b64"]  # stable decoy salt
        assert len(base64.urlsafe_b64decode(fake1.json()["salt_b64"] + "==")) == 16
        proof = hmac.new(os.urandom(32), fake1.json()["nonce"].encode(), hashlib.sha256).hexdigest()
        unknown = c.post("/api/auth/login", json={"email": "nobody-here@example.com", "nonce": fake1.json()["nonce"], "proof": proof})
        wrong = c.post("/api/auth/login", json={"email": email, "nonce": real.json()["nonce"], "proof": proof})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json()["detail"] == c.post("/api/auth/login", json={"email": email, "nonce": "stale-nonce-value", "proof": proof}).json()["detail"]


def test_login_challenge_is_single_use_and_db_backed():
    with TestClient(app) as c:
        email, verifier = _new_user(c)
        ch, proof = _login(c, email, verifier)
        replay = c.post("/api/auth/login", json={"email": email, "nonce": ch["nonce"], "proof": proof})
        assert replay.status_code == 401
    # A second app client (think: a different worker) validates tokens issued by the first.
    with TestClient(app) as issuer, TestClient(app) as other_worker:
        email, verifier = _new_user(issuer)
        ch = issuer.post("/api/auth/challenge", json={"email": email}).json()
        proof = _proof(verifier, ch)
        assert other_worker.post("/api/auth/login", json={"email": email, "nonce": ch["nonce"], "proof": proof}).status_code == 200


def test_mfa_setup_is_post_and_cannot_overwrite_enabled_mfa():
    from app.security import totp_code
    with TestClient(app) as c:
        email, verifier = _new_user(c)
        _login(c, email, verifier)
        assert c.get("/api/auth/mfa/setup").status_code in (404, 405)  # GET no longer mutates state
        secret = c.post("/api/auth/mfa/setup").json()["secret"]
        assert c.post("/api/auth/mfa/enable", json={"code": totp_code(secret)}).status_code == 200
        assert c.post("/api/auth/mfa/setup").status_code == 409


def test_reset_requires_breach_gate_and_clears_vault_check():
    with TestClient(app) as c:
        email, verifier = _new_user(c)
        token = c.post("/api/auth/reset/request", json={"email": email}).json()["demo_token"]
        assert token
        new_verifier = "Another long replacement passphrase!"
        body = {"token": token, **material(new_verifier), "score": 88,
                "score_label": "Excellent", "breached": False, "breach_gate": breach_gate(c, "reset")}
        # A signup ticket cannot be used for a reset.
        wrong = dict(body, breach_gate=breach_gate(c, "signup"))
        assert c.post("/api/auth/reset/complete", json=wrong).status_code == 400
        assert c.post("/api/auth/reset/complete", json=body).status_code == 200
        _login(c, email, new_verifier)
        # Reset token is single use.
        body["breach_gate"] = breach_gate(c, "reset")
        assert c.post("/api/auth/reset/complete", json=body).status_code == 400


def test_account_audit_stores_aggregates_only_and_requires_privileged_role():
    with TestClient(app) as c:
        email, verifier = _new_user(c)
        _login(c, email, verifier)
        payload = {"source_name": "sample-accounts.csv", "total": 40, "breached": 12, "unverified": 0, "below_policy": 16, "hibp_mode": "live"}
        assert c.post("/api/audit/accounts", json=payload).status_code == 403
        _login_admin(c)
        assert c.post("/api/audit/accounts", json=dict(payload, breached=41)).status_code == 400
        saved = c.post("/api/audit/accounts", json=payload).json()
        assert saved["breached_percent"] == 30.0
        assert set(saved) >= {"total", "breached", "unverified", "below_policy", "hibp_mode"}
        overview = c.get("/api/admin/overview").json()
        assert overview["account_audit"]["breached_percent"] == 30.0
        csv = c.get("/api/admin/report.csv").text
        assert "test_account_breached_percent,30.0" in csv


def test_no_synthetic_password_telemetry_is_seeded():
    with TestClient(app) as c:
        _login_admin(c)
        import app.db as dbmod
        from app.models import PasswordEvent
        with dbmod.SessionLocal() as s:
            assert s.query(PasswordEvent).filter(PasswordEvent.event_type == "demo_check").count() == 0


def test_sample_account_list_is_served_in_demo_mode():
    with TestClient(app) as c:
        res = c.get("/api/demo/sample-accounts.csv")
        assert res.status_code == 200
        lines = [line for line in res.text.splitlines() if line and not line.startswith("#")]
        assert lines[0] == "email,password" and len(lines) == 41
