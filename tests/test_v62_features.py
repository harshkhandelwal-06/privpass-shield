"""6.2: notifications, honeytokens, fix deadlines (SLA), breach re-check + forced password change with
vault re-encryption, passkeys (real WebAuthn ceremony with a software authenticator), GitHub fix PRs
(mocked GitHub API), offline breach corpus, breach-mode policy, drop-in widget page."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import zipfile
from datetime import timedelta
from pathlib import Path

import cbor2
import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.main import app
from conftest import breach_gate

ROOT = Path(__file__).resolve().parents[1]
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def new_user(c, pw="A long unique passphrase for tests 2026!"):
    from conftest import signup_as
    pw = pw.decode() if isinstance(pw, bytes) else pw
    email = "u-" + os.urandom(4).hex() + "@example.com"
    assert signup_as(c, email, pw).status_code == 200
    assert login(c, email, pw).status_code == 200
    return email, pw


def login(c, email, password):
    from conftest import login_as
    return login_as(c, email, password.decode() if isinstance(password, bytes) else password)


def admin(c):
    assert login(c, "admin@privpass.local", "PrivPass!Demo#2026-Admin").status_code == 200


def upload(c, files: dict, name="repo.zip"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    r = c.post("/api/scans/upload", files={"file": (name, buf.getvalue(), "application/zip")})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- notifications
def test_critical_scan_raises_a_notification_and_read_all():
    with TestClient(app) as c:
        new_user(c)
        upload(c, {"billing.py": f'STRIPE_KEY = "{STRIPE}"\n'})
        n = c.get("/api/notifications").json()
        assert n["unread"] >= 1 and "CRITICAL" in n["items"][0]["title"] and STRIPE not in json.dumps(n)
        c.post("/api/notifications/read-all")
        assert c.get("/api/notifications").json()["unread"] == 0


# ---------------------------------------------------------------- honeytokens
def test_honeytoken_trip_alerts_and_decoys_the_attacker():
    with TestClient(app) as c:
        new_user(c)
        h = c.post("/api/honeytokens", json={"label": "payments .env", "kind": "api_key"}).json()
        assert h["token"].startswith("ppk_live_") and h["token"] in h["snippet"]
        listing = c.get("/api/honeytokens").json()
        assert h["token"] not in json.dumps(listing)                 # raw token is never shown again
        with TestClient(app) as attacker:                            # no session, no CSRF token
            r = attacker.request("POST", "/api/canary/v1/charges", headers={"Authorization": f"Bearer {h['token']}"}, json={"amount": 1}, skip_csrf=True)
            assert r.status_code == 401 and r.json()["error"] == "invalid_api_key"
            assert attacker.request("POST", "/api/canary/v1/charges", headers={"Authorization": "Bearer ppk_live_notreal"}, skip_csrf=True).status_code == 401
        row = next(x for x in c.get("/api/honeytokens").json() if x["id"] == h["id"])
        assert row["trips"] == 1 and row["recent"][0]["ip"]
        assert any("Honeytoken tripped" in i["title"] and i["severity"] == "CRITICAL" for i in c.get("/api/notifications").json()["items"])


def test_canary_url_and_scanner_recognises_own_honeytokens():
    with TestClient(app) as c:
        new_user(c)
        h = c.post("/api/honeytokens", json={"label": "backup link", "kind": "url"}).json()
        assert c.get(f"/c/{h['token']}").status_code == 404
        assert c.get("/api/honeytokens").json()[0]["trips"] == 1
        k = c.post("/api/honeytokens", json={"label": "api key", "kind": "api_key"}).json()
        body = upload(c, {".env": k["snippet"]})
        bait = [f for f in body["findings"] if f["validity"] == "HONEYTOKEN"]
        assert bait and bait[0]["severity"] == "LOW" and "leave it in place" in bait[0]["reason"]


def test_csrf_exemption_is_only_for_canary_paths():
    with TestClient(app) as c:
        assert c.request("POST", "/api/honeytokens", json={"label": "x1", "kind": "api_key"}, skip_csrf=True).status_code == 403


# ---------------------------------------------------------------- fix deadlines
def test_sla_countdown_rotation_and_metrics():
    import app.db as dbmod
    from app.models import SecretFinding
    with TestClient(app) as c:
        new_user(c)
        f = upload(c, {"billing.py": f'STRIPE_KEY = "{STRIPE}"\n'})["findings"][0]
        assert f["sla"]["sla_hours"] == 4 and 3.9 < f["sla"]["remaining_hours"] <= 4 and f["sla"]["state"] == "on_track"
        for st in ("TRIAGED", "CONTAINED", "ROTATED"):
            assert c.post(f"/api/findings/{f['id']}/transition", json={"status": st}).status_code == 200
        inc = c.get("/api/incidents").json()["incidents"][0]
        assert inc["sla"]["state"] == "met"
        g = upload(c, {"a.py": f'STRIPE_KEY = "{STRIPE}"\n'}, "late.zip")["findings"][0]
        with dbmod.SessionLocal() as s:
            row = s.get(SecretFinding, g["id"]); row.created_at = row.created_at - timedelta(hours=6); s.commit()
        assert c.get("/api/incidents").json()["incidents"][0]["sla"]["state"] == "overdue"
    with TestClient(app) as a:
        from conftest import real_admin
        real_admin(a)                     # the user above is a live account
        sla = a.get("/api/admin/overview").json()["sla"]
        assert sla["overdue"] >= 1 and sla["mean_hours_to_rotate"] is not None


# ---------------------------------------------------------------- 7.3 server-side breach watch: lock, sign out, reset
def test_breach_watch_locks_account_ends_every_session_and_requires_reset(hibp):
    from conftest import material
    with TestClient(app) as c, TestClient(app) as other_device:
        email, pw = new_user(c)
        assert login(other_device, email, pw).status_code == 200
        hibp.breach(pw, 777)                                                       # the password leaks after sign-up
        r = c.post("/api/auth/breach-recheck")                                     # server re-checks; nothing comes from the browser
        assert r.status_code == 423 and "password breached" in r.json()["detail"]
        for client in (c, other_device):                                            # every session is locked out, in session or not
            assert client.get("/api/findings").status_code == 423
            assert client.get("/api/auth/me").status_code == 423
        assert login(c, email, pw).status_code == 423                             # the breached password can't sign in again
        # Reset is the only way back in, and the new password is checked by the server too.
        token = c.post("/api/auth/reset/request", json={"email": email}).json()["demo_token"]
        hibp.breach("Leaked replacement passphrase 2026!")
        bad = c.post("/api/auth/reset/complete", json={"token": token, **material("Leaked replacement passphrase 2026!"), "score": 90, "score_label": "x",
                                                       "breached": False, "breach_gate": breach_gate(c, "reset")})
        assert bad.status_code == 400 and "breaches" in bad.json()["detail"]
        token = c.post("/api/auth/reset/request", json={"email": email}).json()["demo_token"]
        ok = c.post("/api/auth/reset/complete", json={"token": token, **material("A fresh unique passphrase 2026!"), "score": 90, "score_label": "x",
                                                      "breached": False, "breach_gate": breach_gate(c, "reset")})
        assert ok.status_code == 200
        assert login(c, email, pw).status_code == 401 and login(c, email, "A fresh unique passphrase 2026!").status_code == 200
        assert c.get("/api/auth/me").json()["breach_locked"] is False


def test_background_sweep_locks_accounts_that_are_not_signed_in(hibp):
    import app.main as m
    with TestClient(app) as c:
        email, pw = new_user(c)
        c.post("/api/auth/logout")
        hibp.breach(pw)
        stats = m.breach_watch_sweep(None)                                         # the scheduled job
        assert stats["locked"] >= 1
        assert login(c, email, pw).status_code == 423


def test_server_rejects_breached_password_even_if_the_browser_says_safe(hibp):
    from conftest import material
    with TestClient(app) as c:
        hibp.breach("password-that-leaked-2026")
        body = {"email": "liar-" + os.urandom(3).hex() + "@example.com", **material("password-that-leaked-2026"), "score": 99,
                "score_label": "Excellent", "breached": False, "breach_gate": breach_gate(c)}   # the browser claims "safe"
        r = c.post("/api/auth/signup", json=body)
        assert r.status_code == 400 and "verified by the server" in r.json()["detail"]
        hibp.down = True                                                           # server can't verify -> fail closed
        body = {"email": "down-" + os.urandom(3).hex() + "@example.com", **material("unique passphrase while hibp is down"), "score": 90,
                "score_label": "x", "breached": False, "breach_gate": breach_gate(c)}
        assert c.post("/api/auth/signup", json=body).status_code == 503


def test_a_lying_browser_cannot_sign_in_with_the_breached_password(hibp):
    """A modified client registers the checked values of a CLEAN password while the person 'uses' a breached one.
    The server derives the verifier from what it checked, so the breached password never works."""
    from conftest import material, login_as
    with TestClient(app) as c:
        hibp.breach("breached-but-liked-2026")
        email = "cheat-" + os.urandom(3).hex() + "@example.com"
        clean = material("some clean decoy passphrase 2026")
        body = {"email": email, **clean, "score": 90, "score_label": "x", "breached": False, "breach_gate": breach_gate(c)}
        assert c.post("/api/auth/signup", json=body).status_code == 200
        assert login_as(c, email, "breached-but-liked-2026").status_code == 401   # the breached password is useless here
        # Lying about the prefix instead: the account's secret becomes password + an unknown prefix, so the real
        # breached password (as any normal client derives it) still fails.
        email2 = "cheat2-" + os.urandom(3).hex() + "@example.com"
        m = material("breached-but-liked-2026"); m["prefix"] = "00000" if m["prefix"] != "00000" else "11111"
        assert c.post("/api/auth/signup", json={"email": email2, **m, "score": 90, "score_label": "x", "breached": False,
                                                "breach_gate": breach_gate(c)}).status_code == 200
        assert login_as(c, email2, "breached-but-liked-2026").status_code == 401


def test_change_password_reencrypts_vault_and_signs_out_other_sessions(hibp):
    from conftest import material, verifier_for
    with TestClient(app) as c, TestClient(app) as other_device:
        email, pw = new_user(c)
        assert login(other_device, email, pw).status_code == 200
        ids = [c.post("/api/vault/items", json={"ciphertext_b64": '{"v":1,"iv":"AAAA","ct":"' + "B" * 60 + str(i) + '"}'}).json()["id"] for i in range(2)]

        def attempt(items, password=pw, new_pw="Brand new unique passphrase 2026"):
            ch = c.post("/api/auth/change-password/challenge").json()
            key = verifier_for(password, ch)
            return c.post("/api/auth/change-password", json={
                "nonce": ch["nonce"], "proof": hmac.new(key, ch["nonce"].encode(), hashlib.sha256).hexdigest(),
                **material(new_pw), "score": 90, "score_label": "Excellent", "breached": False,
                "breach_gate": breach_gate(c, "change"), "vault_salt_b64": b64e(os.urandom(16)), "vault_check_ciphertext": None,
                "items": items})
        assert attempt([{"id": ids[0], "ciphertext_b64": "x" * 60}]).status_code == 409          # partial re-encryption refused
        assert attempt([{"id": i, "ciphertext_b64": "x" * 60} for i in ids], password="wrong password entirely").status_code == 401
        hibp.breach("Leaked new passphrase 2026")
        assert attempt([{"id": i, "ciphertext_b64": "x" * 60} for i in ids], new_pw="Leaked new passphrase 2026").status_code == 400
        r = attempt([{"id": i, "ciphertext_b64": "NEW" + "x" * 60} for i in ids])
        assert r.status_code == 200 and r.json()["reencrypted"] == 2
        assert all(x["ciphertext_b64"].startswith("NEW") for x in c.get("/api/vault/items").json())
        assert other_device.get("/api/auth/me").status_code == 401             # other sessions signed out
        c.post("/api/auth/logout")
        assert login(c, email, pw).status_code == 401 and login(c, email, "Brand new unique passphrase 2026").status_code == 200


# ---------------------------------------------------------------- passkeys: full WebAuthn ceremony with a software authenticator
class SoftAuthenticator:
    def __init__(self, rp_id="testserver", origin="http://testserver"):
        self.key = ec.generate_private_key(ec.SECP256R1()); self.cred_id = os.urandom(32); self.count = 0
        self.rp_hash = hashlib.sha256(rp_id.encode()).digest(); self.origin = origin

    def _cose(self):
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def create(self, opts):
        cdj = json.dumps({"type": "webauthn.create", "challenge": opts["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        auth = self.rp_hash + bytes([0x45]) + (0).to_bytes(4, "big") + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + self._cose()
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64e(self.cred_id), "rawId": b64e(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64e(cdj), "attestationObject": b64e(att), "transports": ["internal"]}}

    def get(self, opts):
        self.count += 1
        cdj = json.dumps({"type": "webauthn.get", "challenge": opts["challenge"], "origin": self.origin, "crossOrigin": False}).encode()
        auth = self.rp_hash + bytes([0x05]) + self.count.to_bytes(4, "big")
        sig = self.key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64e(self.cred_id), "rawId": b64e(self.cred_id), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64e(cdj), "authenticatorData": b64e(auth), "signature": b64e(sig), "userHandle": None}}


def test_passkey_register_and_passwordless_sign_in():
    dev = SoftAuthenticator()
    with TestClient(app) as c:
        email, _ = new_user(c)
        opts = c.post("/api/auth/passkeys/register/begin").json()
        assert opts["rp"]["id"] == "testserver" and opts["authenticatorSelection"]["residentKey"] == "required"
        r = c.post("/api/auth/passkeys/register/finish", json={"credential": dev.create(opts), "name": "Test key"})
        assert r.status_code == 200, r.text
        assert c.get("/api/auth/passkeys").json()[0]["name"] == "Test key"
    with TestClient(app) as fresh:
        opts = fresh.post("/api/auth/passkeys/login/begin").json()
        r = fresh.post("/api/auth/passkeys/login/finish", json={"credential": dev.get(opts)})
        assert r.status_code == 200, r.text
        assert r.json()["method"] == "passkey" and fresh.get("/api/auth/me").json()["email"] == email
        replay = fresh.post("/api/auth/passkeys/login/finish", json={"credential": dev.get(opts)})
        assert replay.status_code == 401                                          # single-use challenge
        other = SoftAuthenticator()
        o2 = fresh.post("/api/auth/passkeys/login/begin").json()
        assert fresh.post("/api/auth/passkeys/login/finish", json={"credential": other.get(o2)}).status_code == 401


def test_passkeys_refuse_ip_address_hosts():
    with TestClient(app, base_url="http://127.0.0.1") as c:
        r = c.post("/api/auth/passkeys/login/begin")
        assert r.status_code == 400 and "localhost" in r.json()["detail"]


# ---------------------------------------------------------------- GitHub fix PR (mocked GitHub API)
def test_github_fix_pr_patches_the_real_file_without_the_secret(monkeypatch):
    import app.db as dbmod
    from app import github
    from app.models import Scan, SecretFinding
    file_text = f'import stripe\nSTRIPE_KEY = "{STRIPE}"\nprint("ok")\n'
    calls = {}

    def handler(req: httpx.Request):
        p, m = req.url.path, req.method
        assert req.headers["authorization"] == "Bearer ghp_test_token_value"
        if m == "GET" and p == "/repos/acme/pay":
            return httpx.Response(200, json={"default_branch": "main"})
        if m == "GET" and p.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "abc123"}})
        if m == "GET" and p.endswith("/contents/billing.py"):
            return httpx.Response(200, json={"content": base64.b64encode(file_text.encode()).decode(), "sha": "filesha"})
        if m == "POST" and p.endswith("/git/refs"):
            calls["ref"] = json.loads(req.content); return httpx.Response(201, json={})
        if m == "PUT" and p.endswith("/contents/billing.py"):
            calls["put"] = json.loads(req.content); return httpx.Response(201, json={})
        if m == "POST" and p.endswith("/pulls"):
            calls["pr"] = json.loads(req.content); return httpx.Response(201, json={"html_url": "https://github.com/acme/pay/pull/7"})
        return httpx.Response(404)

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_token_value")
    monkeypatch.setattr(github, "http_client", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    with TestClient(app) as c:
        new_user(c)
        body = upload(c, {"billing.py": file_text})
        fid = next(f["id"] for f in body["findings"] if f["type"] == "Stripe secret key")
        with dbmod.SessionLocal() as s:
            f = s.get(SecretFinding, fid); scan = s.get(Scan, f.scan_id)
            scan.source_url = "https://github.com/acme/pay"; f.file_path = "billing.py"; s.commit()
        r = c.post(f"/api/github/fix-pr/{fid}")
        assert r.status_code == 200, r.text
        assert r.json()["pr_url"].endswith("/pull/7") and calls["ref"]["ref"].startswith("refs/heads/privpass/fix-")
        new_file = base64.b64decode(calls["put"]["content"]).decode()
        assert STRIPE not in new_file and 'STRIPE_KEY = os.environ["STRIPE_KEY"]' in new_file and new_file.startswith("import os\n")
        assert STRIPE not in json.dumps(calls["pr"]) and "Rotate it first" in calls["pr"]["body"]
        file_text = 'import stripe\nSTRIPE_KEY = os.environ["X"]\n'   # file changed since the scan
        assert c.post(f"/api/github/fix-pr/{fid}").status_code == 409


def test_github_scan_rejects_non_github_urls():
    with TestClient(app) as c:
        new_user(c)
        for bad in ("https://evil.example/owner/repo", "file:///etc/passwd", "https://github.com/owner/repo;rm -rf"):
            assert c.post("/api/scans/github", json={"url": bad}).status_code == 400


# ---------------------------------------------------------------- offline corpus, breach-mode policy, widget
def test_offline_breach_corpus_bloom_filter():
    import random, string, sys
    sys.path.insert(0, str(ROOT / "tools"))
    from build_breach_bloom import indices
    bits = (ROOT / "static" / "breach" / "top1m.bloom").read_bytes()
    meta = json.loads((ROOT / "static" / "breach" / "top1m.json").read_text())
    has = lambda pw: all(bits[i >> 3] & (1 << (i & 7)) for i in indices(hashlib.sha1(pw.encode()).digest(), meta["k"], meta["m"]))
    assert all(has(p) for p in ("password", "123456", "iloveyou", "qwerty123"))
    rng = random.Random(7)
    fp = sum(has("".join(rng.choice(string.ascii_letters + string.digits) for _ in range(16))) for _ in range(5000))
    assert fp / 5000 < 0.004


def test_local_corpus_mode_is_rejected_unless_policy_allows(monkeypatch, hibp):
    from conftest import material
    hibp.down = True                       # HIBP unreachable: only the policy fallback can accept the offline corpus
    with TestClient(app) as c:
        body = lambda: {"email": "lc-" + os.urandom(3).hex() + "@example.com", **material("offline corpus passphrase 2026"), "score": 90,
                        "score_label": "Excellent", "breached": False, "breach_gate": {**breach_gate(c), "hibp_mode": "local-corpus"}}
        assert c.post("/api/auth/signup", json=body()).status_code == 400
        monkeypatch.setenv("PRIVPASS_BREACH_FALLBACK", "local")
        assert "local-corpus" in c.post("/api/auth/breach-ticket", json={"purpose": "signup"}).json()["policy"]["accepted_modes"]
        assert c.post("/api/auth/signup", json=body()).status_code == 200


def test_acme_widget_demo_page_is_served():
    with TestClient(app) as c:
        r = c.get("/demo/acme")
        assert r.status_code == 200 and "<privpass-password-field" in r.text and "Fictional company" in r.text
        assert c.get("/static/widget/privpass-password-field.js").status_code == 200


# ---------------------------------------------------------------- admin demo simulations
def _make_demo(email):
    """Move a freshly created account into the demo workspace (simulations only run there)."""
    import app.db as dbmod
    from app.models import User
    with dbmod.SessionLocal() as s:
        u = s.query(User).filter(User.email == email).first(); u.workspace = "demo"; s.commit()
        return u.id


def test_breach_simulation_is_admin_only_and_fully_removable(monkeypatch):
    import app.db as dbmod
    from app.models import LoginEvent, User
    with TestClient(app) as victim, TestClient(app) as a:
        email, pw = new_user(victim)
        vid = _make_demo(email)
        assert victim.post("/api/admin/simulate/breach", json={"user_id": vid}).status_code == 403   # not an admin
        admin(a)
        r = a.post("/api/admin/simulate/breach", json={"user_id": vid}).json()
        assert r["target"] == email and r["simulated_breached_users"] == 1
        assert victim.get("/api/findings").status_code == 423                                      # victim is locked, session ended
        assert "simulation" in victim.get("/api/findings").json()["detail"]                        # and told it's a demo simulation
        assert login(victim, email, pw).status_code == 423                                        # can't sign back in either
        assert any(i["title"].startswith("[SIMULATION]") for i in a.get("/api/notifications").json()["items"])
        a.post("/api/ai/anomalies/simulate")
        st = a.get("/api/admin/simulations").json()
        assert st["simulated_login_events"] > 200 and email in st["breached_users"] and st["simulation_alerts"] >= 2
        cleared = a.post("/api/admin/simulations/clear").json()
        assert cleared["users_unlocked"] == 1 and cleared["removed_login_events"] > 200
        assert cleared["simulated_login_events"] == cleared["simulated_breached_users"] == cleared["simulation_alerts"] == 0
        assert login(victim, email, pw).status_code == 200                                        # unlocked again
        assert victim.get("/api/findings").status_code == 200
        with dbmod.SessionLocal() as s:
            assert s.query(LoginEvent).filter(LoginEvent.reason.like("sim_%")).count() == 0
        events = [e["event"] for e in a.get("/api/admin/audit").json()]
        assert "SIMULATION_BREACH" in events and "SIMULATIONS_CLEARED" in events                   # audit trail kept


def test_clearing_simulations_never_unlocks_a_real_breach(hibp):
    import app.db as dbmod
    from app.models import User
    with TestClient(app) as victim, TestClient(app) as a:
        email, pw = new_user(victim)
        vid = _make_demo(email)
        hibp.breach(pw)
        assert victim.post("/api/auth/breach-recheck").status_code == 423                        # a REAL server-side re-check
        admin(a)
        assert a.post("/api/admin/simulate/breach", json={"user_id": vid}).status_code == 409    # can't overwrite a real lock
        a.post("/api/admin/simulations/clear")
        assert login(victim, email, pw).status_code == 423                                        # still locked - it was real


def test_simulations_disabled_in_production(monkeypatch):
    import app.features as feats
    import app.config as cfg
    with TestClient(app) as a:
        admin(a)
        monkeypatch.setattr(cfg, "APP_ENV", "production")
        assert a.get("/api/admin/simulations").status_code == 404
        assert a.post("/api/admin/simulations/clear").status_code == 404
