"""7.1: demo and live workspaces are isolated, the real admin is private, and demo accounts are restricted."""
from __future__ import annotations

import base64
import hashlib
import io
import os
import zipfile

from fastapi.testclient import TestClient

from app.main import app
from conftest import REAL_ADMIN_EMAIL, breach_gate, login_as, real_admin

DEMO_ADMIN = ("admin@privpass.local", "PrivPass!Demo#2026-Admin")
DEMO_USER = ("user@privpass.local", "PrivPass!Demo#2026-User")
STRIPE = "sk_live_" + "51HcQzQ2eZvKYlo2C0FAKEb9x7Qv"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def live_user(c):
    from conftest import signup_as
    email = f"live-{os.urandom(4).hex()}@example.com"
    assert signup_as(c, email, "a-long-unique-live-passphrase-2026").status_code == 200
    assert login_as(c, email, "a-long-unique-live-passphrase-2026").status_code == 200
    return email


def upload(c, name):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("billing.py", f'STRIPE_KEY = "{STRIPE}"\n')
    r = c.post("/api/scans/upload", files={"file": (name, buf.getvalue(), "application/zip")})
    assert r.status_code == 200, r.text
    return r.json()


def test_workspaces_never_see_each_others_data():
    with TestClient(app) as live, TestClient(app) as demo, TestClient(app) as owner, TestClient(app) as dadmin:
        live_email = live_user(live)
        upload(live, "live-only-repo.zip")
        assert login_as(demo, *DEMO_USER).status_code == 200
        assert demo.get("/api/auth/me").json()["workspace"] == "demo"
        upload(demo, "demo-only-repo.zip")

        real_admin(owner)
        assert owner.get("/api/auth/me").json()["workspace"] == "live"
        live_roster = {u["email"] for u in owner.get("/api/admin/users").json()}
        assert live_email in live_roster and REAL_ADMIN_EMAIL in live_roster
        assert not live_roster & {"admin@privpass.local", "analyst@privpass.local", "user@privpass.local"}

        assert login_as(dadmin, *DEMO_ADMIN).status_code == 200
        demo_roster = {u["email"] for u in dadmin.get("/api/admin/users").json()}
        assert "user@privpass.local" in demo_roster
        assert live_email not in demo_roster and REAL_ADMIN_EMAIL not in demo_roster   # the real admin is invisible to the demo

        # Findings, alerts and the audit trail are scoped too: each admin's totals match its own workspace exactly.
        import app.db as dbmod
        from app.models import SecretFinding
        with dbmod.SessionLocal() as s:
            per_ws = {ws: s.query(SecretFinding).filter(SecretFinding.workspace == ws).count() for ws in ("demo", "live")}
        assert owner.get("/api/admin/overview").json()["secret_findings"] == per_ws["live"]
        assert dadmin.get("/api/admin/overview").json()["secret_findings"] == per_ws["demo"]
        assert all("demo-only" not in n["body"] for n in owner.get("/api/notifications").json()["items"])
        assert all("live-only" not in n["body"] for n in dadmin.get("/api/notifications").json()["items"])
        assert all(e["meta"].get("target") != live_email for e in dadmin.get("/api/admin/audit").json())


def test_demo_admin_cannot_touch_live_accounts_and_is_read_only_for_user_management():
    with TestClient(app) as live, TestClient(app) as dadmin, TestClient(app) as owner:
        live_email = live_user(live)
        real_admin(owner)
        live_id = next(u["id"] for u in owner.get("/api/admin/users").json() if u["email"] == live_email)
        assert login_as(dadmin, *DEMO_ADMIN).status_code == 200
        assert dadmin.post(f"/api/admin/users/{live_id}/deactivate").status_code == 404        # not even visible
        demo_user_id = next(u["id"] for u in dadmin.get("/api/admin/users").json() if u["email"] == "user@privpass.local")
        assert dadmin.post(f"/api/admin/users/{demo_user_id}/deactivate").status_code == 403
        assert dadmin.delete(f"/api/admin/users/{demo_user_id}").status_code == 403
        # The real admin manages live accounts but cannot reach demo ones.
        assert owner.post(f"/api/admin/users/{demo_user_id}/deactivate").status_code == 404
        assert owner.post(f"/api/admin/users/{live_id}/deactivate").status_code == 200


def test_demo_accounts_are_restricted():
    with TestClient(app) as demo, TestClient(app) as anon:
        assert login_as(demo, *DEMO_USER).status_code == 200
        assert demo.post("/api/auth/change-password/challenge").status_code == 403
        assert anon.post("/api/auth/reset/request", json={"email": "user@privpass.local"}).status_code == 403
        assert demo.post("/api/github/fix-pr/anything").status_code == 403


def test_simulations_only_run_in_the_demo_workspace():
    with TestClient(app) as owner, TestClient(app) as dadmin:
        real_admin(owner)
        assert owner.get("/api/admin/simulations").status_code == 403
        assert owner.post("/api/ai/anomalies/simulate").status_code == 403
        assert login_as(dadmin, *DEMO_ADMIN).status_code == 200
        assert dadmin.get("/api/admin/simulations").status_code == 200


def test_emails_are_unique_across_workspaces():
    with TestClient(app) as c:
        from conftest import signup_as
        r = signup_as(c, "admin@privpass.local", "another-long-unique-passphrase")
        assert r.status_code == 409


def test_real_admin_is_not_in_demo_info_and_password_is_generated_when_not_configured(monkeypatch, tmp_path):
    with TestClient(app) as c:
        info = c.get("/api/demo/info").json()
        assert REAL_ADMIN_EMAIL not in str(info)
    import app.bootstrap as boot
    monkeypatch.setenv("PRIVPASS_ADMIN_EMAIL", "generated-owner@example.com")
    monkeypatch.delenv("PRIVPASS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(boot, "ADMIN_FILE", tmp_path / "ADMIN-CREDENTIALS.txt")
    email, password = boot.ensure_real_admin()
    assert email == "generated-owner@example.com" and password and len(password) >= 15
    assert password in (tmp_path / "ADMIN-CREDENTIALS.txt").read_text()
    with TestClient(app) as c:
        assert login_as(c, email, password).status_code == 200
        assert c.get("/api/auth/me").json() | {} and c.get("/api/auth/me").json()["workspace"] == "live"
    assert boot.ensure_real_admin() == (email, None)          # second start: nothing regenerated


# ---------------------------------------------------------------- 7.2: demo data + public demo mode
def test_demo_data_loads_into_demo_only_and_is_fully_removable():
    with TestClient(app) as dadmin, TestClient(app) as owner:
        assert login_as(dadmin, *DEMO_ADMIN).status_code == 200
        real_admin(owner)
        live_before = owner.get("/api/admin/overview").json()["secret_findings"]
        r = dadmin.post("/api/admin/simulate/seed").json()
        assert r["repositories"] == 2 and r["findings"] > 5 and r["seeded_items"] >= 3
        again = dadmin.post("/api/admin/simulate/seed").json()                     # reloading replaces, never duplicates
        assert again["seeded_items"] == r["seeded_items"]
        ov = dadmin.get("/api/admin/overview").json()
        import app.db as dbmod
        from app.models import AccountAuditReport
        with dbmod.SessionLocal() as s:
            assert s.query(AccountAuditReport).filter(AccountAuditReport.source_name.like("[DEMO]%"), AccountAuditReport.workspace == "demo").count() == 1
        assert ov["honeytoken_trips"] >= 2 and ov["sla"]["overdue"] >= 1
        assert dadmin.get("/api/exposure/graph").json()["paths"]
        assert owner.get("/api/admin/overview").json()["secret_findings"] == live_before  # live workspace untouched
        assert owner.post("/api/admin/simulate/seed").status_code == 403                 # real admin can't seed
        cleared = dadmin.post("/api/admin/simulations/clear").json()
        assert cleared["removed_demo_data"] > 0 and cleared["seeded_items"] == 0
        with dbmod.SessionLocal() as s:
            assert s.query(AccountAuditReport).filter(AccountAuditReport.source_name.like("[DEMO]%")).count() == 0


def test_public_demo_mode_keeps_demo_but_production_security(monkeypatch):
    import app.config as cfg
    import app.main as m
    with TestClient(app) as c, TestClient(app) as dadmin:
        monkeypatch.setattr(cfg, "APP_ENV", "production")
        monkeypatch.setattr(m, "APP_ENV", "production")
        monkeypatch.setattr(cfg, "PUBLIC_DEMO", False)
        assert c.get("/api/demo/info").json() == {"demo_mode": False}
        assert c.get("/api/health").json()["demo"] is False
        monkeypatch.setattr(cfg, "PUBLIC_DEMO", True)
        assert c.get("/api/demo/info").json()["demo_mode"] is True
        assert c.get("/api/demo/repository.zip").status_code == 200
        assert login_as(dadmin, *DEMO_ADMIN).status_code == 200
        assert dadmin.get("/api/admin/simulations").status_code == 200
        # production security still applies: no reset token is ever returned in the response
        live = live_user(c)
        assert c.post("/api/auth/reset/request", json={"email": live}).json()["demo_token"] is None


def test_production_needs_an_explicit_real_admin_password(monkeypatch, tmp_path):
    import app.bootstrap as boot
    import app.config as cfg
    monkeypatch.setattr(cfg, "APP_ENV", "production")
    monkeypatch.setenv("PRIVPASS_ADMIN_EMAIL", "prod-owner@example.com")
    monkeypatch.delenv("PRIVPASS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(boot, "ADMIN_FILE", tmp_path / "ADMIN-CREDENTIALS.txt")
    assert boot.ensure_real_admin() == ("prod-owner@example.com", None)
    assert not (tmp_path / "ADMIN-CREDENTIALS.txt").exists()
