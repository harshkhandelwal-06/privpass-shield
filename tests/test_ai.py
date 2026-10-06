"""6.1 AI/ML: redaction guard, ML secret classifier, remediation copilot, triage guardrails,
password coach schema, copilot tools, incident report, login anomaly detection, PR reviewer."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ai import assist, provider, remediation
from app.main import app
from app.ml import anomaly, secret_model
from app.redaction import LeakBlocked, assert_clean, mask_text
from app.scanner import scan_text
from conftest import breach_gate

ROOT = Path(__file__).resolve().parents[1]
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
DBPASS = "Summer2024!" + "prod"


def _login(c, email, pw_bytes):
    from conftest import login_as
    r = login_as(c, email, pw_bytes.decode() if isinstance(pw_bytes, bytes) else pw_bytes)
    assert r.status_code == 200, r.text


def _admin(c):
    _login(c, "admin@privpass.local", b"PrivPass!Demo#2026-Admin")


def _user(c):
    _login(c, "user@privpass.local", b"PrivPass!Demo#2026-User")


# ---------------------------------------------------------------- redaction guard
def test_mask_text_removes_every_credential_shape():
    text = f'STRIPE = "{STRIPE}"\nDB_PASSWORD = "{DBPASS}"\ntoken = "a8Kd92LmQz7Rt5Vn3Xp0Qw"\nname = "customer_display_name"'
    masked = mask_text(text)
    assert STRIPE not in masked and DBPASS not in masked and "a8Kd92LmQz7Rt5Vn3Xp0Qw" not in masked
    assert "<REDACTED:STRIPE_SECRET_KEY>" in masked
    assert "customer_display_name" in masked  # ordinary identifiers survive


def test_assert_clean_blocks_leaks():
    with pytest.raises(LeakBlocked):
        assert_clean(f"please fix {STRIPE}")
    with pytest.raises(LeakBlocked):
        assert_clean("value X9fK2mQ7vL3pR8tZ1wY6nB4cD5 here")
    with pytest.raises(LeakBlocked):
        assert_clean("anything", known_secrets=("anything",))
    assert assert_clean('STRIPE = "<REDACTED:STRIPE_SECRET_KEY>"')


def test_finding_context_never_contains_the_secret():
    code = f'import stripe\nstripe.api_key = "{STRIPE}"\nDB_PASSWORD = "{DBPASS}"\n'
    findings = scan_text(code, "billing.py", "k")
    assert findings
    for f in findings:
        assert f.context and STRIPE not in f.context and DBPASS not in f.context
        assert STRIPE not in json.dumps(f.to_dict()) and DBPASS not in json.dumps(f.to_dict())


class _FakeClient:
    """Stands in for the Anthropic SDK; records exactly what would be sent."""
    def __init__(self, reply):
        self.sent, self.reply = [], reply
        self.messages = self

    def create(self, **kw):
        self.sent.append(kw)
        block = type("B", (), {"type": "text", "text": self.reply})()
        return type("R", (), {"content": [block]})()


def test_provider_guard_blocks_leaking_prompt_and_falls_back(monkeypatch):
    fake = _FakeClient('{"verdict": "likely_real", "confidence": 0.9, "explanation": "x"}')
    monkeypatch.setattr(provider, "enabled", lambda: True)
    monkeypatch.setattr(provider, "_client", lambda: fake)
    result, mode = provider.try_ai(lambda: provider.complete_json("sys", f"key is {STRIPE}"), lambda: {"offline": True})
    assert result == {"offline": True} and "redaction guard" in mode
    assert fake.sent == []  # nothing left the process
    result, mode = provider.try_ai(lambda: provider.complete_json("sys", "clean prompt"), lambda: {})
    assert mode.startswith("claude:") and result["verdict"] == "likely_real"


# ---------------------------------------------------------------- ML secret classifier
def test_classifier_is_available_and_catches_what_rules_miss():
    assert secret_model.available()
    findings = {f.line_no: f for f in scan_text(
        f'DB_PASSWORD = "{DBPASS}"\nchecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"\n'
        'label = "customer_display_name"\nAPI_KEY = "your-api-key-here"\n', "app/settings.py", "k")}
    assert findings[1].secret_type == "Hardcoded secret (ML)" and findings[1].ml_probability > 0.9
    assert findings[1].ml_reasons
    assert 2 not in findings and 3 not in findings                  # hash and identifier are not secrets
    assert 4 not in findings or findings[4].confidence < 0.8        # placeholder is demoted below the gate


def test_ml_does_not_resurrect_rule_rejected_provider_values():
    assert scan_text("REDIS_URL = 'redis://redis:6379/0'\n", "a.py", "k") == []


def test_model_card_shows_ml_beats_rules_on_recall():
    card = json.loads((ROOT / "ml" / "reports" / "secret-classifier-card.json").read_text())
    assert card["test"]["ml"]["recall"] > card["test"]["rules_baseline"]["recall"] + 0.3
    assert card["test"]["ml"]["precision"] >= 0.95


# ---------------------------------------------------------------- remediation copilot
def test_offline_remediation_patch_runbook_and_history():
    f = {"type": "Stripe secret key", "severity": "CRITICAL", "kind": "secret", "file": "billing.py", "line": 2, "in_head": False,
         "context": '   1  import stripe\n   2> stripe_key = "<REDACTED:STRIPE_SECRET_KEY>"'}
    r = remediation.remediate(f)
    assert r["mode"] == "offline"
    assert '+stripe_key = os.environ["STRIPE_KEY"]' in r["patch"]
    assert r["provider"] == "Stripe" and r["console"].startswith("https://dashboard.stripe.com")
    assert any("filter-repo" in c for c in r["history_cleanup"]) and "history" in r["summary"]


@pytest.mark.parametrize("path,line,expect", [
    ("src/a.js", 'const apiKey = "<REDACTED:LITERAL>";', "process.env.API_KEY;"),
    (".env", "STRIPE_KEY=<REDACTED:STRIPE_SECRET_KEY>", "STRIPE_KEY="),
    ("deploy/values.yaml", '  token: "<REDACTED:LITERAL>"', "${TOKEN}"),
])
def test_offline_patch_languages(path, line, expect):
    patch, _ = remediation.offline_patch({"type": "Generic secret assignment", "kind": "secret", "file": path, "context": f"   7> {line}"})
    assert expect in patch


def test_offline_patch_for_risky_code():
    patch, notes = remediation.offline_patch({"type": "Risky: unsafe deserialization", "kind": "code", "file": "a.py", "context": "   3>     return yaml.load(raw)"})
    assert "+    return yaml.safe_load(raw)" in patch and notes


# ---------------------------------------------------------------- triage guardrail
def test_ai_can_never_dismiss_a_critical_finding(monkeypatch):
    monkeypatch.setattr(provider, "try_ai", lambda fn, fb: ({"verdict": "placeholder", "confidence": 0.99, "explanation": "looks fake"}, "claude:test"))
    out = assist.triage({"type": "Stripe secret key", "severity": "CRITICAL", "file": "a.py", "context": ""})
    assert out["verdict"] == "needs_human_review"
    out = assist.triage({"type": "Hardcoded secret (ML)", "severity": "MEDIUM", "file": "a.py", "context": ""})
    assert out["verdict"] == "placeholder"


# ---------------------------------------------------------------- API: coach, copilot, report, anomalies
def test_password_coach_schema_cannot_carry_a_password():
    with TestClient(app) as c:
        ok = {"length": 11, "score": 30, "label": "Weak", "log10_guesses": 6.2, "neural_log10": 11.9, "char_classes": 3,
              "flags": {"year": True, "dictionary_like": True}}
        r = c.post("/api/ai/password-coach", json=ok)
        assert r.status_code == 200 and r.json()["why"] and r.json()["sent"] == {**ok}
        assert c.post("/api/ai/password-coach", json={**ok, "password": "Summer2024!"}).status_code == 422
        assert c.post("/api/ai/password-coach", json={**ok, "label": "Summer2024!"}).status_code == 422
        assert c.post("/api/ai/password-coach", json={**ok, "flags": {"Summer2024!": True}}).status_code == 422


def test_copilot_and_report_require_privileged_role_and_use_tools():
    with TestClient(app) as c:
        _user(c)
        assert c.post("/api/ai/copilot", json={"question": "which critical findings are unrotated?"}).status_code == 403
        _admin(c)
        buf_path = ROOT / "demo-assets" / "PrivPass-Demo-Leak-Repo.zip"
        assert c.post("/api/scans/upload", files={"file": ("demo.zip", buf_path.read_bytes(), "application/zip")}).status_code == 200
        r = c.post("/api/ai/copilot", json={"question": "Which critical findings are still unrotated?"}).json()
        assert r["tool_calls"][0]["tool"] == "list_findings" and r["tool_calls"][0]["args"]["severity"] == "CRITICAL"
        assert "CRITICAL" in r["answer"] and "sk_t" not in r["answer"].replace("sk_t…", "")
        rep = c.post("/api/ai/incident-report").json()
        assert rep["markdown"].startswith("# Incident report") and "## Actions" in rep["markdown"]


def test_remediate_and_triage_endpoints():
    with TestClient(app) as c:
        _admin(c)
        body = c.post("/api/scans/upload", files={"file": ("demo.zip", (ROOT / "demo-assets" / "PrivPass-Demo-Leak-Repo.zip").read_bytes(), "application/zip")}).json()
        stripe = next(f for f in body["findings"] if f["type"] == "Stripe secret key")
        assert stripe["context"] and stripe["ml_probability"] is not None
        r = c.post(f"/api/ai/remediate/{stripe['id']}").json()
        assert r["patch"] and r["runbook"] and "context" in r["ai_input"]
        t = c.post("/api/ai/triage", json={}).json()
        assert "triaged" in t
        with TestClient(app) as other:
            _user(other)
            assert other.post(f"/api/ai/remediate/{stripe['id']}").status_code == 404  # cannot read another user's finding


def test_login_telemetry_is_hashed_and_anomaly_simulation_detects_attacks():
    with TestClient(app) as c:
        ch = c.post("/api/auth/challenge", json={"email": "victim@example.com"}).json()
        c.post("/api/auth/login", json={"email": "victim@example.com", "nonce": ch["nonce"], "proof": "00"})
        import app.db as dbmod
        from app.models import LoginEvent
        with dbmod.SessionLocal() as s:
            ev = s.query(LoginEvent).filter(LoginEvent.reason == "unknown_account").first()
            assert ev and "victim" not in ev.account_hash and len(ev.account_hash) == 32
        _user(c)
        assert c.get("/api/ai/anomalies").status_code == 403
        _admin(c)
        data = c.post("/api/ai/anomalies/simulate").json()
        patterns = {w["pattern"] for w in data["windows"] if w["anomalous"]}
        assert {"Credential stuffing", "Brute force on one account", "Account enumeration"} <= patterns
        assert all(w["reasons"] for w in data["windows"] if w["anomalous"])
        assert c.delete("/api/ai/anomalies/simulated").json()["deleted"] >= 200


def test_anomaly_model_benchmark():
    ev = anomaly.evaluate()["evaluation"]
    assert ev["detect_credential_stuffing"] >= 0.95 and ev["detect_enumeration"] >= 0.95 and ev["detect_brute_force"] >= 0.9
    assert ev["false_alarm_rate"] <= 0.03


def test_model_cards_endpoint_and_status():
    with TestClient(app) as c:
        cards = c.get("/api/ai/models").json()
        assert cards["secret_classifier"]["test"]["ml"]["recall"] > 0.9
        assert cards["password_model"]["evaluation"]["neural"]["random_12_20_char_rated_weak_within_1e12"] <= 0.01
        st = c.get("/api/ai/status").json()
        assert st["redaction_guard"] and st["secret_classifier"] and st["password_model"]


# ---------------------------------------------------------------- password model artefact & PR reviewer
def test_password_model_artifact_is_well_formed():
    m = json.loads((ROOT / "static" / "ml" / "password-model.json").read_text())
    table = m["calibration"]
    assert all(a[0] >= b[0] and a[1] <= b[1] for a, b in zip(table, table[1:]))  # prob decreases, guesses increase
    assert set(m["weights"]) == {"emb", "w_ih", "w_hh", "b_ih", "b_hh", "w_out", "b_out"}
    assert len(m["weights"]["b_ih"]) == 3 * m["hidden"]


def test_pr_reviewer_markdown_has_fixes_and_no_secrets(tmp_path):
    from tools.ai_pr_review import build
    findings = [f.to_dict() for f in scan_text(f'STRIPE_KEY = "{STRIPE}"\n', "billing.py", "k")]
    md = build(findings, [], blocked=True)
    assert "```diff" in md and "Rotate first" in md and STRIPE not in md and "<!-- privpass-secretguard -->" in md


def test_copilot_claude_tool_loop_with_fake_client(monkeypatch):
    """Exercise the real tool-use loop (as Claude would drive it) without network access."""
    class Block:
        def __init__(self, **kw): self.__dict__.update(kw)
        def model_dump(self): return {k: v for k, v in self.__dict__.items()}

    class ToolClient:
        def __init__(self): self.calls = 0; self.messages = self; self.sent = []
        def create(self, **kw):
            self.sent.append(kw); self.calls += 1
            if self.calls == 1:
                return Block(content=[Block(type="tool_use", id="tu_1", name="list_findings", input={"severity": "CRITICAL", "status": "OPEN"})])
            return Block(content=[Block(type="text", text="There are open CRITICAL findings; rotate the Stripe key first.")])

    fake = ToolClient()
    monkeypatch.setattr(provider, "enabled", lambda: True)
    monkeypatch.setattr(provider, "_client", lambda: fake)
    seen = {}
    def list_findings(**kw):
        seen.update(kw); return {"findings": [{"type": "Stripe secret key", "preview": "sk_t…CDEF"}]}
    out = assist.copilot("which critical findings are open?", {"list_findings": list_findings})
    assert out["mode"].startswith("claude:") and "rotate the Stripe key" in out["answer"]
    assert out["tool_calls"] == [{"tool": "list_findings", "args": {"severity": "CRITICAL", "status": "OPEN"}}]
    assert seen == {"severity": "CRITICAL", "status": "OPEN"}
    tool_result = fake.sent[1]["messages"][-1]["content"][0]
    assert tool_result["type"] == "tool_result" and "sk_t…CDEF" in tool_result["content"]
