"""6.0 SecretGuard: git-history scanning, allowlists/baselines, false-positive controls,
opt-in live verification, risky code patterns and hardened git execution."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import verifiers
from app.scanner import findings_to_sarif, scan_dir, scan_git_history, scan_text, scan_zip

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "secret_scan.py"
KEY = "test-key"
STRIPE = "sk_test_" + "HistoryDemo0123456789abcd"   # split so this file never looks like a literal key
GITHUB = "ghp_" + "HistoryDemo0123456789abcdefABCDEFGH"


def _git(repo: Path, *args: str) -> None:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _repo_with_deleted_secret(tmp_path: Path) -> Path:
    repo = tmp_path / "svc"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Dev One")
    _git(repo, "config", "user.email", "dev@example.com")
    (repo / "billing.py").write_text(f'STRIPE_KEY = "{STRIPE}"\n', encoding="utf-8")
    _git(repo, "add", "-A"); _git(repo, "commit", "-q", "-m", "add billing")
    (repo / "billing.py").write_text('import os\nSTRIPE_KEY = os.environ["STRIPE_KEY"]\n', encoding="utf-8")
    _git(repo, "add", "-A"); _git(repo, "commit", "-q", "-m", "remove key")
    return repo


# ---------- false-positive controls -------------------------------------------------------
def test_vendor_documentation_example_key_is_low_and_non_blocking():
    findings = scan_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n', "config.py", KEY)  # secretguard:allow
    assert len(findings) == 1
    assert findings[0].severity == "LOW" and findings[0].confidence < 0.5
    assert findings[0].validity == "KNOWN_DOCUMENTATION_EXAMPLE"


def test_inline_allow_marker_suppresses_a_reviewed_line():
    line = f'TOKEN = "{GITHUB}"'
    assert scan_text(line + "\n", "a.py", KEY)
    assert scan_text(line + "  # secretguard:allow reviewed test fixture\n", "a.py", KEY) == []
    assert scan_text(line + "  # pragma: allowlist secret\n", "a.py", KEY) == []


def test_connection_strings_without_credentials_are_not_findings():
    assert scan_text("REDIS_URL = 'redis://redis:6379/0'\n", "a.py", KEY) == []
    assert scan_text("DB = 'postgresql://app:${DB_PASSWORD}@db/app'\n", "a.py", KEY) == []
    hit = scan_text("DB = 'postgresql://app:S3cretPassw0rd99@db.internal/app'\n", "a.py", KEY)
    assert hit and hit[0].secret_type == "Connection string"


def test_secretguardignore_excludes_paths(tmp_path):
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "keys.py").write_text(f'K = "{GITHUB}"\n', encoding="utf-8")
    (tmp_path / "app.py").write_text(f'K = "{GITHUB}"\n', encoding="utf-8")
    assert len(scan_dir(tmp_path, KEY)[0]) == 2
    (tmp_path / ".secretguardignore").write_text("# reviewed fixtures\nfixtures/\n", encoding="utf-8")
    findings, _ = scan_dir(tmp_path, KEY)
    assert [f.file_path for f in findings] == ["app.py"]


def test_repository_self_scan_passes():
    """The project's own CI gate must be green: planted demo secrets are ignored deliberately."""
    proc = subprocess.run([sys.executable, str(CLI), str(ROOT), "--quiet"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------- risky code patterns -----------------------------------------------------------
@pytest.mark.parametrize("line,rule", [
    ('subprocess.run(f"ping {host}", shell=True)', "shell=True"),
    ("requests.get(url, verify=False)", "TLS verification"),
    ("cur.execute(f\"SELECT * FROM t WHERE id={uid}\")", "SQL built"),
    ("data = pickle.loads(blob)", "deserialization"),
    ("cfg = yaml.load(text)", "deserialization"),
    ("result = eval(user_input)", "eval/exec"),
    ("jwt.decode(tok, options={'verify_signature': False})", "JWT"),
])
def test_risky_code_patterns(line, rule):
    findings = [f for f in scan_text(line + "\n", "svc.py", KEY) if f.kind == "code"]
    assert findings and rule in findings[0].secret_type
    assert findings[0].advice


def test_safe_variants_are_not_flagged():
    safe = ("subprocess.run(['ping', host])\nyaml.load(text, Loader=yaml.SafeLoader)\n"
            "cur.execute('SELECT * FROM t WHERE id=?', (uid,))\nrequests.get(url, timeout=5)\n")
    assert [f for f in scan_text(safe, "svc.py", KEY) if f.kind == "code"] == []


def test_js_math_random_token_is_flagged():
    findings = scan_text("const token = Math.random().toString(36);\n", "a.js", KEY)
    assert any("Math.random" in f.secret_type for f in findings)


# ---------- git history ---------------------------------------------------------------------
def test_history_finds_secret_deleted_from_head(tmp_path):
    repo = _repo_with_deleted_secret(tmp_path)
    assert [f for f in scan_dir(repo, KEY)[0] if f.kind == "secret"] == []  # HEAD looks clean...
    findings, commits = scan_git_history(repo, KEY)                       # ...history does not
    assert commits == 2
    assert len(findings) == 1
    f = findings[0]
    assert f.secret_type == "Stripe secret key" and f.in_head is False
    assert f.author == "Dev One" and len(f.commit) == 40 and f.commits_seen == 1
    assert "DELETED from HEAD" in f.reason


def test_cli_history_blocks_then_baseline_after_rotation_passes(tmp_path):
    repo = _repo_with_deleted_secret(tmp_path)
    baseline = tmp_path / "baseline.json"
    first = subprocess.run([sys.executable, str(CLI), str(repo), "--history"], capture_output=True, text=True)
    assert first.returncode == 1
    assert "HISTORY-ONLY" in first.stdout and "ROTATE, DON'T JUST DELETE" in first.stdout
    subprocess.run([sys.executable, str(CLI), str(repo), "--history", "--quiet", "--write-baseline", str(baseline),
                    "--baseline-note", "rotated in Stripe dashboard 2026-09-26"], capture_output=True, text=True)
    entries = json.loads(baseline.read_text())["entries"]
    assert entries[0]["note"].startswith("rotated") and STRIPE not in baseline.read_text()
    second = subprocess.run([sys.executable, str(CLI), str(repo), "--history", "--baseline", str(baseline)], capture_output=True, text=True)
    assert second.returncode == 0, second.stdout + second.stderr


def test_hostile_git_config_cannot_execute_commands(tmp_path):
    repo = _repo_with_deleted_secret(tmp_path)
    marker = tmp_path / "PWNED"
    cmd = f"touch {marker}"
    with open(repo / ".git" / "config", "a", encoding="utf-8") as cfg:
        cfg.write(f'[core]\n\tpager = {cmd}\n\tfsmonitor = {cmd}\n[diff]\n\texternal = {cmd}\n'
                  f'[diff "evil"]\n\ttextconv = {cmd}\n[log]\n\tshowSignature = true\n[gpg]\n\tprogram = {cmd}\n')
    (repo / ".gitattributes").write_text("*.py diff=evil\n", encoding="utf-8")
    findings, _ = scan_git_history(repo, KEY)
    assert findings  # still works
    assert not marker.exists()


def test_zip_with_git_directory_reports_history_only_secret(tmp_path):
    repo = _repo_with_deleted_secret(tmp_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path in repo.rglob("*"):
            if path.is_file():
                zf.write(path, "svc/" + str(path.relative_to(repo)).replace("\\", "/"))
    findings, _count = scan_zip(buf.getvalue(), KEY)
    hist = [f for f in findings if f.in_head is False]
    assert len(hist) == 1 and hist[0].file_path == "svc/billing.py"


def test_upload_api_returns_history_metadata(tmp_path):
    from app.main import app
    from conftest import breach_gate
    import base64, hashlib, hmac
    zip_path = ROOT / "demo-assets" / "PrivPass-History-Leak-Repo.zip"
    assert zip_path.exists()
    with TestClient(app) as c:
        email = "hist-" + os.urandom(4).hex() + "@example.com"
        from conftest import signup_as, login_as
        assert signup_as(c, email, "History demo passphrase long enough").status_code == 200
        assert login_as(c, email, "History demo passphrase long enough").status_code == 200
        res = c.post("/api/scans/upload", files={"file": ("history.zip", zip_path.read_bytes(), "application/zip")})
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["history_only"] == 2
        f = next(x for x in body["findings"] if x["in_head"] is False)
        assert f["commit"] and f["author"] == "Riya Dev"
        incidents = c.get("/api/incidents").json()["incidents"]
        assert any(i["in_head"] is False for i in incidents)


# ---------- live verification (opt-in) ------------------------------------------------------
def test_verifier_outcomes_adjust_confidence():
    live = verifiers.make_verifier({"GitHub token": lambda s: "LIVE_VERIFIED"})
    dead = verifiers.make_verifier({"GitHub token": lambda s: "PROVIDER_REJECTED"})
    line = f'T = "{GITHUB}"\n'
    assert scan_text(line, "a.py", KEY, verifier=live)[0].confidence == 0.999
    rejected = scan_text(line, "a.py", KEY, verifier=dead)[0]
    assert rejected.confidence <= 0.60 and rejected.validity == "PROVIDER_REJECTED"
    aws = scan_text('K = "AKIA1234567890ABCDEF"\n', "a.py", KEY, verifier=verifiers.make_verifier({}))[0]
    assert aws.validity.endswith("UNVERIFIABLE")


def test_verifier_is_cached_and_swallows_errors():
    calls = []
    def boom(secret):
        calls.append(secret)
        raise OSError("network down")
    verify = verifiers.make_verifier({"GitHub token": boom})
    assert verify("GitHub token", GITHUB) == "VERIFY_ERROR"
    assert verify("GitHub token", GITHUB) == "VERIFY_ERROR"
    assert len(calls) == 1


def test_provider_probes_map_http_status(monkeypatch):
    monkeypatch.setattr(verifiers, "_request", lambda url, headers, method="GET", data=None: (200, b'{"ok": true}'))
    assert verifiers._github(GITHUB) == "LIVE_VERIFIED"
    assert verifiers._slack("xoxb-x") == "LIVE_VERIFIED"
    monkeypatch.setattr(verifiers, "_request", lambda url, headers, method="GET", data=None: (401, b""))
    assert verifiers._stripe(STRIPE) == "PROVIDER_REJECTED"
    monkeypatch.setattr(verifiers, "_request", lambda url, headers, method="GET", data=None: (200, b'{"ok": false}'))
    assert verifiers._slack("xoxb-x") == "PROVIDER_REJECTED"


def test_sarif_carries_history_and_kind():
    repo_findings = scan_text(f'T = "{GITHUB}"\nsubprocess.call(cmd, shell=True)\n', "a.py", KEY)
    props = [r["properties"] for r in findings_to_sarif(repo_findings)["runs"][0]["results"]]
    assert {p["kind"] for p in props} == {"secret", "code"}
    assert all("inHead" in p for p in props)
