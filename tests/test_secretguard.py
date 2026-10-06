from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.scanner import findings_to_sarif, scan_dir, scan_text

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "tools" / "secret_scan.py"


def test_provider_pattern_is_validated_and_deduplicated():
    text = 'AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\nAWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n'
    findings = scan_text(text, "config/.env", "test-key")
    assert len(findings) == 2
    finding = findings[0]
    assert finding.secret_type == "AWS access key"
    assert finding.validity == "AWS_FORMAT_VALID"
    assert finding.confidence >= 0.80
    assert finding.redacted_preview != "AKIA1234567890ABCDEF"


def test_generic_entropy_and_placeholder_controls():
    text = (
        'API_KEY="this-is-a-placeholder"\n'
        'API_KEY="xY7!kQ2@vP9#rL5$sN8%aZ3&cT6^uH4*"\n'
    )
    findings = scan_text(text, "src/config.py", "test-key")
    assert len(findings) == 1
    assert findings[0].secret_type == "Generic secret assignment"
    assert findings[0].entropy > 3.0
    assert findings[0].confidence >= 0.80


def test_sarif_has_stable_fingerprints():
    findings = scan_text('token = "xY7!kQ2@vP9#rL5$sN8%aZ3&cT6^uH4*"', "src/config.py", "test-key")
    sarif = findings_to_sarif(findings)
    result = sarif["runs"][0]["results"][0]
    assert result["partialFingerprints"]["privpassStable"]
    assert result["properties"]["validity"]


def test_cli_json_and_sarif(tmp_path):
    (tmp_path / ".env").write_text('AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n', encoding="utf-8")
    json_path = tmp_path / "out.json"
    sarif_path = tmp_path / "out.sarif"
    proc = subprocess.run(
        [sys.executable, str(CLI), str(tmp_path), "--json", str(json_path), "--sarif", str(sarif_path), "--fail-on", "high"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["finding_count"] == 1
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_cli_clean_repo_passes(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, str(CLI), str(tmp_path), "--fail-on", "high"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "PASS" in proc.stdout


def test_staged_mode_scans_git_index(tmp_path):
    (tmp_path / "config.py").write_text('AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"\n', encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "SecretGuard Test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "config.py"], check=True)
    proc = subprocess.run([sys.executable, str(CLI), "--staged", "--fail-on", "high"], cwd=tmp_path, capture_output=True, text=True)
    assert proc.returncode == 1
    assert "config.py:1" in proc.stdout
