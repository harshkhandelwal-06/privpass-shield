from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.scanner import (  # noqa: E402
    Finding,
    findings_to_json,
    findings_to_sarif,
    scan_dir,
    scan_git_history,
    scan_staged_git,
    scan_zip,
)

VERSION = "6.2.0"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
EXIT_PASS, EXIT_BLOCK, EXIT_ERROR = 0, 1, 2

ROTATE_GUIDE = """
ROTATE, DON'T JUST DELETE
  A committed secret is compromised the moment it is pushed: deleting the line only hides it
  from HEAD - every clone, fork, CI cache and the git history still contain it.
  1. Revoke / rotate the credential at the provider NOW (issue a new one, disable the old one).
  2. Move the new value to a secret manager or CI secret and read it from the environment.
  3. Check provider audit logs for use of the old credential since the introducing commit.
  4. Optionally purge history (git filter-repo --replace-text / BFG) and force-push - but this
     is hygiene, not remediation: step 1 is what actually closes the incident.
  5. Record the rotated fingerprint with --write-baseline so the gate stops blocking on it.
"""


def _print_text(findings: list[Finding], files: int, mode: str, baselined: set[tuple[str, str]], blocking: list[Finding]) -> None:
    secrets = [f for f in findings if f.kind == "secret"]
    code = [f for f in findings if f.kind == "code"]
    counts = {sev: sum(f.severity == sev for f in findings) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    unit = "commits" if mode == "history" else "files"
    print(f"PrivPass SecretGuard {VERSION} | mode={mode} | scanned={files} {unit} | secrets={len(secrets)} risky-code={len(code)}")
    print("Severity: " + " ".join(f"{k}={v}" for k, v in counts.items()))
    if not findings:
        print("PASS: no secret-like findings or risky code patterns detected.")
        return
    block_ids = {id(f) for f in blocking}
    for finding in findings:
        tags = []
        if id(finding) in block_ids:
            tags.append("BLOCKING")
        if (finding.fingerprint, finding.secret_type) in baselined:
            tags.append("BASELINED")
        if finding.in_head is False:
            tags.append("HISTORY-ONLY")
        label = f" [{' '.join(tags)}]" if tags else ""
        print(
            f"{finding.severity:8} {finding.file_path}:{finding.line_no:<5} "
            f"{finding.secret_type:<34} confidence={finding.confidence:.0%} "
            f"entropy={finding.entropy:.2f} validity={finding.validity}{label}"
        )
        print(f"          {finding.reason}")
        print(f"          redacted={finding.redacted_preview}")
        if finding.commit:
            print(f"          commit={finding.commit[:12]} author={finding.author} date={(finding.commit_date or '')[:10]} commits_with_value={finding.commits_seen}")


def _load_baseline(path: Path | None) -> set[tuple[str, str]]:
    if not path or not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {(entry["fingerprint"], entry["secret_type"]) for entry in data.get("entries", [])}


def _write_baseline(path: Path, findings: list[Finding], note: str) -> None:
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"version": 1, "entries": []}
    keys = {(e["fingerprint"], e["secret_type"]) for e in existing.get("entries", [])}
    for f in findings:
        if (f.fingerprint, f.secret_type) in keys:
            continue
        existing["entries"].append({"fingerprint": f.fingerprint, "secret_type": f.secret_type, "file": f.file_path,
                                    "line": f.line_no, "commit": f.commit, "note": note})
        keys.add((f.fingerprint, f.secret_type))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")


def _blocking(findings: list[Finding], fail_rank: int, min_confidence: float, risky_rank: int, baselined: set[tuple[str, str]]) -> list[Finding]:
    out = []
    for f in findings:
        if (f.fingerprint, f.secret_type) in baselined:
            continue
        rank = SEVERITY_RANK.get(f.severity, 0)
        if f.kind == "code":
            if risky_rank and rank >= risky_rank:
                out.append(f)
        elif fail_rank and rank >= fail_rank and (f.confidence >= min_confidence or f.validity == "LIVE_VERIFIED"):
            out.append(f)
    return out


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PrivPass SecretGuard - shared repository, staged-file, git-history and CI secret scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Exit codes: 0 = pass, 1 = blocking findings, 2 = scanner error.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Repository directory or a ZIP archive")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="Scan exactly staged Git index content (pre-commit)")
    mode.add_argument("--history", action="store_true", help="Scan every line ever added in any commit on any ref")
    parser.add_argument("--max-commits", type=int, default=5000, help="History mode: newest N commits to inspect")
    parser.add_argument("--verify", action="store_true", help="Opt-in: ask providers whether detected credentials are live (CI only; sends each value to its own provider)")
    parser.add_argument("--no-code-rules", action="store_true", help="Only look for secrets, skip risky code patterns")
    parser.add_argument("--sarif", type=Path, help="Write SARIF 2.1.0 output")
    parser.add_argument("--json", dest="json_path", type=Path, help="Write machine-readable JSON output")
    parser.add_argument("--fail-on", choices=["never", "medium", "high", "critical"], default="high", help="Block (exit 1) when a secret at/above this severity meets --min-confidence")
    parser.add_argument("--fail-on-risky", choices=["never", "medium", "high", "critical"], default="high", help="Block (exit 1) on risky code patterns at/above this severity")
    parser.add_argument("--min-confidence", type=float, default=0.80, help="Minimum confidence for a blocking secret finding")
    parser.add_argument("--baseline", type=Path, help="JSON baseline of reviewed/rotated fingerprints that must not block")
    parser.add_argument("--write-baseline", type=Path, help="Append current findings to this baseline file (after rotating them!)")
    parser.add_argument("--baseline-note", default="rotated", help="Note stored with --write-baseline entries")
    parser.add_argument("--quiet", action="store_true", help="Suppress normal text output")
    parser.add_argument("--json-stdout", action="store_true", help="Print JSON to stdout instead of normal text")
    return parser.parse_args()


def _resolve_mode(path: Path, staged: bool, history: bool) -> str:
    if staged:
        return "staged"
    if history:
        return "history"
    if path.is_file() and path.suffix.lower() == ".zip":
        return "zip"
    return "repository"


def main() -> int:
    args = _parse_args()
    if not 0.0 <= args.min_confidence <= 1.0:
        print("ERROR: --min-confidence must be between 0 and 1", file=sys.stderr)
        return EXIT_ERROR

    path = Path(args.path).resolve()
    mode = _resolve_mode(path, args.staged, args.history)
    secret_key = os.environ.get("PRIVPASS_SCAN_FINGERPRINT_KEY", "privpass-secretguard-v1")
    include_code = not args.no_code_rules
    verifier = None
    if args.verify:
        from app.verifiers import make_verifier
        verifier = make_verifier()

    try:
        if mode == "staged":
            findings, files = scan_staged_git(path, secret_key, verifier=verifier, include_code=include_code)
        elif mode == "history":
            findings, files = scan_git_history(path, secret_key, verifier=verifier, include_code=include_code, max_commits=args.max_commits)
        elif mode == "zip":
            findings, files = scan_zip(path.read_bytes(), secret_key, verifier=verifier, include_code=include_code)
        else:
            findings, files = scan_dir(path, secret_key, verifier=verifier, include_code=include_code)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    baselined = _load_baseline(args.baseline)
    fail_rank = SEVERITY_RANK.get(args.fail_on.upper(), 0)
    risky_rank = 0 if args.no_code_rules else SEVERITY_RANK.get(args.fail_on_risky.upper(), 0)
    blocking = _blocking(findings, fail_rank, args.min_confidence, risky_rank, baselined)

    payload = findings_to_json(findings, files, mode, VERSION)
    payload["blocking_count"] = len(blocking)
    payload["baselined_count"] = sum((f.fingerprint, f.secret_type) in baselined for f in findings)
    payload["history_only_count"] = sum(f.in_head is False for f in findings)
    if args.json_path:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(json.dumps(findings_to_sarif(findings, VERSION), indent=2), encoding="utf-8")
    if args.write_baseline:
        _write_baseline(args.write_baseline, [f for f in findings if f.kind == "secret"], args.baseline_note)
        print(f"Baseline updated: {args.write_baseline}", file=sys.stderr)

    if args.json_stdout:
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        _print_text(findings, files, mode, baselined, blocking)

    if blocking:
        secrets_blocking = [f for f in blocking if f.kind == "secret"]
        if secrets_blocking and not args.quiet:
            print(ROTATE_GUIDE)
        print(f"BLOCK: {len(blocking)} finding(s) meet the gate (secrets: --fail-on {args.fail_on.upper()} "
              f"@ {args.min_confidence:.0%}; code: --fail-on-risky {args.fail_on_risky.upper()}).", file=sys.stderr)
        return EXIT_BLOCK
    return EXIT_PASS


if __name__ == "__main__":
    raise SystemExit(main())
