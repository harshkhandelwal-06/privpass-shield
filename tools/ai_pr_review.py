"""Build the SecretGuard pull-request comment, with AI remediation for each blocking finding.

Reads the JSON reports written by tools/secret_scan.py and writes Markdown. Uses Claude when
ANTHROPIC_API_KEY is available (e.g. a repository secret), otherwise the offline remediation engine.
Only redacted findings and masked context snippets are used - the raw values are never in the reports.

    python tools/ai_pr_review.py --tree secretguard.json --history secretguard-history.json --out pr-comment.md --blocked
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ai import provider  # noqa: E402
from app.ai.remediation import remediate  # noqa: E402

MARKER = "<!-- privpass-secretguard -->"


def _load(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("findings", [])


def _as_finding(f: dict) -> dict:
    return {"type": f["secret_type"], "severity": f["severity"], "kind": f.get("kind", "secret"), "file": f["file_path"], "line": f["line_no"],
            "validity": f.get("validity"), "in_head": f.get("in_head"), "commit": f.get("commit"), "commits_seen": f.get("commits_seen"),
            "reason": f.get("reason", ""), "context": f.get("context", ""), "ml_probability": f.get("ml_probability")}


def build(tree: list[dict], history: list[dict], blocked: bool, limit: int = 8) -> str:
    rows = [f for f in tree + [h for h in history if h.get("in_head") is False] if f["severity"] in {"CRITICAL", "HIGH"}]
    head = f"### {'🚫 SecretGuard blocked this PR' if blocked else '✅ SecretGuard passed'}\n"
    if not rows:
        return f"{head}\nNo HIGH/CRITICAL findings.\n\n{MARKER}\n"
    table = ["| Severity | Kind | Type | Location | Where | ML | Redacted |", "|---|---|---|---|---|---|---|"]
    for f in rows[:20]:
        ml = f"{round(f['ml_probability'] * 100)}%" if f.get("ml_probability") is not None else "—"
        where = f"history only ({(f.get('commit') or '')[:8]})" if f.get("in_head") is False else "HEAD"
        table.append(f"| {f['severity']} | {'Risky code' if f.get('kind') == 'code' else 'Secret'} | {f['secret_type']} | `{f['file_path']}:{f['line_no']}` | {where} | {ml} | `{f['redacted_preview']}` |")
    parts = [head, "\n".join(table), "", f"<sub>AI mode: {provider.status()['provider']} · only redacted findings and masked snippets are sent</sub>", ""]
    for f in rows[:limit]:
        r = remediate(_as_finding(f))
        parts.append(f"<details><summary><b>✦ Fix: {f['secret_type']}</b> in <code>{f['file_path']}:{f['line_no']}</code></summary>\n")
        parts.append(r["summary"] + "\n")
        if r.get("patch"):
            parts.append("```diff\n" + r["patch"].rstrip() + "\n```\n")
        if r.get("runbook"):
            parts.append("**Rotate first:**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(r["runbook"], 1)) + "\n")
        if r.get("history_cleanup"):
            parts.append("**Then (optional) purge history:**\n```bash\n" + "\n".join(r["history_cleanup"]) + "\n```\n")
        parts.append("</details>\n")
    if blocked:
        parts.append("**Rotate, don't just delete:** a pushed secret is already compromised. After rotating, record it with "
                     "`python tools/secret_scan.py . --history --write-baseline .secretguard-baseline.json`.")
    parts.append(f"\n{MARKER}\n")
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", type=Path, default=Path("secretguard.json"))
    ap.add_argument("--history", type=Path, default=Path("secretguard-history.json"))
    ap.add_argument("--out", type=Path, default=Path("pr-comment.md"))
    ap.add_argument("--blocked", action="store_true")
    args = ap.parse_args()
    args.out.write_text(build(_load(args.tree), _load(args.history), args.blocked), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
