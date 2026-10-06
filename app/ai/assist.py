"""Hybrid triage, flags-only password coach, security copilot and incident reports."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Callable

from . import provider

# ------------------------------------------------------------------ hybrid triage
GREY_LOW, GREY_HIGH = 0.35, 0.85
VERDICTS = {"likely_real", "likely_test_fixture", "placeholder", "not_a_secret", "needs_human_review"}


def in_grey_zone(f: dict) -> bool:
    p = f.get("ml_probability")
    conf = f.get("confidence") or 0
    return f.get("kind") != "code" and ((p is not None and GREY_LOW <= p <= GREY_HIGH) or (p is None and 0.5 <= conf < 0.85)
                                        or f.get("type") in {"Generic secret assignment", "Hardcoded secret (ML)"} and (p or 0) < 0.95)


def offline_triage(f: dict) -> dict:
    ctx = (f.get("context") or "").lower()
    path = (f.get("file") or "").lower()
    reasons = f.get("ml_reasons") or []
    if re.search(r"(^|/)(tests?|fixtures?|examples?|docs?|mocks?)(/|$)|_test\.|\.spec\.", path) or re.search(r"\b(fake|dummy|example|sample|mock)\b", ctx):
        verdict, why = "likely_test_fixture", "It lives in a test/example path or the surrounding code says fake/dummy/example."
    elif any("placeholder" in r for r in reasons):
        verdict, why = "placeholder", "The value looks like a placeholder rather than a credential."
    elif any(r.startswith("+ variable name suggests") for r in reasons) or f.get("validity", "").endswith("VALID"):
        verdict, why = "likely_real", "A credential-like variable name plus a random-looking value in production code."
    else:
        verdict, why = "needs_human_review", "Signals are mixed; a human should decide."
    return {"verdict": verdict, "confidence": 0.6, "explanation": why}


TRIAGE_SYSTEM = ("You triage secret-scanner findings. You get a masked code snippet (values replaced by <REDACTED:...>), the file "
                 "path, the rule that fired and the ML classifier's probability and reasons. Decide: likely_real, likely_test_fixture, "
                 "placeholder or not_a_secret. Keys: verdict, confidence (0-1), explanation (one or two sentences, cite the evidence).")


def triage(f: dict) -> dict:
    safe = {k: f.get(k) for k in ("type", "severity", "file", "line", "validity", "confidence", "ml_probability", "ml_reasons", "context")}
    result, mode = provider.try_ai(lambda: provider.complete_json(TRIAGE_SYSTEM, json.dumps(safe, indent=2), 500), lambda: offline_triage(safe))
    verdict = result.get("verdict") if result.get("verdict") in VERDICTS else "needs_human_review"
    # Guardrail: AI may downgrade to "review", but can never dismiss a CRITICAL finding.
    if f.get("severity") == "CRITICAL" and verdict != "likely_real":
        verdict = "needs_human_review"
        result["explanation"] = (result.get("explanation") or "") + " (CRITICAL findings cannot be dismissed by AI - a human must confirm.)"
    return {"verdict": verdict, "confidence": float(result.get("confidence") or 0.5), "explanation": str(result.get("explanation") or "")[:600], "mode": mode}


# ------------------------------------------------------------------ password coach (flags only)
FLAG_TIPS = {
    "common": "It is one of the most common passwords - attackers try these first.",
    "identity_like": "It contains a name or something tied to you; attackers build guesses from public profile data.",
    "dictionary_like": "It is built from dictionary words in a predictable way.",
    "year": "It contains a year or date, one of the first things guessing tools append.",
    "keyboard": "It follows a keyboard pattern (qwerty, 1qaz...).",
    "sequence": "It contains a sequence like abc or 123.",
    "repeat_substring": "It repeats the same chunk, which barely adds strength.",
    "digit_only": "It is digits only - a much smaller search space.",
    "short": "It is shorter than 15 characters.",
    "breached": "It appears in real breach data, so it is on every attacker's list.",
}


def offline_coach(flags: dict) -> dict:
    issues = [FLAG_TIPS[k] for k, v in flags.get("flags", {}).items() if v and k in FLAG_TIPS]
    if flags.get("length", 0) < 15:
        issues.append(FLAG_TIPS["short"])
    guesses = flags.get("neural_log10") or flags.get("log10_guesses") or 0
    score = flags.get("score", 0)
    # Both signals must agree before we call a password strong (same conservative rule as the UI).
    if score < 45 or guesses < 10:
        verdict = "weak"
    elif score >= 80 and guesses >= 14 and not issues:
        verdict = "strong"
    else:
        verdict = "okay but improvable"
    advice = ["Use 5–6 random words joined with spaces or dashes (a password manager can generate them).",
              "Make it unique to this account - reuse turns one breach into many.",
              "Let the vault generate and remember it; you only need one master passphrase."]
    return {"verdict": verdict, "why": issues or ["No major pattern found."], "advice": advice,
            "summary": f"Combined score {score}/100 and ~10^{guesses:.0f} estimated guesses: {verdict}."}


COACH_SYSTEM = ("You are a friendly password coach. You NEVER see the password - only analysis flags. Explain in plain language why "
                "the password is weak or strong and give 3 concrete, NIST-aligned tips (length over complexity, passphrases, no reuse, "
                "password manager). Keys: verdict, why (list), advice (list), summary.")


def coach(flags: dict) -> dict:
    result, mode = provider.try_ai(lambda: provider.complete_json(COACH_SYSTEM, json.dumps(flags), 600), lambda: offline_coach(flags))
    result["mode"] = mode
    result["sent"] = flags
    return result


# ------------------------------------------------------------------ security copilot
TOOL_SPECS = [
    {"name": "get_security_overview", "description": "Breach-gate stats, latest test-account audit, finding counts by severity/status, MFA adoption.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "list_findings", "description": "List SecretGuard findings (redacted). Filter by severity, lifecycle status, kind, history-only, or age in hours since detection.",
     "input_schema": {"type": "object", "properties": {
         "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
         "status": {"type": "string", "enum": ["DETECTED", "TRIAGED", "CONTAINED", "ROTATED", "VERIFIED", "OPEN"]},
         "kind": {"type": "string", "enum": ["secret", "code"]}, "history_only": {"type": "boolean"},
         "older_than_hours": {"type": "number"}, "limit": {"type": "integer"}}}},
    {"name": "get_login_anomalies", "description": "Isolation-Forest scored sign-in windows (per IP, 5 minutes) for the last N hours.",
     "input_schema": {"type": "object", "properties": {"hours": {"type": "number"}}}},
    {"name": "get_audit_events", "description": "Recent audit events, optionally filtered by event type prefix.",
     "input_schema": {"type": "object", "properties": {"event_type": {"type": "string"}, "limit": {"type": "integer"}}}},
]

COPILOT_SYSTEM = ("You are the PrivPass security copilot for a SaaS identity team. Answer using ONLY the tools; never guess numbers. "
                  "Be concise: a direct answer first, then a short markdown list or table, then one recommended next action. "
                  "Findings are already redacted; never ask for secret values.")


def _fmt_findings(rows: list[dict]) -> str:
    if not rows:
        return "_No matching findings._"
    lines = ["| Severity | Type | Location | Status | Age |", "|---|---|---|---|---|"]
    for r in rows[:15]:
        lines.append(f"| {r['severity']} | {r['type']} | `{r['file']}:{r['line']}` | {r['status']}{' · history only' if r.get('in_head') is False else ''} | {r.get('age_hours', 0):.0f} h |")
    return "\n".join(lines)


def offline_copilot(question: str, tools: dict[str, Callable[..., Any]]) -> tuple[str, list[dict]]:
    q = question.lower()
    calls: list[dict] = []

    def call(name, **args):
        calls.append({"tool": name, "args": args}); return tools[name](**args)
    hours = float(m.group(1)) if (m := re.search(r"(\d+)\s*(h|hour)", q)) else (24.0 if "day" in q or "24" in q else None)
    if re.search(r"anomal|attack|stuffing|brute|suspicious|login", q):
        data = call("get_login_anomalies", hours=hours or 24)
        flagged = [w for w in data["windows"] if w["anomalous"]]
        if not flagged:
            return f"No anomalous sign-in windows in the last {hours or 24:.0f} h ({data['windows_scored']} windows scored).", calls
        body = "\n".join(f"- **{w['pattern']}** from `{w['ip']}` at {w['window_start'][11:16]}: {w['attempts']} attempts, {w['accounts']} accounts, score {w['score']:.2f} — " + "; ".join(w["reasons"][:2]) for w in flagged[:8])
        return f"**{len(flagged)} anomalous sign-in window(s)** in the last {hours or 24:.0f} h:\n\n{body}\n\n**Next:** block the source IPs at the edge and force a password reset for any targeted account that signed in successfully.", calls
    if re.search(r"finding|secret|key|unrotated|rotat|critical|leak|history|risky|code", q):
        args: dict[str, Any] = {}
        if "critical" in q: args["severity"] = "CRITICAL"
        elif re.search(r"\bhigh\b", q): args["severity"] = "HIGH"
        if re.search(r"unrotated|not rotated|open|still", q): args["status"] = "OPEN"
        if "history" in q: args["history_only"] = True
        if re.search(r"risky|code pattern", q): args["kind"] = "code"
        if hours: args["older_than_hours"] = hours
        rows = call("list_findings", **args, limit=50)["findings"]
        desc = ", ".join(f"{k}={v}" for k, v in args.items()) or "all"
        return f"**{len(rows)} finding(s)** match ({desc}).\n\n{_fmt_findings(rows)}\n\n**Next:** rotate the oldest CRITICAL first, then move it to ROTATED in the Incident Center.", calls
    if re.search(r"honey|bait|canary|trip", q):
        ov = call("get_security_overview")
        hs = ov.get("honeytokens", [])
        tripped = [h for h in hs if h["trips"]]
        if not hs:
            return "No honeytokens are planted yet. Create one in SecretGuard → Honeytokens.", calls
        body = "\n".join(f"- **{h['label']}**: {h['trips']} trip(s), last {h['last_trip_at'][:16].replace('T', ' ') if h['last_trip_at'] else 'never'}" for h in hs)
        return (f"**{len(tripped)} of {len(hs)} honeytoken(s) have been used by someone.**\n\n{body}\n\n"
                + ("**Next:** treat the repo/config holding a tripped token as compromised — rotate everything in it." if tripped else "**Next:** plant tokens in the places an attacker would look first (.env, CI config, backups).")), calls
    if re.search(r"overdue|deadline|sla|late", q):
        ov = call("get_security_overview"); d = ov.get("fix_deadlines", {})
        rows = call("list_findings", status="OPEN", limit=50)["findings"]
        late = [r for r in rows if r.get("sla", {}).get("state") in {"overdue", "at_risk"}] if rows and "sla" in rows[0] else []
        return (f"**{d.get('overdue', 0)} finding(s) are overdue** and {d.get('at_risk', 0)} at risk. Mean time to rotate: {d.get('mean_hours_to_rotate') or '—'} h; deadline compliance: {d.get('sla_compliance_percent') or '—'}%.\n\n"
                + _fmt_findings(late or rows[:10])), calls
    if re.search(r"audit|event|who|activity", q):
        rows = call("get_audit_events", limit=15)["events"]
        return "**Recent audit events:**\n\n" + "\n".join(f"- {e['created_at'][:16].replace('T', ' ')} · {e['event']} ({e['severity']})" for e in rows), calls
    ov = call("get_security_overview")
    g, a = ov["gate"], ov.get("account_audit") or {}
    return ("**Security posture summary**\n\n"
            f"- Breach gate: {g['blocked']} of {g['attempts']} signup/reset attempts blocked ({g['breached_percent']}% used a breached password)\n"
            f"- Test-account audit: {a.get('breached_percent', '—')}% of {a.get('total', '—')} accounts use a breached password\n"
            f"- Findings: {ov['findings']['open_critical']} open CRITICAL, {ov['findings']['open_high']} open HIGH, {ov['findings']['history_only']} only in git history\n"
            f"- MFA adoption: {ov['mfa_adoption_percent']}%\n"
            f"- Fix deadlines: {ov.get('fix_deadlines', {}).get('overdue', 0)} overdue, compliance {ov.get('fix_deadlines', {}).get('sla_compliance_percent') or '—'}%\n"
            f"- Honeytokens: {sum(h['trips'] for h in ov.get('honeytokens', []))} trip(s) across {len(ov.get('honeytokens', []))} bait key(s)\n\n**Next:** ask me “which critical findings are still unrotated?” or “any login attacks today?”"), calls


def copilot(question: str, tools: dict[str, Callable[..., Any]]) -> dict:
    def ai():
        return provider.run_tools(COPILOT_SYSTEM, question, TOOL_SPECS, tools)
    (answer, calls), mode = provider.try_ai(ai, lambda: offline_copilot(question, tools))
    return {"answer": answer, "tool_calls": calls, "mode": mode}


# ------------------------------------------------------------------ incident report
REPORT_SYSTEM = ("Write a concise security incident report in Markdown for engineering leadership at a fintech company. Sections: "
                 "Executive summary (3 sentences), Impact & scope, Timeline, Findings (table), Containment & rotation status, "
                 "Root cause, Actions (owner-less checklist), Lessons learned. Use only the data provided; say 'unknown' when missing. "
                 "Values are redacted - never invent them.")


def offline_report(data: dict) -> str:
    ov, findings, anomalies, events = data["overview"], data["findings"], data["anomalies"], data["audit"]
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    open_crit = [f for f in findings if f["severity"] == "CRITICAL" and f["status"] in {"DETECTED", "TRIAGED", "CONTAINED"}]
    hist = [f for f in findings if f.get("in_head") is False]
    flagged = [w for w in anomalies.get("windows", []) if w["anomalous"]]
    lines = [f"# Incident report — credential exposure\n_Generated {now} by PrivPass Shield (offline mode)_\n",
             "## Executive summary",
             f"SecretGuard detected **{len(findings)}** exposed credentials or risky patterns across the latest scans, "
             f"{len(open_crit)} of them CRITICAL and not yet rotated. {len(hist)} secrets were deleted from the code but remain in git history. "
             f"{'Sign-in telemetry shows ' + str(len(flagged)) + ' anomalous window(s) consistent with automated attacks.' if flagged else 'No anomalous sign-in activity was detected.'}\n",
             "## Impact & scope",
             f"- Repositories: {', '.join(sorted({f['repo'] for f in findings if f.get('repo')})) or 'unknown'}",
             f"- Credential types: {', '.join(sorted({f['type'] for f in findings if f.get('kind') == 'secret'})) or 'none'}",
             f"- Breach gate: {ov['gate']['blocked']} blocked of {ov['gate']['attempts']} signup/reset attempts\n",
             "## Timeline"]
    for f in sorted([f for f in findings if f.get("commit_date")], key=lambda x: x["commit_date"])[:8]:
        lines.append(f"- {f['commit_date'][:10]} — {f['type']} introduced in `{f['file']}` (commit `{(f.get('commit') or '')[:8]}`)")
    for e in events[:6][::-1]:
        lines.append(f"- {e['created_at'][:16].replace('T', ' ')} — {e['event']}")
    lines += ["", "## Findings", _fmt_findings(findings), "", "## Containment & rotation status"]
    for status in ("DETECTED", "TRIAGED", "CONTAINED", "ROTATED", "VERIFIED"):
        lines.append(f"- {status}: {sum(f['status'] == status for f in findings)}")
    lines += ["", "## Root cause", "Credentials were hardcoded in source and committed; removal from HEAD did not remove them from history.", "",
              "## Actions", "- [ ] Rotate every CRITICAL/HIGH credential at its provider (runbooks in SecretGuard)",
              "- [ ] Move secrets to a secret manager; read from the environment", "- [ ] Record rotations in `.secretguard-baseline.json`",
              "- [ ] Make the SecretGuard gate a required status check", "- [ ] Review provider audit logs since each introducing commit"]
    if flagged:
        lines.append("- [ ] Block anomalous source IPs and reset passwords for targeted accounts")
    lines += ["", "## Lessons learned", "Pre-commit scanning plus a required CI gate stops the leak before merge; rotation - not deletion - closes it."]
    return "\n".join(lines)


def incident_report(data: dict) -> dict:
    result, mode = provider.try_ai(lambda: provider.complete(REPORT_SYSTEM, json.dumps(data, default=str)[:30000], 2500), lambda: offline_report(data))
    return {"markdown": result, "mode": mode}
