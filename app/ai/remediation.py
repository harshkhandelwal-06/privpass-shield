"""AI remediation copilot: patch + rotation runbook + history clean-up for one finding.

Input is only finding metadata and the *masked* context snippet stored at scan time - the secret
itself was never stored, so it cannot be sent.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from . import provider

RUNBOOKS = {
    "AWS access key": ("AWS IAM", "https://console.aws.amazon.com/iam/home#/security_credentials", [
        "IAM → Users → the key's owner → Security credentials → Create access key (new key first, so nothing breaks).",
        "Deploy the new key via your secret manager / CI secret, then mark the leaked key Inactive.",
        "Review CloudTrail for API calls made with the leaked key ID since the introducing commit.",
        "Delete the inactive key once traffic has moved; prefer IAM roles/OIDC over long-lived keys."]),
    "AWS temporary access key": ("AWS STS", "https://console.aws.amazon.com/iam/home", [
        "Revoke active sessions for the role (IAM → Roles → Revoke sessions).",
        "Find how a session credential ended up in code; replace with role assumption at runtime.",
        "Review CloudTrail for activity from the session."]),
    "GitHub token": ("GitHub", "https://github.com/settings/tokens", [
        "Settings → Developer settings → Personal access tokens → revoke the token (or ask an org owner to).",
        "Create a fine-grained replacement with the minimum repositories and permissions; for CI use GITHUB_TOKEN or a GitHub App.",
        "Check the org audit log / security log for use of the token since the introducing commit."]),
    "GitLab token": ("GitLab", "https://gitlab.com/-/user_settings/personal_access_tokens", [
        "Revoke the token in User settings → Access tokens.", "Issue a scoped replacement with an expiry date.",
        "Review the audit events for the token's user."]),
    "Stripe secret key": ("Stripe", "https://dashboard.stripe.com/apikeys", [
        "Developers → API keys → Roll the secret key (optionally keep the old one alive for a short overlap).",
        "Prefer a restricted key (rk_) limited to the resources this service needs.",
        "Review Developers → Logs / Events for requests made with the old key."]),
    "Slack token": ("Slack", "https://api.slack.com/apps", [
        "Your app → OAuth & Permissions → Revoke tokens / reinstall the app to issue new ones.",
        "Enable token rotation for the app.", "Review the workspace access logs."]),
    "Google API key": ("Google Cloud", "https://console.cloud.google.com/apis/credentials", [
        "APIs & Services → Credentials → regenerate the key.",
        "Add API and application restrictions (HTTP referrers / IPs) to the new key.", "Check the API usage metrics for spikes."]),
    "OpenAI API key": ("OpenAI", "https://platform.openai.com/api-keys", [
        "Revoke the key on the API keys page and create a project-scoped replacement.", "Check usage for the project since the introducing commit."]),
    "Anthropic API key": ("Anthropic", "https://console.anthropic.com/settings/keys", [
        "Console → Settings → API keys → disable/delete the leaked key and create a new one.",
        "Put the new key in .env or a secret manager (ANTHROPIC_API_KEY) - never in code.", "Check Usage in the console for unexpected spend."]),
    "SendGrid API key": ("SendGrid", "https://app.sendgrid.com/settings/api_keys", [
        "Delete the key and create a replacement with only Mail Send permission.", "Review Activity for unexpected mail."]),
    "Private key": ("Key owner / PKI", None, [
        "Treat the key pair as compromised: generate a new key pair.",
        "Replace it everywhere it is trusted (authorized_keys, TLS certificate re-issue and revoke, JWT signing JWKS, deploy keys).",
        "Revoke any certificate issued for the old key."]),
    "JWT": ("Identity provider", None, [
        "Revoke the token/session at the issuer, or rotate the signing key if the token must not remain valid until expiry.",
        "Never hardcode bearer tokens; fetch them at runtime with a client credential stored in a secret manager."]),
    "Connection string": ("Database", None, [
        "Change the database user's password (ALTER USER ... PASSWORD ...) or create a new user and drop the old one.",
        "Put the connection string in a secret manager / environment variable.",
        "Review DB logs for connections from unexpected hosts; restrict network access to the DB."]),
}
GENERIC_RUNBOOK = ("the issuing service", None, [
    "Identify which service issued this credential (owner, variable name, commit author).",
    "Revoke/rotate it at that service and issue a new value with least privilege.",
    "Store the new value in a secret manager or CI secret and read it from the environment.",
    "Review the service's access logs for use since the introducing commit."])

CODE_FIXES = [
    (r"subprocess\.(\w+)\(\s*f?([\"'])(.+?)\2\s*,\s*shell\s*=\s*True\s*\)", lambda m: f"subprocess.{m.group(1)}(shlex.split({m.group(2)}{m.group(3)}{m.group(2)}), shell=False)  # better: build the list explicitly", "Use an argument list; never pass user input through a shell."),
    (r",\s*verify\s*=\s*False", lambda m: "", "Remove the disabled certificate check; for a private CA pass the CA bundle path instead."),
    (r"yaml\.load\(([^)]*)\)", lambda m: f"yaml.safe_load({m.group(1)})", "yaml.safe_load cannot construct arbitrary Python objects."),
    (r"pickle\.loads?\(([^)]*)\)", lambda m: f"json.loads({m.group(1)})", "Use JSON (or a signed, versioned format) for untrusted data."),
    (r"(?<![\w.])eval\(([^)]*)\)", lambda m: f"ast.literal_eval({m.group(1)})", "ast.literal_eval only accepts Python literals."),
    (r"\.execute\(\s*f([\"'])(.*?)\{(\w+)\}(.*?)\1\s*\)", lambda m: f".execute({m.group(1)}{m.group(2)}?{m.group(4)}{m.group(1)}, ({m.group(3)},))", "Parameterised queries keep data out of the SQL grammar."),
]


def _env_name(var: str, secret_type: str) -> str:
    if var and not re.fullmatch(r"(x|v|k|s|value|data|default|param|arg|item|result|cfg|fallback|prod)", var, re.I):
        return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", var).upper().replace("-", "_")
    return re.sub(r"[^A-Z0-9]+", "_", secret_type.upper()).strip("_")


def _target_line(context: str) -> tuple[int, str] | None:
    for raw in context.splitlines():
        m = re.match(r"\s*(\d+)>\s?(.*)$", raw)
        if m:
            return int(m.group(1)), m.group(2)
    return None


def offline_patch(f: dict) -> tuple[str, list[str]]:
    target = _target_line(f.get("context") or "")
    path = f.get("file") or "file"
    notes: list[str] = []
    if not target:
        return "", ["No code context was captured for this finding; apply the runbook manually."]
    lineno, line = target
    ext = PurePosixPath(path).suffix.lower()
    new = None
    if f.get("kind") == "code":
        for rx, repl, note in CODE_FIXES:
            if re.search(rx, line):
                new = re.sub(rx, repl, line); notes.append(note); break
        if new is None:
            notes.append(f.get("reason", "").replace("Risky code pattern; ", ""))
    else:
        m = re.match(r"(\s*)(?:export\s+|const\s+|let\s+|var\s+)?([A-Za-z_][\w.]*)\s*(=|:)\s*", line)
        var = m.group(2).split(".")[-1] if m else ""
        env = _env_name(var, f.get("type", "SECRET"))
        indent = m.group(1) if m else ""
        if PurePosixPath(path).name.startswith(".env"):
            new = f"{env}=  # set in your secret manager / CI secret; never commit real values"
            notes.append("Remove the value from the committed .env, add .env to .gitignore and commit a .env.example with an empty value.")
        elif ext == ".py":
            new = f'{indent}{var or env.lower()} = os.environ["{env}"]'; notes.append("Add `import os` if the module does not import it yet.")
        elif ext in {".js", ".ts", ".jsx", ".tsx"}:
            decl = "const " if re.match(r"\s*(const|let|var)\s", line) else ""
            sep = ": " if m and m.group(3) == ":" else " = "
            new = f"{indent}{decl}{var or env.lower()}{sep}process.env.{env}{';' if line.rstrip().endswith(';') else ','if line.rstrip().endswith(',') else ''}"
        elif ext in {".yml", ".yaml"}:
            new = f"{indent}{var}: ${{{env}}}"; notes.append("Inject the value at deploy time (e.g. from a secret manager or CI secret).")
        elif ext == ".json":
            notes.append(f"JSON cannot read environment variables: move `{var}` out of this file and load it from `{env}` at runtime.")
        else:
            notes.append(f"Replace the literal with a lookup of the `{env}` environment variable / secret manager entry.")
    if new is None:
        return "", notes
    diff = f"--- a/{path}\n+++ b/{path}\n@@ -{lineno} +{lineno} @@\n-{line}\n+{new}\n"
    return diff, notes


def _history_commands(f: dict) -> list[str]:
    path = f.get("file") or "<file>"
    cmds = [
        "# 1) Rotate first (runbook above). Then, optionally, purge the value from history:",
        "pip install git-filter-repo",
        "echo 'PASTE-THE-OLD-SECRET==>REMOVED' > replacements.txt   # locally only - never commit this file",
        "git filter-repo --replace-text replacements.txt",
        "git push --force --all && git push --force --tags",
        "# 2) Ask collaborators to re-clone; invalidate CI caches; open a GitHub support ticket to purge cached PR views if needed.",
    ]
    if path.endswith((".pem", ".key")) or PurePosixPath(path).name.startswith(".env"):
        cmds.insert(3, f"git filter-repo --invert-paths --path {path}   # remove the whole file from history")
    return cmds


def offline_remediation(f: dict) -> dict:
    patch, notes = offline_patch(f)
    if f.get("kind") == "code":
        return {"summary": f"Risky code pattern: {f.get('type', '').replace('Risky: ', '')}. Rewrite the call so untrusted input cannot change its behaviour.",
                "patch": patch, "notes": notes, "provider": None, "console": None,
                "runbook": ["Apply the patch (or an equivalent safe API).", "Add a unit test that feeds hostile input.", "Re-run SecretGuard; the rule should no longer match."],
                "history_cleanup": [], "verify": ["python tools/secret_scan.py . --fail-on-risky high"]}
    prov, console, steps = RUNBOOKS.get(f.get("type"), GENERIC_RUNBOOK)
    history_note = ("This value was deleted from HEAD but is still in git history - every clone has it."
                    if f.get("in_head") is False else "The value is in the current code and in git history once pushed.")
    return {
        "summary": f"{f.get('type')} hardcoded in {f.get('file')}:{f.get('line')}. {history_note} Rotate it at {prov} first - deleting the line does not un-leak it.",
        "patch": patch, "notes": notes, "provider": prov, "console": console, "runbook": steps,
        "history_cleanup": _history_commands(f),
        "verify": ["Confirm the old credential is rejected by the provider (e.g. a request with it returns 401).",
                   "python tools/secret_scan.py . --history --write-baseline .secretguard-baseline.json --baseline-note \"rotated <date> by <you>\"",
                   "Move the finding to ROTATED → VERIFIED in the Incident Center."],
    }


SYSTEM = ("You are PrivPass SecretGuard's remediation copilot for a fintech platform team. You receive ONE finding with a "
          "masked code snippet (secrets are already replaced by <REDACTED:...> placeholders - never invent or guess values). "
          "Produce a precise fix. Keys: summary (2 sentences), patch (a unified diff that only touches the marked '>' line, "
          "keeping placeholders out of the new code), notes (list), runbook (list of concrete provider-specific rotation steps), "
          "history_cleanup (list of shell commands; rotation comes first, history purge is optional hygiene), verify (list).")


def remediate(finding: dict) -> dict:
    safe = {k: finding.get(k) for k in ("type", "severity", "kind", "file", "line", "validity", "in_head", "commit", "commits_seen", "reason", "context", "ml_probability")}
    base = offline_remediation(safe)

    def ai():
        out = provider.complete_json(SYSTEM, "Finding:\n" + json.dumps(safe, indent=2))
        merged = {**base, **{k: v for k, v in out.items() if k in base and v}}
        merged["console"] = base["console"]  # console URLs come from our vetted list only
        return merged
    result, mode = provider.try_ai(ai, lambda: base)
    result["mode"] = mode
    result["ai_input"] = safe  # exactly what was (or would be) sent - shown in the UI
    return result
