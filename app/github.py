"""GitHub integration: scan a repository by URL (full history) and open a fix pull request.

* Public repos need nothing. Private repos and PR creation need GITHUB_TOKEN in .env
  (a fine-grained token with Contents: read/write and Pull requests: read/write on the repo).
* The fix PR is built from the *real* file fetched from GitHub; the target line is matched against
  the masked context captured at scan time, so a stale scan can never overwrite the wrong line.
* The token is never logged, stored in the database, or sent to an AI model.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import APP_SECRET
from .db import db
from .models import Scan, SecretFinding
from .redaction import mask_text
from .scanner import _GIT_HARDENING, git_available, merge_history, scan_dir, scan_git_history

router = APIRouter()
REPO_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$")
API = "https://api.github.com"


def _main():
    from . import main
    return main


def _token() -> str:
    return os.environ.get("GITHUB_TOKEN", "").strip()


def http_client() -> httpx.Client:  # replaced in tests with a mock transport
    return httpx.Client(timeout=20, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "PrivPass-SecretGuard"})


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {_token()}"} if _token() else {}


def clone(owner: str, repo: str, dest: Path, depth: int = 300) -> None:
    url = f"https://github.com/{owner}/{repo}.git"
    if _token():
        url = f"https://x-access-token:{_token()}@github.com/{owner}/{repo}.git"
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    cmd = ["git", *_GIT_HARDENING, "-c", "protocol.https.allow=always", "clone", "--quiet", "--no-tags", f"--depth={depth}",
           "--filter=blob:limit=2m", url, str(dest)]
    try:
        subprocess.run(cmd, env=env, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "clone timed out (repository too large?)")
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or b"").decode("utf-8", "replace").replace(_token() or "\0", "***")
        raise HTTPException(400, "could not clone repository" + (" (private? set GITHUB_TOKEN)" if "not found" in msg.lower() or "authentication" in msg.lower() else ""))


class GithubScanBody(BaseModel):
    url: str = Field(max_length=300)


@router.post("/api/scans/github")
def scan_github(body: GithubScanBody, request: Request, session: Session = Depends(db)):
    m = _main()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request); m.rate_limited(request, "scan", 10, 60)
    match = REPO_URL.match(body.url.strip())
    if not match:
        raise HTTPException(400, "enter a URL like https://github.com/owner/repo")
    if not git_available():
        raise HTTPException(501, "git is not installed on the server")
    owner, repo = match.group(1), match.group(2)
    with tempfile.TemporaryDirectory(prefix="pp-gh-") as tmp:
        dest = Path(tmp) / repo
        clone(owner, repo, dest)
        tree, files = scan_dir(dest, APP_SECRET[:24])
        try:
            hist, _ = scan_git_history(dest, APP_SECRET[:24])
        except ValueError:
            hist = []
        findings = merge_history(tree, hist)
        head = subprocess.run(["git", *_GIT_HARDENING, "-C", str(dest), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True).stdout.strip()
    scan, rows = m._persist_scan(session, user, f"github.com/{owner}/{repo}", files, findings)
    scan.source_url, scan.source_ref = f"https://github.com/{owner}/{repo}", head or None
    m.audit(session, user.id, "GITHUB_REPO_SCAN", severity="HIGH" if any(f.severity == "CRITICAL" for f in findings) else "INFO",
            meta={"repo": f"{owner}/{repo}", "files": files, "findings": len(findings)})
    session.commit()
    out = m._scan_response(scan, rows)
    out["source_url"] = scan.source_url
    return out


@router.get("/api/github/status")
def github_status():
    return {"token_configured": bool(_token()), "git_available": git_available()}


def _apply_line(content: str, lineno: int, masked_expected: str, new_line: str, ensure_import_os: bool) -> str:
    lines = content.split("\n")
    if not 1 <= lineno <= len(lines):
        raise HTTPException(409, "the file changed since the scan (line out of range) - rescan first")
    if mask_text(lines[lineno - 1]).strip() != masked_expected.strip():
        raise HTTPException(409, "the file changed since the scan (line no longer matches) - rescan first")
    lines[lineno - 1] = new_line
    out = "\n".join(lines)
    if ensure_import_os and not re.search(r"^\s*import os\b|^\s*from os import", out, re.M):
        out = "import os\n" + out
    return out


@router.post("/api/github/fix-pr/{finding_id}")
def fix_pr(finding_id: str, request: Request, session: Session = Depends(db)):
    m = _main()
    user, _ = m.get_current_session(request, session); m.require_same_origin(request); m.rate_limited(request, "ai", 20, 60)
    if user.workspace == "demo":
        raise HTTPException(403, "Fix pull requests use the server's real GitHub token, so they are disabled for demo accounts.")
    if not _token():
        raise HTTPException(412, "set GITHUB_TOKEN in .env to open pull requests")
    f = session.get(SecretFinding, finding_id)
    if not f or (f.owner_user_id != user.id and user.role != "admin"):
        raise HTTPException(404, "finding not found")
    scan = session.get(Scan, f.scan_id)
    if not scan or not scan.source_url:
        raise HTTPException(400, "fix PRs are available for repositories scanned by GitHub URL")
    if f.in_head is False:
        raise HTTPException(400, "this secret only exists in git history - rotate it; there is no current line to patch")
    from .ai.remediation import offline_patch, remediate
    fd = {"type": f.secret_type, "kind": f.kind, "file": f.file_path, "line": f.line_no, "context": f.context_masked, "severity": f.severity,
          "in_head": f.in_head, "reason": f.reason, "validity": f.validity}
    patch, _notes = offline_patch(fd)
    plus = [l[1:] for l in patch.splitlines() if l.startswith("+") and not l.startswith("+++")]
    minus = [l[1:] for l in patch.splitlines() if l.startswith("-") and not l.startswith("---")]
    if not plus or not minus:
        raise HTTPException(422, "no automatic patch for this finding - use the runbook")
    rem = remediate(fd)
    owner, repo = scan.source_url.rstrip("/").split("/")[-2:]
    auth = _auth_headers()
    with http_client() as gh:
        meta = gh.get(f"{API}/repos/{owner}/{repo}", headers=auth)
        if meta.status_code != 200:
            raise HTTPException(502, f"GitHub: cannot read repository ({meta.status_code})")
        base = meta.json()["default_branch"]
        ref = gh.get(f"{API}/repos/{owner}/{repo}/git/ref/heads/{base}", headers=auth).json()
        file = gh.get(f"{API}/repos/{owner}/{repo}/contents/{f.file_path}", params={"ref": base}, headers=auth)
        if file.status_code != 200:
            raise HTTPException(409, "file not found on the default branch - rescan first")
        body = file.json()
        content = base64.b64decode(body["content"]).decode("utf-8")
        new = _apply_line(content, f.line_no, minus[0], plus[0], ensure_import_os="os.environ" in plus[0])
        branch = f"privpass/fix-{f.id[:8]}"
        r = gh.post(f"{API}/repos/{owner}/{repo}/git/refs", headers=auth, json={"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]})
        if r.status_code not in (201, 422):  # 422 = branch already exists
            raise HTTPException(502, f"GitHub: cannot create branch ({r.status_code})")
        put = gh.put(f"{API}/repos/{owner}/{repo}/contents/{f.file_path}", headers=auth, json={
            "message": f"fix(secrets): read {f.secret_type} from the environment\n\nOpened by PrivPass SecretGuard.",
            "content": base64.b64encode(new.encode("utf-8")).decode(), "sha": body["sha"], "branch": branch})
        if put.status_code not in (200, 201):
            raise HTTPException(502, f"GitHub: cannot commit ({put.status_code})")
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(rem.get("runbook", []), 1))
        pr_body = (f"### 🔐 PrivPass SecretGuard fix\n\n**{f.secret_type}** in `{f.file_path}:{f.line_no}` is now read from the environment.\n\n"
                   f"> ⚠️ **Merging this does not un-leak the old value.** Rotate it first:\n\n{steps}\n\n"
                   f"After rotating, record it: `python tools/secret_scan.py . --history --write-baseline .secretguard-baseline.json`\n\n"
                   "<sub>Generated from a masked snippet - the secret value was never read by PrivPass or any AI.</sub>")
        pr = gh.post(f"{API}/repos/{owner}/{repo}/pulls", headers=auth, json={"title": f"Remove hardcoded {f.secret_type} from {f.file_path}", "head": branch, "base": base, "body": pr_body})
        if pr.status_code not in (200, 201):
            raise HTTPException(502, f"GitHub: cannot open pull request ({pr.status_code})")
        url = pr.json()["html_url"]
    m.audit(session, user.id, "GITHUB_FIX_PR", meta={"finding_id": f.id, "pr": url}); session.commit()
    return {"ok": True, "pr_url": url, "branch": branch}
