"""Prove what the PrivPass server sends to Have I Been Pwned.

Runs the real server code (sign-up, a blocked breached sign-up, sign-in, and the admin "re-check all
passwords" sweep) against a local stand-in for api.pwnedpasswords.com that RECORDS every request it
receives. Then it checks every recorded request and prints them:

  * the URL is /range/ + exactly 5 hex characters, with no query string and no request body;
  * the password, its full SHA-1 and the 35-character SHA-1 suffix appear nowhere (URL, headers, body);
  * what the browser sent to our server contains no password and no full hash either.

    python tools/prove_hibp_privacy.py

Uses a throwaway database in a temp folder; your real accounts are never touched. No internet needed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
import threading
import unicodedata
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CLEAN_PASSWORD = "Lantern-Orbit-Copper-Meadow-2026"
BREACHED_PASSWORD = "correct horse battery staple"
ADMIN_EMAIL, ADMIN_PASSWORD = "proof-admin@example.com", "Proof-Admin-Passphrase-2026"


def sha1(pw: str) -> str:
    return hashlib.sha1(unicodedata.normalize("NFKC", pw).encode()).hexdigest().upper()  # nosec B324 secretguard:allow - HIBP format


# ------------------------------------------------------------------ a recording stand-in for HIBP
RECORDED: list[dict] = []
BREACHED_HASHES = {sha1(BREACHED_PASSWORD): 3_100_000}  # secretguard:allow - HIBP hash format of a demo password


class FakeHIBP(BaseHTTPRequestHandler):
    def _record(self, body: bytes) -> None:
        RECORDED.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": body})

    def do_GET(self):  # noqa: N802 - http.server API
        self._record(b"")
        prefix = self.path.rsplit("/", 1)[-1].upper()
        lines = [f"{h[5:]}:{c}" for h, c in BREACHED_HASHES.items() if h.startswith(prefix)]
        lines += [f"{i:035X}:{i % 7 + 1}" for i in range(800)]     # ~800 unrelated suffixes, like the real range
        lines += [f"{(i + 9000):035X}:0" for i in range(200)]       # padding rows (count 0), like Add-Padding
        data = "\r\n".join(lines).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802 - would only happen if something tried to send a body
        n = int(self.headers.get("Content-Length") or 0)
        self._record(self.rfile.read(n))
        self.send_response(405)
        self.end_headers()

    def log_message(self, *args):  # keep the output clean
        pass


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeHIBP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tmp = tempfile.mkdtemp(prefix="privpass-proof-")
    os.environ.update({
        "APP_ENV": "development", "APP_SECRET": "proof-secret-0123456789abcdef-proof",
        "DATABASE_URL": f"sqlite:///{Path(tmp, 'proof.db').as_posix()}",
        "HIBP_RANGE_URL": f"http://127.0.0.1:{server.server_port}/range/",
        "PRIVPASS_BREACH_WATCH_MINUTES": "0", "PRIVPASS_PUBLIC_DEMO": "false",
        "PRIVPASS_ADMIN_EMAIL": ADMIN_EMAIL, "PRIVPASS_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    })

    from fastapi.testclient import TestClient
    from app.breachwatch import derive_verifier, derive_watch
    from app.main import app

    e = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
    d = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    browser_sent: list[dict] = []

    def post(c, url, body):
        if "pp_csrf" not in c.cookies:
            c.get("/api/csrf")
        browser_sent.append({"url": url, "body": body})
        return c.post(url, json=body, headers={"X-CSRF-Token": c.cookies.get("pp_csrf")})

    def material(pw):  # exactly what static/app.js sends for a new password
        h, salt, ws = sha1(pw), os.urandom(16), os.urandom(16)
        return {"salt_b64": e(salt), "watch_salt_b64": e(ws), "prefix": h[:5], "watch_b64": e(derive_watch(h, ws))}

    def signup(c, email, pw):
        ticket = post(c, "/api/auth/breach-ticket", {"purpose": "signup"}).json()["ticket"]
        return post(c, "/api/auth/signup", {"email": email, **material(pw), "score": 90, "score_label": "Excellent", "breached": False,
                                            "breach_gate": {"ticket": ticket, "hibp_status": "safe", "hibp_mode": "live", "password_length": len(pw)}})

    def login(c, email, pw):
        ch = post(c, "/api/auth/challenge", {"email": email}).json()
        h = sha1(pw)
        v = derive_verifier(derive_watch(h, d(ch["watch_salt_b64"])), h[:5], d(ch["salt_b64"]))
        return post(c, "/api/auth/login", {"email": email, "nonce": ch["nonce"], "proof": hmac.new(v, ch["nonce"].encode(), hashlib.sha256).hexdigest()})

    print("PrivPass Shield: what the SERVER sends to Have I Been Pwned\n")
    with TestClient(app) as user, TestClient(app) as attacker, TestClient(app) as admin:
        steps = [
            ("Sign up with a clean password", lambda: signup(user, "proof-user@example.com", CLEAN_PASSWORD)),
            ("Sign up with a BREACHED password", lambda: signup(attacker, "proof-breached@example.com", BREACHED_PASSWORD)),
            ("Sign in (fresh breach check)", lambda: login(user, "proof-user@example.com", CLEAN_PASSWORD)),
            ("Admin signs in", lambda: login(admin, ADMIN_EMAIL, ADMIN_PASSWORD)),
            ("Admin: Re-check all passwords now", lambda: post(admin, "/api/admin/breach-watch/run", {})),
        ]
        for label, run in steps:
            before = len(RECORDED)
            status = run().status_code
            new = RECORDED[before:]
            sent = ", ".join(f"{r['method']} {r['path']}" for r in new) or "(no request: answered from the 15-minute cache)"
            print(f"  {label:<38} -> app answered {status}; sent to HIBP: {sent}")
    server.shutdown()

    secrets = []
    for pw in (CLEAN_PASSWORD, BREACHED_PASSWORD, ADMIN_PASSWORD):
        h = sha1(pw)
        secrets += [("password", pw), ("full SHA-1", h), ("SHA-1 suffix", h[5:])]

    def leaks(blob: str) -> list[str]:
        low = blob.lower()
        return [f"{kind} of a test password" for kind, val in secrets if val.lower() in low]

    checks = []
    shape_ok = all(r["method"] == "GET" and re.fullmatch(r"/range/[0-9A-F]{5}", r["path"]) and not r["body"] for r in RECORDED)
    checks.append(("Every request is GET /range/ + exactly 5 hex characters, no query, no body", shape_ok and bool(RECORDED)))
    hibp_leaks = sorted({x for r in RECORDED for x in leaks(r["path"] + json.dumps(r["headers"]) + r["body"].decode(errors="replace"))})
    checks.append(("No password, full SHA-1 or suffix in any request to HIBP (URL, headers, body)", not hibp_leaks))
    checks.append(("Padding was requested, so even the response size reveals nothing (Add-Padding: true)",
                   all(r["headers"].get("Add-Padding") == "true" for r in RECORDED)))
    browser_leaks = sorted({x for b in browser_sent for x in leaks(json.dumps(b["body"])) if "prefix" not in x})
    checks.append(("What the browser sent to OUR server has no password and no full SHA-1", not browser_leaks))

    print(f"\nRequests the server made to HIBP: {len(RECORDED)}")
    for r in RECORDED:
        print(f"  {r['method']} {r['path']}   (body: {len(r['body'])} bytes; Add-Padding: {r['headers'].get('Add-Padding')})")
    print("\nChecks:")
    for text, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    for x in hibp_leaks + browser_leaks:
        print(f"         found: {x}")
    print("\nFor comparison, the clean password's SHA-1 is", sha1(CLEAN_PASSWORD)[:5] + "…" + "(35 more characters that never left)")  # secretguard:allow - prints the prefix only
    ok = all(c[1] for c in checks)
    print("\nRESULT:", "PROVED - only 5-character prefixes left the server." if ok else "FAILED - see above.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
