"""Opt-in live credential verification for SecretGuard (CLI / CI only).

Why opt-in: verifying a key means sending it to its own provider. That is exactly what the
provider already trusts, but it must never happen silently on a developer laptop or from the web
upload path. Enable it explicitly with ``secret_scan.py --verify`` in CI.

Every probe is a read-only "who am I" style call against the provider's official API host, with a
short timeout. Outcomes:

* ``LIVE_VERIFIED``      provider accepted the credential  -> confidence 99.9 %, always blocks
* ``PROVIDER_REJECTED``  provider said revoked/invalid      -> confidence capped at 60 %, non-blocking
* ``UNVERIFIABLE``       no safe single-value probe exists (e.g. an AWS key ID without its secret)
* ``VERIFY_ERROR``       network/timeout/unexpected status  -> finding unchanged

Results are cached per value for the run; raw values are never logged or written anywhere.
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from typing import Callable, Optional

TIMEOUT_SECONDS = 6
USER_AGENT = "PrivPass-SecretGuard-Verifier/6.0"


def _request(url: str, headers: dict[str, str], method: str = "GET", data: bytes | None = None) -> tuple[int, bytes]:
    if not url.startswith("https://"):
        raise ValueError("verifier probes must use https")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers}, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:  # nosec B310 - fixed https provider hosts only (checked above)
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def _status_probe(url: str, headers: dict[str, str], live: set[int] = frozenset({200}), rejected: set[int] = frozenset({401, 403})) -> str:
    status, _ = _request(url, headers)
    if status in live:
        return "LIVE_VERIFIED"
    if status in rejected:
        return "PROVIDER_REJECTED"
    return "VERIFY_ERROR"


def _github(secret: str) -> str:
    return _status_probe("https://api.github.com/user", {"Authorization": f"Bearer {secret}", "Accept": "application/vnd.github+json"})


def _gitlab(secret: str) -> str:
    return _status_probe("https://gitlab.com/api/v4/personal_access_tokens/self", {"PRIVATE-TOKEN": secret})


def _stripe(secret: str) -> str:
    token = base64.b64encode(f"{secret}:".encode()).decode()
    return _status_probe("https://api.stripe.com/v1/balance", {"Authorization": f"Basic {token}"})


def _openai(secret: str) -> str:
    return _status_probe("https://api.openai.com/v1/models", {"Authorization": f"Bearer {secret}"})


def _sendgrid(secret: str) -> str:
    return _status_probe("https://api.sendgrid.com/v3/scopes", {"Authorization": f"Bearer {secret}"})


def _slack(secret: str) -> str:
    status, body = _request("https://slack.com/api/auth.test", {"Authorization": f"Bearer {secret}"}, method="POST", data=b"")
    if status != 200:
        return "VERIFY_ERROR"
    try:
        return "LIVE_VERIFIED" if json.loads(body or b"{}").get("ok") else "PROVIDER_REJECTED"
    except ValueError:
        return "VERIFY_ERROR"


PROBES: dict[str, Callable[[str], str]] = {
    "GitHub token": _github,
    "GitLab token": _gitlab,
    "Stripe secret key": _stripe,
    "OpenAI API key": _openai,
    "SendGrid API key": _sendgrid,
    "Slack token": _slack,
}

# Types where a single value cannot be tested safely or without its pair.
UNVERIFIABLE = {"AWS access key", "AWS temporary access key", "Private key", "JWT", "Connection string",
                "Generic secret assignment", "Azure/SAS-style secret", "Google API key"}


def make_verifier(probes: dict[str, Callable[[str], str]] | None = None) -> Callable[[str, str], Optional[str]]:
    """Return a cached verifier callback suitable for ``scan_*(..., verifier=...)``."""
    table = PROBES if probes is None else probes
    cache: dict[tuple[str, str], str] = {}

    def verify(secret_type: str, secret: str) -> Optional[str]:
        key = (secret_type, secret)
        if key in cache:
            return cache[key]
        probe = table.get(secret_type)
        if probe is None:
            result = "UNVERIFIABLE" if secret_type in UNVERIFIABLE else None
        else:
            try:
                result = probe(secret)
            except Exception:  # network errors must never crash or leak the value
                result = "VERIFY_ERROR"
        cache[key] = result
        return result

    return verify
