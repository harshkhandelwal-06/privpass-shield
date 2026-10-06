"""Redaction layer: the only way code or findings reach an AI model.

`mask_text` replaces every provider-format credential, every quoted secret-like literal and every
long random-looking token with a typed placeholder such as <REDACTED:STRIPE_SECRET_KEY>.
`assert_clean` is a last-line check run on every outbound AI payload: it refuses to send anything
that still looks like a credential.
"""
from __future__ import annotations

import re

from .scanner import PATTERNS, entropy

_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=.]{20,}")
_QUOTED = re.compile(r"""(['"`])([^'"`\s]{8,})\1""")
_WORDY = re.compile(r"^[A-Za-z_.\-/]+$")


def _slug(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")


def mask_text(text: str) -> str:
    out = text
    for name, rx, _sev in PATTERNS:
        def repl(m, _name=name):
            if m.lastindex:  # generic assignment: keep the variable, mask the value only
                return m.group(0).replace(m.group(1), f"<REDACTED:{_slug(_name)}>")
            return f"<REDACTED:{_slug(_name)}>"
        out = rx.sub(repl, out)

    def quoted(m):
        v = m.group(2)
        if v.startswith("<REDACTED") or _WORDY.match(v) or entropy(v) < 3.0:
            return m.group(0)
        return f"{m.group(1)}<REDACTED:LITERAL>{m.group(1)}"
    out = _QUOTED.sub(quoted, out)

    def token(m):
        v = m.group(0)
        if v.startswith("<REDACTED") or _WORDY.match(v) or entropy(v) < 3.5:
            return v
        return "<REDACTED:TOKEN>"
    return _TOKEN.sub(token, out)


def masked_context(lines: list[str], lineno: int, radius: int = 3) -> str:
    """Numbered, masked snippet around a 1-based line number."""
    start, end = max(1, lineno - radius), min(len(lines), lineno + radius)
    return "\n".join(f"{n:>4}{'>' if n == lineno else ' '} {mask_text(lines[n - 1])[:220]}" for n in range(start, end + 1))


class LeakBlocked(ValueError):
    """Raised when an outbound AI payload still contains credential-like material."""


def assert_clean(payload: str, known_secrets: tuple[str, ...] = ()) -> str:
    for secret in known_secrets:
        if secret and secret in payload:
            raise LeakBlocked("refusing to send a known secret value to the AI provider")
    for name, rx, _sev in PATTERNS:
        if name == "Generic secret assignment":
            continue
        if rx.search(payload):
            raise LeakBlocked(f"refusing to send {name}-shaped material to the AI provider")
    for m in _TOKEN.finditer(payload):
        v = m.group(0)
        if not v.startswith("<REDACTED") and not _WORDY.match(v) and entropy(v) >= 4.2 and len(v) >= 24:
            raise LeakBlocked("refusing to send a high-entropy token to the AI provider")
    return payload
