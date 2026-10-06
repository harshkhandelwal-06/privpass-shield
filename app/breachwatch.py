"""Server-enforced breach protection that still never sees the password (7.3).

The browser sends, at sign-up / reset / change / legacy upgrade:
    prefix = first 5 hex chars of SHA-1(NFKC(password))          (the same k-anonymity prefix HIBP gets)
    watch  = PBKDF2-SHA256(SHA-1 hex, watch_salt, 2 000 iterations)
Never the password, its full SHA-1, or the SHA-1 suffix.

The server then:
  1. fetches the HIBP range for `prefix` itself (k-anonymity: HIBP sees our server, never the user),
  2. recomputes `watch` for every returned hash and compares - a match means the password is breached,
  3. derives the login verifier FROM `watch`:  verifier = PBKDF2-SHA256(watch_b64 + "." + prefix, salt, 310 000).

Step 3 is what makes the check impossible to fake. A modified browser that reports the values of some
other, clean password gets a verifier for that other password - so the breached password itself can never
be used to sign in. Lying about the prefix only makes the effective secret "password + a 20-bit prefix
nobody knows", which is not the breached password either.

At rest the prefix is encrypted with the server key and only HMAC(pepper, watch) is stored, so a stolen
database alone can't be used to pre-filter password guesses. With these the server re-checks every account
on a schedule and at every sign-in (see monitor()), whether or not the person is signed in.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass

from .config import APP_SECRET, HIBP_USER_AGENT
from .security import decrypt_verifier, encrypt_verifier

WATCH_ITERATIONS = 2000
VERIFIER_ITERATIONS = 310000
RANGE_TTL = 15 * 60
_cache: dict[str, tuple[float, list[tuple[str, int]]]] = {}
_lock = threading.Lock()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _pepper() -> bytes:
    return hmac.new(APP_SECRET.encode(), b"privpass:breach-watch-pepper:v1", hashlib.sha256).digest()


def derive_watch(sha1_hex: str, watch_salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", sha1_hex.upper().encode(), watch_salt, WATCH_ITERATIONS, dklen=32)


def derive_verifier(watch: bytes, prefix: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", f"{b64e(watch)}.{prefix.upper()}".encode(), salt, VERIFIER_ITERATIONS, dklen=32)


def watch_mac(watch: bytes) -> str:
    return hmac.new(_pepper(), watch, hashlib.sha256).hexdigest()


def seal_prefix(prefix: str) -> str:
    return encrypt_verifier(prefix.upper())


def open_prefix(ciphertext: str) -> str:
    return decrypt_verifier(ciphertext).decode()


def valid_prefix(prefix: str) -> bool:
    return len(prefix) == 5 and all(c in "0123456789ABCDEF" for c in prefix.upper())


# ------------------------------------------------------------------ HIBP range (server side)
def fetch_range(prefix: str, fresh: bool = False) -> list[tuple[str, int]] | None:
    """Suffixes (with counts > 0) for a 5-char SHA-1 prefix, or None if HIBP can't be reached.
    Uses response padding so even the response size reveals nothing. Replaced in tests."""
    prefix = prefix.upper()
    now = time.time()
    with _lock:
        hit = _cache.get(prefix)
        if hit and not fresh and now - hit[0] < RANGE_TTL:
            return hit[1]
    try:
        import httpx
        base = os.getenv("HIBP_RANGE_URL", "https://api.pwnedpasswords.com/range/")
        r = httpx.get(base + prefix, headers={"Add-Padding": "true", "User-Agent": HIBP_USER_AGENT}, timeout=6.0)
        if r.status_code != 200:
            return None
        rows = []
        for line in r.text.splitlines():
            suffix, _, count = line.strip().partition(":")
            if len(suffix) == 35 and count.strip().isdigit() and int(count) > 0:
                rows.append((suffix.upper(), int(count)))
    except Exception:
        return None
    with _lock:
        _cache[prefix] = (now, rows)
    return rows


@dataclass
class Result:
    status: str          # "breached" | "safe" | "unavailable"
    count: int = 0


def check_watch(prefix: str, watch_salt: bytes, matches, fresh: bool = False) -> Result:
    """`matches(candidate_watch) -> bool` decides whether a recomputed watch value is the account's."""
    rows = fetch_range(prefix, fresh=True) if fresh else fetch_range(prefix)
    if rows is None:
        return Result("unavailable")
    for suffix, count in rows:
        if matches(derive_watch(prefix.upper() + suffix, watch_salt)):
            return Result("breached", count)
    return Result("safe")


def check_new(prefix: str, watch_salt: bytes, watch: bytes) -> Result:
    """Check a password the browser just derived (sign-up, reset, change, upgrade)."""
    return check_watch(prefix, watch_salt, lambda cand: hmac.compare_digest(cand, watch))


def check_user(user, fresh: bool = False) -> Result:
    """Re-check a stored account with only what the server keeps: sealed prefix + HMAC(pepper, watch)."""
    if not (user.watch_prefix_ct and user.watch_mac and user.watch_salt_b64):
        return Result("unavailable")
    try:
        prefix = open_prefix(user.watch_prefix_ct)
    except Exception:
        return Result("unavailable")
    stored = user.watch_mac
    return check_watch(prefix, b64d(user.watch_salt_b64), lambda cand: hmac.compare_digest(watch_mac(cand), stored), fresh=fresh)


def install(user, salt: bytes, watch_salt: bytes, prefix: str, watch: bytes) -> None:
    """Write a v2 credential: verifier bound to the checked watch value, plus the breach-watch record."""
    from .security import verifier_integrity
    vb = b64e(derive_verifier(watch, prefix, salt))
    user.verifier_ciphertext = encrypt_verifier(vb)
    user.verifier_hash = verifier_integrity(vb)
    user.salt_b64 = b64e(salt)
    user.kdf_version = 2
    user.watch_salt_b64 = b64e(watch_salt)
    user.watch_prefix_ct = seal_prefix(prefix)
    user.watch_mac = watch_mac(watch)


def material_from_password(password: str) -> tuple[bytes, bytes, str, bytes]:
    """Server-side helper for accounts whose password the server is given (demo accounts, env-configured admin)."""
    import unicodedata
    h = hashlib.sha1(unicodedata.normalize("NFKC", password).encode()).hexdigest().upper()  # nosec B324 secretguard:allow - HIBP k-anonymity format, never stored
    salt, watch_salt = os.urandom(16), os.urandom(16)
    return salt, watch_salt, h[:5], derive_watch(h, watch_salt)
