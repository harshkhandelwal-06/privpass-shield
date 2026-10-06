# Threat model: what PrivPass Shield proves, and what it does not

This page states the security claims precisely so reviewers can check each one against code and tests.

## 1. "No plaintext password ever leaves the client"

| Data | Leaves the browser? | Where |
|---|---|---|
| Password | **Never** | analysed, normalised (NFKC) and hashed in `static/app.js` |
| Full SHA-1 of password | **Never** | computed locally, suffix compared locally |
| First 5 hex chars of SHA-1 | Only to `api.pwnedpasswords.com` (with `Add-Padding: true`) | `lookupHibp()` |
| 5-char prefix to *our* server | **Never** (see note) | not part of any request body |
| PBKDF2-SHA256 verifier (310k iter, random salt) | To our server at signup/reset | stored AES-GCM-encrypted + Argon2id integrity hash |
| Login proof | HMAC(verifier, single-use nonce) | nonce is DB-backed and consumed once |

**Why the server never gets the HIBP prefix:** the prefix is 20 bits of an *unsalted* hash. A
database thief who had both the prefix and the verifier could discard about 99.9999 % of guesses
with cheap SHA-1 before paying for PBKDF2. Keeping the prefix out of the server keeps the verifier's
full work factor.

## 2. Reject-on-breach: enforced by the server, without the server seeing the password

**Goal:** no one can sign in with a breached password, and an account whose password appears in a breach is
locked (every session ends) until the password is reset, whether or not the person is signed in.

**What the browser sends** for a new password (sign-up, reset, change, legacy upgrade), in `static/app.js newCredential`:

| Value | What it is | Leaves the browser? |
|---|---|---|
| password | | **never** |
| SHA-1(password) / SHA-1 suffix | | **never** |
| `prefix` | first 5 hex characters of SHA-1: the same thing HIBP's k-anonymity API receives | yes |
| `watch` | PBKDF2-SHA256(SHA-1 hex, per-user salt, 2 000 iterations) | yes |

**What the server does** (`app/breachwatch.py`):

1. Fetches the HIBP range for `prefix` **itself** (with response padding). HIBP sees the server, never the user.
2. Recomputes `watch` for every hash in the range. A match means the password is breached, so it is rejected.
   If HIBP can't be reached, the password is refused (**fail-closed**) unless `PRIVPASS_BREACH_FALLBACK=local`.
3. Derives the login verifier **from the checked values**: `verifier = PBKDF2(watch ‖ "." ‖ prefix, salt, 310 000)`.

**Why a modified browser can't get around it (step 3):**

- Report the values of a *different, clean* password, and the account's login secret belongs to that clean
  password. The breached password, entered in any normal client, produces a different proof and is refused.
- Report the correct `watch` with a *wrong prefix*, and the verifier includes the wrong prefix. The effective
  secret becomes "password + 20 unknown bits", which a normal client can't produce and a credential-stuffing
  attacker can't guess. The breached password still can't sign in.
- Report nothing and just log in: the server re-checks the **stored** value itself at sign-in (uncached), so
  nothing is taken from the browser.

`tests/test_features.py::test_a_lying_browser_cannot_sign_in_with_the_breached_password` covers both lies.

**Continuous protection** (`breach_watch_sweep`):

- **At every sign-in:** a fresh HIBP check before a session is issued.
- **On a schedule:** `PRIVPASS_BREACH_WATCH_MINUTES`, default 6 h, re-checks *every* account, signed in or not.
- **On demand:** the admin button *Re-check all passwords now*, and the user's *Check my password now*.
- **On a match**, the account is locked:
  - all sessions are revoked, and every request (including from sessions opened earlier) gets `423 Locked`;
  - password and passkey sign-in are refused;
  - an alert is raised;
  - only a password reset unlocks it, and the new password is checked by the server too.

**What the server stores, and what a database thief gets:**

| Stored | Protection |
|---|---|
| sealed prefix | AES-GCM with the server key: the prefix alone would let a thief pre-filter guesses |
| `HMAC(pepper, watch)` | pepper derived from `APP_SECRET`, not stored in the database |
| verifier | encrypted at rest + Argon2 integrity hash (unchanged) |

Without `APP_SECRET` the stolen rows can't be used to test password guesses. **Trade-off**, stated plainly:
someone holding both the database *and* `APP_SECRET` can test guesses against the watch value at 2 000 PBKDF2
iterations per guess instead of 310 000. That's the cost of letting the server re-check accounts while nobody
is signed in. Keep `APP_SECRET` out of the database and backups.

**Other honest limits:**

- The 15-character minimum is checked in the browser. The server can't measure a password it never sees; a
  modified client could set a short, *non-breached* password for its own account.
- The zero-knowledge vault is encrypted with the old password, so a forgot-password reset clears it. That's why
  a breach lock requires a reset instead of letting the (possibly stolen) old password change itself.
- In production, reset links need an email service (not included in this build); development mode shows the
  link on screen.
- Accounts created before the server-side check existed are upgraded and checked at their next sign-in. Until then the scheduled watch
  can't check them, and `/challenge` reveals that such an account is on the old scheme.

## 3. SecretGuard

- Uploaded code is never executed. Git is run with every command-executing hook disabled; see
  `test_hostile_git_config_cannot_execute_commands`.
- Raw secrets are held in memory only during a scan. The database, JSON, SARIF, PR comments and
  baselines contain only redacted previews and HMAC fingerprints.
- `--verify` sends a detected credential **to its own provider only**, is opt-in, CI-only, and never
  runs for web uploads or the pre-commit hook.

## 4. Session and request integrity

- Session cookie: `HttpOnly`, `SameSite=Lax`, `Secure` when `COOKIE_SECURE=true`.
- CSRF: every POST/PUT/PATCH/DELETE under `/api/` must echo `X-CSRF-Token`, bound to the
  server-side session after login (double-submit cookie before login). Origin checks remain as
  defence in depth.
- Account enumeration: `/api/auth/challenge` returns a stable decoy salt for unknown emails, and
  login returns one generic error.
- Login, vault and reset challenges and breach tickets are stored hashed in the database
  (`ephemeral_tokens`), are single-use, and work across multiple workers.

## 5. Known gaps (tracked)

- The verifier is password-equivalent for anyone holding **both** the database and `APP_SECRET`.
  OPAQUE/WebAuthn would remove this.
- Login PBKDF2 uses 310,000 iterations (the vault uses 600,000). A per-user iteration column would
  allow raising it without breaking existing accounts.
- The in-memory rate limiter is per-process unless `REDIS_URL` is set.
