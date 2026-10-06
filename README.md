# PrivPass Shield 7.3.0

**Continuous identity and credential exposure defense.** One product for two problems:

| Brief | What PrivPass Shield does |
|---|---|
| **#20 Block the Breached Password** | Browser-only strength analysis, HIBP k-anonymity breach check, a **reject-on-breach gate at signup *and* reset** with a server-issued ticket, a test-account audit report ("X % of test accounts use a breached password"), and a NIST SP 800-63B rev. 4 aligned policy. |
| **#24 The Leaked Key Incident** | SecretGuard: one scanner for web upload, CLI, pre-commit and GitHub Actions. Detects provider secrets **and risky code**, **scans full git history**, cuts false positives with entropy, validity checks, vendor-example detection and opt-in **live provider verification**, **blocks the merge**, and teaches **rotate, don't just delete**. |

The flow: **Prevent → Detect → Correlate → Contain → Rotate → Verify**

## What's new in 7.3: breached passwords can't get in, even with a hacked browser

| Change | What it means |
|---|---|
| **Server-verified breach check** | At sign-up, reset, password change and **every sign-in**, the server itself checks HIBP (k-anonymity, 5-character prefix). It no longer takes the browser's word for it. |
| **Can't be faked** | The login secret is derived from the exact values the server checked, so a modified browser that lies ends up with a different secret: the breached password can never sign in. Covered by tests. |
| **Lock + reset** | If an account's password appears in a breach, the account is locked, **every session on every device is signed out**, a "Password breached: account locked" screen appears, and only a password reset unlocks it. Passkeys can't bypass the lock. |
| **In session or not** | A background breach watch re-checks every account (default every 6 h, `PRIVPASS_BREACH_WATCH_MINUTES`), plus *Re-check all passwords now* for admins and *Check my password now* for users. |
| **Still zero-knowledge** | The password, its full SHA-1 and the SHA-1 suffix never leave the browser. What the server stores is sealed with the server key. Details and trade-offs: `docs/THREAT-MODEL.md` §2. |

Existing accounts upgrade automatically at their next sign-in (and are checked then).

## What's new in 7.2: ready for a public link

| Change | What it means |
|---|---|
| **Public demo deployment** | `render.yaml` deploys with production security plus the demo sandbox (`PRIVPASS_PUBLIC_DEMO=true`). Step-by-step guide: `docs/DEPLOY.md`. |
| **Load demo data** | Command Center → *Load demo data* fills the demo workspace with a full story (2 repos incl. a history-only key, findings at every stage with one overdue, a tripped honeytoken, breach-gate stats, the test-account audit, login attacks). *Remove simulation data* deletes all of it. Public deployments load it automatically. |
| **15-step guided tour** | Now covers the Exposure map, attack paths and the demo sandbox. If nobody is signed in it signs in as the demo admin and loads the sample data first. |
| **Safer builds** | `.dockerignore` keeps `.env` and `runtime/` out of Docker images; tests use their own database file. |

## What's new in 7.1

| Change | What it means |
|---|---|
| **Demo and real workspaces** | The three demo accounts share a *demo workspace* and only ever see demo data. Accounts people create, and your private real admin, live in the *live workspace*. Every database query is filtered by workspace automatically, so nothing crosses over. |
| **Private real admin** | Set `PRIVPASS_ADMIN_EMAIL` / `PRIVPASS_ADMIN_PASSWORD` in `.env`, or let the first start generate one into `runtime/ADMIN-CREDENTIALS.txt` (printed by the launcher; `python tools/admin_account.py --reset` makes a new one). It is never listed in the Demo Center. |
| **Demo restrictions** | Demo accounts can't change or reset their password, the demo admin can't suspend or delete accounts, fix PRs (real GitHub token) are off, demo alerts never reach your real Slack/Teams webhook, and simulations only run in the demo workspace. |
| **Word & name attack model** | Crack-time estimates now include how attackers really guess: ranked word lists, first names and surnames from many countries (including Indian names), years, leetspeak and your own name/company. "harsh khandelwal" is now ~10^11 guesses (seconds offline), not "a million years". |
| **Password managers** | Chrome / Google Password Manager suggested passwords (and 1Password, Bitwarden…) are detected however they fill the field; the confirmation fills itself. |
| **Exposure map** | A redesigned Exposure page: exposure score gauge with the factors behind it, an interactive attack-surface map, ranked attack paths with one-click fixes, controls coverage and a timeline. |
| **Closable dropdowns** | Account and alert menus close with ✕, Esc, a second click or a click outside. |

## What's new in 7.0: the redesign

A complete visual redesign, built by hand in plain HTML/CSS/JS (no framework, no CDN, works offline):

- **Landing page**: preloader, a giant split-text hero over an interactive hex field, a live **"try it"** card that hashes your typing into SHA-1 and highlights the 5 characters that would go to HIBP (nothing is sent), a marquee, a bento grid of modules, a pinned **scroll story** that animates k-anonymity step by step, count-up numbers and a finale.
- **Motion**: custom cursor, magnetic buttons, card spotlights, scroll reveals, a sliding nav indicator, page transitions, a scroll-progress bar, and a full-screen menu on phones.
- **Design system**: dark and light themes, self-hosted fonts (Inter Tight, Instrument Serif, JetBrains Mono), one accent colour, and consistent cards, tables and chips across every page.
- **Accessible**: honours *reduced motion*, stays keyboard-usable, and every page works at phone width.

## What's new in 6.2

| Feature | What it does |
|---|---|
| **Live privacy proof** | 🛡 button (bottom-left): every request the page sends, checked live for your password or its SHA-1 |
| **Offline breach corpus** | 1M leaked passwords in a 1.8 MB Bloom filter, checked in the browser; not even the 5-char prefix leaves |
| **Breach re-check at every login** | A password that leaks *after* signup locks the account into a password change |
| **Password change with vault re-encryption** | The vault is decrypted and re-encrypted in the browser; the server never sees either password |
| **Passkeys** | Sign in with fingerprint, face or PIN (WebAuthn); phishing-resistant |
| **Honeytokens** | Bait keys and URLs: anyone who uses one triggers a CRITICAL alert with their IP |
| **Fix deadlines** | CRITICAL 4 h · HIGH 24 h · MEDIUM 7 d countdowns, time-to-contain/rotate, compliance % |
| **Alerts** | 🔔 in-app notifications, forwarded to Slack/Teams/Discord via `ALERT_WEBHOOK_URL` |
| **GitHub** | Scan any repo by URL (full history); **one-click fix pull request** (`GITHUB_TOKEN`) |
| **Drop-in widget** | `<privpass-password-field>`: add breach protection to any signup form with one tag (`/demo/acme`) |
| **Demo simulations** | Admin-only panel in Command Center: simulate a breach or a login attack, then **remove all simulation data** in one click |
| **Guided tour** | ▶ Guided tour on the Overview page walks judges through everything in 15 steps (signs in as the demo admin and loads sample data if needed) |
| **Deploy** | `render.yaml` + `docs/DEPLOY.md` for a public HTTPS link (public demo mode) |

## AI & ML (6.1)

| Model / feature | What it does | Result |
|---|---|---|
| **Neural password model** (char-GRU, in-browser) | Estimates attacker guesses; never sends the password | 0 % of random passwords wrongly rated weak (rules: 91.5 %) |
| **ML secret classifier** (LightGBM + SHAP) | Decides if a literal is a hardcoded credential and explains why | 99.3 % recall vs 42.6 % for rules, same precision |
| **Login anomaly detector** (Isolation Forest) | Flags credential stuffing, brute force and enumeration | 97–100 % detection, 1 % false alarms (synthetic benchmark) |
| **AI remediation copilot** | Patch, provider rotation runbook and history clean-up per finding | Claude, or offline engine |
| **Hybrid triage** | ML decides clear cases; LLM explains the grey zone; never dismisses CRITICAL | |
| **AI PR reviewer** | GitHub PR comment with a fix for each blocking finding | |
| **Security copilot + incident report** | Tool-using assistant over read-only data; one-click postmortem | |
| **Password coach** | Advice from analysis *flags* only | |

Every AI call passes a redaction guard; the AI sees masked snippets like `<REDACTED:STRIPE_SECRET_KEY>`, never values.
Set `ANTHROPIC_API_KEY` in `.env` to use Claude; without it everything runs in offline mode. Details: `docs/AI-ML.md`.

## Quick start (Windows)

1. Double-click `START-PRIVPASS.bat` and open `http://localhost:8000` (use `localhost`, not `127.0.0.1`, so passkeys work).
2. Your **private real admin** login is printed by the launcher and saved in `runtime/ADMIN-CREDENTIALS.txt` (or set your own in `.env`).
3. Demo credentials are in **Demo Center** (development only; they are a sandbox that only sees demo data):
   - admin `admin@privpass.local` / `PrivPass!Demo#2026-Admin`
   - analyst `analyst@privpass.local` / `PrivPass!Demo#2026-Analyst`
   - vault user `user@privpass.local` / `PrivPass!Demo#2026-User`

Other scripts: `DOCTOR-PRIVPASS.bat`, `VERIFY-PRIVPASS.bat` (tests), `RESET-PRIVPASS.bat`, `STOP-PRIVPASS.bat`.
Linux/macOS: `pip install -r requirements.txt && uvicorn app.main:app --port 8000`.

## Judge demo (about 5 minutes)

1. **Password Shield**: run the benchmark, then **Check with HIBP**. Only a 5-character SHA-1 prefix leaves the browser.
2. **Create account** with `password123`: it is blocked. Try a 12-character random password: blocked (below 15). Then a long unique passphrase: accepted after a *live* breach check.
3. Sign in as admin, open **Command Center**, and click **Run on sample list**. 40 synthetic test accounts are hashed in the browser; the headline reads *"30 % of 40 test accounts use a breached password"*. Only counts go to the server.
4. **SecretGuard**: upload `demo-assets/PrivPass-Demo-Leak-Repo.zip`. You'll see provider keys, risky code (`shell=True`, `verify=False`, string-built SQL), and the AWS *documentation* key downgraded to LOW.
5. Upload `demo-assets/PrivPass-History-Leak-Repo.zip`. HEAD is clean, but two keys are flagged **GIT HISTORY ONLY**, with the commit and author that introduced them.
6. **Incident Center**: move a finding DETECTED → TRIAGED → CONTAINED → ROTATED → VERIFIED.
7. Expand a finding → **✦ AI fix**: a patch, the Stripe rotation runbook and the exact masked input the AI saw.
8. **AI Lab**: model cards → **Simulate attack traffic** → ask the copilot *"Any login attacks in the last 24 hours?"* → **Generate report**.
9. **Overview → ▶ Guided tour** for the full story in 15 steps. Open the **🛡 privacy proof** drawer while testing passwords.
10. SecretGuard → **Honeytokens** → create one → *Simulate attacker* → watch the 🔔 CRITICAL alert.
11. Account menu → **Security settings** → *Add a passkey* → sign out → **Sign in with a passkey**. (Password change needs your own account: demo accounts are shared, so their password is locked.)
12. Open `/demo/acme` to show the drop-in widget protecting a (fictional) company's signup form.
13. CLI: `RUN-SECRETGUARD-DEMO.bat`, or `python tools/secret_scan.py demo-assets/PrivPass-History-Leak-Repo.zip`, prints the rotation playbook and exits 1 (blocked).

## Security claims and where they are proven

| Claim | Proof |
|---|---|
| No plaintext password or full hash leaves the browser | `docs/THREAT-MODEL.md` §1, `static/app.js` (`lookupHibp`, `deriveVerifier`) |
| Reject-on-breach at signup and reset, fail-closed | `tests/test_v60_auth.py` (tickets, breached/unavailable/offline/short all rejected) |
| NIST SP 800-63B alignment | `docs/NIST-800-63B.md` (requirement → code → test) |
| CSRF, no account enumeration, single-use DB-backed challenges | `tests/test_v60_auth.py` |
| Secrets in git history are found | `tests/test_v60_secretguard.py::test_history_finds_secret_deleted_from_head` |
| Hostile repositories cannot make git execute code | `test_hostile_git_config_cannot_execute_commands` |
| Project's own CI gate is green | `test_repository_self_scan_passes` |

What the breach gate can and cannot prove against a *modified* client is explained honestly in `docs/THREAT-MODEL.md` §2.

## SecretGuard in CI

```bash
python tools/secret_scan.py .            # working tree: secrets + risky code
python tools/secret_scan.py . --history  # every commit on every ref
python tools/secret_scan.py --staged     # pre-commit
python tools/secret_scan.py . --verify   # opt-in live provider verification (CI only)
```

`.github/workflows/secretguard.yml` checks out full history, scans the tree and the history, uploads SARIF, comments on the PR, and fails the **SecretGuard gate** check. Bandit blocks; Semgrep reports. To make a failure block the merge, mark the checks as *required* in a branch ruleset. See `docs/SECRETGUARD-CI.md`.

False-positive controls: `.secretguardignore`, inline `# secretguard:allow`, and `.secretguard-baseline.json` for **rotated** fingerprints (`--write-baseline`).

## Zero-knowledge vault

Each signed-in user gets a private vault encrypted in the browser (AES-GCM-256, PBKDF2-SHA-256 with 600k iterations). The server stores only ciphertext. Admins see counts, never contents. A forgot-password reset clears the vault by design, because no server recovery key exists.

## Architecture and scaling

FastAPI + SQLAlchemy (SQLite locally, PostgreSQL in production), optional Redis rate limiting, and vanilla JS. Challenges and tickets live in the database, so multiple workers work. See `docs/ARCHITECTURE.md` and `deploy/SCALING.md`.

## Tests

```bash
pip install -r requirements.txt && pytest -q && python tools/ui_check.py
```
