# PrivPass Shield

**Continuous identity and credential exposure defense.** PrivPass Shield stops breached passwords from being used and
catches leaked keys before they are merged, with one strict rule throughout: **no password and no secret value ever has
to leave the user's control.**

| Problem | What PrivPass Shield does |
|---|---|
| **Block the Breached Password** | Checks passwords against Have I Been Pwned with k-anonymity (only 5 characters of a hash leave the browser). Breached passwords are refused at sign-up, reset, change and **every sign-in**, enforced by the server. An account whose password later shows up in a breach is locked until it is reset. Includes a test-account audit (*"X % of test accounts use a breached password"*) and a NIST SP 800-63B aligned policy. |
| **The Leaked Key Incident** | **SecretGuard** scans code and the **full git history** for leaked keys and risky code, cuts false positives with entropy, validity checks and a trained ML classifier, **blocks the merge** in CI, and guides the response: **rotate, don't just delete**, with provider runbooks, fix deadlines and an incident lifecycle. |

**Prevent → Detect → Correlate → Contain → Rotate → Verify**

---

## Contents
[Features](#features) · [Privacy model](#privacy-model) · [Quick start](#quick-start) · [Accounts and admin](#accounts-and-admin) ·
[Configuration](#configuration) · [5-minute demo](#5-minute-demo) · [SecretGuard in CI](#secretguard-in-ci) ·
[Security claims and proofs](#security-claims-and-proofs) · [Tech stack](#tech-stack) · [Project structure](#project-structure) ·
[Tests](#tests) · [Deployment](#deployment) · [Limitations](#limitations) · [Documentation](#documentation)

---

## Features

### Password Shield
- **Analyses guessability, not decoration.** Pattern rules (dictionary words, names, your own name/company/email, years, keyboard walks, sequences, repeats, leetspeak) plus three attack models; the most conservative result wins.
- **Three attack models, all in the browser:**
  - a **neural network** (character-level GRU trained on public leaked-password lists) for passwords that *look like* leaked ones;
  - a **word & name model** (103k ranked words and first names/surnames from many countries, including Indian names) for realistic crack times: `harsh khandelwal` ≈ 10^11 guesses, seconds offline;
  - a **1M leaked-password Bloom filter** (1.8 MB) checked fully offline.
- **HIBP check** with a privacy receipt showing exactly what left the browser (a 5-character SHA-1 prefix, padded responses).
- **Secure generator** (Web Crypto, unbiased random secrets or passphrases), a **real-life benchmark** of five threat profiles, and an **AI coach** that only ever receives analysis flags.

### Breach gate, breach watch and account lock
- **Sign-up, reset and password change** run a browser check (length 15+, common passwords, offline corpus, HIBP) and then a **server check**: the server queries HIBP itself and refuses a match. If HIBP is unreachable the request is refused (fail-closed).
- **Can't be faked by a modified browser.** The login verifier is derived from the exact values the server checked, so a browser that lies about the check ends up with a verifier for a *different* password; the breached one can never sign in.
- **Breach watch.** Every sign-in triggers a fresh check, and a background job re-checks every account (default every 6 hours), signed in or not. Admins can run *Re-check all passwords now*; users can run *Check my password now*.
- **Lock + reset.** A breached account is locked, **every session on every device is signed out**, the user sees *"Password breached: account locked"*, and only a password reset unlocks it. Passkeys can't bypass the lock.

### Sign-in and accounts
- **Zero-knowledge sign-in:** a one-time challenge and an HMAC proof; the password is never sent. Unknown emails get decoy values (no account enumeration).
- **Passkeys** (WebAuthn: fingerprint, face or PIN), MFA (TOTP) via the API, single-use reset links.
- **Password-manager friendly:** Chrome/Google Password Manager, 1Password and Bitwarden fills are detected and the confirmation fills itself.
- Session cookies (HttpOnly, SameSite=Lax), session-bound CSRF tokens, per-IP rate limits.

### Live privacy proof
A 🛡 drawer lists every request the page sends and checks each one for any password typed on the page (plain text, normalised form, full SHA-1 and suffix). The count stays at **"Password found: 0"**.

### Zero-knowledge vault
A personal password manager for every account: titles, usernames, passwords, notes and tags are encrypted **in the browser** (AES-256-GCM, PBKDF2-SHA256 with 600k iterations). The server stores only ciphertext; admins see counts, never contents. Includes search, reuse detection, per-entry breach checks, rotation reminders, encrypted backups and auto-lock. Changing the password re-encrypts everything in the browser; a forgot-password reset clears the vault by design (there is no server recovery key).

### SecretGuard
- **One engine, four entry points:** web upload (ZIP), command line, git pre-commit hook and GitHub Actions. GitHub repositories can also be scanned by URL.
- **Detects** 15 provider credential types (AWS, GitHub/GitLab, Stripe, Slack, Google, OpenAI, Anthropic, SendGrid, private keys, JWTs, connection strings…) and 11 risky-code rules (`shell=True`, `eval`, string-built SQL, disabled TLS verification, unsafe deserialization, weak password hashing…).
- **Full git history:** keys deleted from the code but still in history are flagged **GIT HISTORY ONLY**, with the commit, author and date.
- **Few false positives:** entropy and format checks, context (tests, docs, vendor documentation examples such as the AWS example key are downgraded), an **ML classifier** (LightGBM + SHAP: 99.3 % recall vs 42.6 % for rules at the same precision), optional read-only **live verification** in CI, plus ignore files and a baseline for rotated keys.
- **Rotate, don't just delete:** every finding explains why, and **✦ AI fix** gives a patch, the provider's rotation runbook and history clean-up steps. One-click **fix pull requests** on GitHub; *Store rotated key in vault*.
- **Honeytokens:** plant fake keys or canary URLs; anyone who uses one triggers a CRITICAL alert with their IP.

### Incident Center
Every finding moves through **DETECTED → TRIAGED → CONTAINED → ROTATED → VERIFIED** with a fix deadline by severity (CRITICAL 4 h · HIGH 24 h · MEDIUM 7 d · LOW 30 d), countdowns, time-to-contain, time-to-rotate and compliance %. Transitions are validated by the server and audited.

### Exposure map
An exposure score (0–100) with the factors behind it, an interactive attack-surface map (password, sign-in factors, sessions, vault, repositories, bait keys, alerts), **ranked attack paths** with one-click fixes, controls coverage and a timeline.

### Command Center (admins)
Posture metrics, the **test-account breach audit** (accounts hashed in the browser; only counts are saved; CSV export), fix-deadline compliance, the account roster with breach-watch status, the security audit stream and demo simulations.

### AI Lab
| Model | What it does | Result |
|---|---|---|
| Secret classifier (LightGBM + SHAP) | Is this literal a real hardcoded credential, and why? | 99.3 % recall vs 42.6 % for rules |
| Neural password model (char-GRU, in the browser) | Estimates attacker guesses | 0 % of random passwords wrongly rated weak (rules: 91.5 %) |
| Login anomaly detector (Isolation Forest) | Flags credential stuffing, brute force and enumeration | 97–100 % detection, 1 % false alarms (synthetic benchmark) |

Plus AI remediation, hybrid triage (the model decides clear cases; the LLM explains the grey zone and can never dismiss a CRITICAL), a security copilot over read-only data, one-click incident reports and an AI pull-request reviewer. **Every AI call passes a redaction guard**: the AI sees masked context such as `<REDACTED:STRIPE_SECRET_KEY>`, never values or passwords. With `ANTHROPIC_API_KEY` it uses Claude; without it an offline engine answers.

### Platform
- **Alerts** (🔔) for honeytoken trips, attacks, critical findings and breach locks; HIGH/CRITICAL can be forwarded to Slack, Teams or Discord.
- **Demo and live workspaces:** demo accounts only ever see demo data; real accounts never see it. Every database query is filtered automatically.
- **Drop-in widget:** `<privpass-password-field>` adds breach protection to any sign-up form with one tag (demo at `/demo/acme`).
- **15-step guided tour**, dark and light themes, full phone layout, reduced-motion support, self-hosted fonts (works offline).

---

## Privacy model

| Data | Stays in the browser | Sent to our server | Sent to HIBP | Sent to the AI |
|---|---|---|---|---|
| Password | ✔ | never | never | never |
| Full SHA-1 of the password | ✔ | never | never | never |
| First 5 characters of the SHA-1 | | ✔ (sealed at rest) | ✔ (k-anonymity) | never |
| Login proof | derived | one-time HMAC proof | never | never |
| Vault contents | ✔ (decrypted only here) | ciphertext only | never | never |
| A leaked key found in code | | redacted preview + HMAC fingerprint | never | masked context only |

The full analysis, including what a modified browser can and cannot do, is in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Quick start

**Windows (one click)**
1. Install Python 3.10+ from python.org (tick *Add python.exe to PATH*).
2. Double-click **`START-PRIVPASS.bat`**. The first run sets everything up; later runs start in seconds.
3. Open **http://localhost:8000**. Use `localhost`, not `127.0.0.1`, so passkeys work.
4. Stop the server with `STOP-PRIVPASS.bat`.

Helper scripts in [`scripts/`](scripts): `VERIFY-PRIVPASS.bat` (tests), `DOCTOR-PRIVPASS.bat` (diagnostics), `RESET-PRIVPASS.bat` (clean start), `RUN-SECRETGUARD-DEMO.bat`, `INSTALL-SECRETGUARD-HOOK.bat` and `RUN-SECRETGUARD-HOOK-DEMO.bat`.

**Linux / macOS**
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # optional: edit settings
uvicorn app.main:app --port 8000
```

**Docker**
```bash
docker build -t privpass-shield .
docker run -p 8000:8000 -e APP_SECRET=<long random string> \
  -e PRIVPASS_ADMIN_EMAIL=you@example.com -e PRIVPASS_ADMIN_PASSWORD='<15+ character passphrase>' privpass-shield
```

---

## Accounts and admin

There is no role picker at sign-up: **every account people create is a normal user.** Admin access comes only from the server side.

| Account | How to get it | Sees |
|---|---|---|
| **Real admin** | Set `PRIVPASS_ADMIN_EMAIL` and `PRIVPASS_ADMIN_PASSWORD` (15+ characters) in `.env`, or let the first start generate one: it is printed in the console and saved to `runtime/ADMIN-CREDENTIALS.txt`. `python tools/admin_account.py --reset` creates a new password. | Real accounts only; never listed in the Demo Center |
| **Your own accounts** | *Sign in → Create account* | Their own data |
| Demo admin | `admin@privpass.local` / `PrivPass!Demo#2026-Admin` | Demo data only |
| Demo analyst | `analyst@privpass.local` / `PrivPass!Demo#2026-Analyst` | Demo data only |
| Demo user | `user@privpass.local` / `PrivPass!Demo#2026-User` | Demo data only |

Demo accounts are a shared sandbox: they can't change their password or manage users, simulations only run there, and they never send real alerts. Try password change, reset and the breach lock with an account you create yourself.

`runtime/` and `.env` are git-ignored, so the admin password and the local database never reach the repository.

---

## Configuration

Copy `.env.example` to `.env`. Everything is optional for local use.

| Setting | Default | Meaning |
|---|---|---|
| `PRIVPASS_ADMIN_EMAIL` / `PRIVPASS_ADMIN_PASSWORD` | generated | Your private real admin (required in production). |
| `APP_SECRET` | generated | Signs sessions and encrypts stored verifiers. Keep it stable. |
| `ANTHROPIC_API_KEY` | empty | Use Claude for the AI features (offline engine otherwise). |
| `GITHUB_TOKEN` | empty | Private-repository scans and one-click fix pull requests. |
| `ALERT_WEBHOOK_URL` | empty | Forward HIGH/CRITICAL alerts to Slack, Teams or Discord. |
| `PRIVPASS_BREACH_WATCH_MINUTES` | `360` | How often every account is re-checked (`0` = only at sign-in / on demand). |
| `PRIVPASS_BREACH_FALLBACK` | empty | `local` accepts the offline corpus when HIBP is down (default: refuse). |
| `APP_ENV` | `development` | `production` enables production security. |
| `PRIVPASS_PUBLIC_DEMO` / `PRIVPASS_DEMO_AUTOSEED` | `false` | Keep the demo sandbox in production / load sample data automatically. |
| `DATABASE_URL` | SQLite in `runtime/` | PostgreSQL in production. |
| `REDIS_URL` | empty | Shared rate limiting across several app instances. |
| `COOKIE_SECURE` | `false` | HTTPS-only cookies (set `true` behind HTTPS). |

---

## 5-minute demo

1. **Home:** type into the *Try it* card and watch only 5 hash characters get highlighted; open the 🛡 privacy drawer.
2. **Create account** with `password123` → blocked. A long unique passphrase → accepted after the server's breach check.
3. **Command Center** (demo admin) → *Run on sample list* → *"30 % of 40 test accounts use a breached password"*.
4. **SecretGuard** → upload `demo-assets/PrivPass-History-Leak-Repo.zip` → keys flagged **GIT HISTORY ONLY** → expand one → **✦ AI fix**.
5. **Incident Center** → move a finding DETECTED → … → VERIFIED.
6. **Exposure** → hover the red nodes → *Fix →* on an attack path.
7. **Command Center** → *Password found in a new breach* on the demo user → that user's browser shows *"Account locked"*. *Remove simulation data* undoes it.
8. **AI Lab** → *Simulate attack traffic* → ask the copilot → *Generate report*.

Or press **▶ Guided tour** on the Overview page: it signs in as the demo admin, loads sample data and walks through everything in 15 steps.

---

## SecretGuard in CI

```bash
python tools/secret_scan.py .                   # working tree: secrets + risky code
python tools/secret_scan.py . --history         # every commit on every ref
python tools/secret_scan.py --staged            # pre-commit (reads the git index)
python tools/secret_scan.py . --verify          # opt-in live provider verification (CI only)
python tools/secret_scan.py . --write-baseline  # record fingerprints of ROTATED keys
```

[`.github/workflows/secretguard.yml`](.github/workflows/secretguard.yml) checks out full history, scans the tree and the history, uploads **SARIF** to GitHub code scanning, comments on the pull request with fixes, and fails the **SecretGuard gate** check (Bandit also blocks; Semgrep reports). Mark the checks as *required* in branch protection to block merges. A blocking scan exits with code 1 and prints the rotation playbook.

False-positive controls: `.secretguardignore`, inline `# secretguard:allow`, and `.secretguard-baseline.json` for rotated fingerprints. Details: [`docs/SECRETGUARD-CI.md`](docs/SECRETGUARD-CI.md).

---

## Security claims and proofs

| Claim | Where it is proven |
|---|---|
| No password or full hash leaves the browser | Live privacy drawer; `docs/THREAT-MODEL.md` §1; `tests/test_auth.py` |
| The server refuses breached passwords even if the browser says "safe" | `tests/test_features.py::test_server_rejects_breached_password_even_if_the_browser_says_safe` |
| A lying browser can't sign in with a breached password | `tests/test_features.py::test_a_lying_browser_cannot_sign_in_with_the_breached_password` |
| Accounts are locked even when nobody is signed in | `tests/test_features.py::test_background_sweep_locks_accounts_that_are_not_signed_in`, `tests/test_breach_lock.py` |
| A stolen database alone doesn't help crack passwords | `tests/test_breach_lock.py` (storage test) |
| Fail-closed gate, CSRF, no enumeration, single-use challenges | `tests/test_auth.py` |
| Secrets deleted from HEAD are still found in history | `tests/test_secretguard_history.py::test_history_finds_secret_deleted_from_head` |
| Hostile repositories can't make git run code | `tests/test_secretguard_history.py::test_hostile_git_config_cannot_execute_commands` |
| Secrets never reach the AI | `tests/test_ai.py` (redaction guard) |
| Demo and real data never mix | `tests/test_workspaces.py` |
| NIST SP 800-63B alignment | [`docs/NIST-800-63B.md`](docs/NIST-800-63B.md) (requirement → code → test) |

---

## Tech stack

| Layer | Technologies |
|---|---|
| Front end | Vanilla JavaScript, HTML, CSS (no framework, no CDN); Web Crypto (SHA-1, PBKDF2, HMAC, AES-GCM); WebAuthn; Web Components; Canvas animations |
| Back end | Python, FastAPI, Uvicorn, Pydantic, SQLAlchemy 2, `cryptography`, `argon2-cffi`, `py_webauthn`, `httpx` |
| Data | SQLite (local), PostgreSQL (production), Redis (optional) |
| ML | Character-level GRU (trained with NumPy, int8, runs in JS), zxcvbn-style word & name model, Bloom filter, LightGBM + SHAP, scikit-learn Isolation Forest |
| AI | Anthropic Claude (optional) with an offline fallback engine |
| Security data | Have I Been Pwned range API (k-anonymity, padded) |
| DevOps | GitHub Actions, SARIF, Bandit, Semgrep, Docker, Render blueprint |
| Testing | pytest, FastAPI TestClient |

---

## Project structure

```text
app/            FastAPI server: auth, breach watch, SecretGuard engine, incidents, exposure, AI, ML
static/         Web app (HTML/CSS/JS), password models, offline breach corpus, widget, fonts
tools/          SecretGuard CLI, pre-commit installer, launcher, admin tool, model/data builders
tests/          Automated tests
docs/           Threat model, NIST mapping, AI/ML, vault, SecretGuard CI, deployment
ml/             Model training scripts and model cards
data/           Synthetic demo repositories and the sample test-account list
demo-assets/    Ready-made demo ZIPs (leaky repo, history-only leak, clean repo)
scripts/        Windows helper scripts
deploy/         Docker Compose (PostgreSQL + Redis) and an Nginx example
.github/        CI and the SecretGuard merge gate
```

All keys in `data/` and `demo-assets/` are fake and exist only to demonstrate the scanner.

---

## Tests

```bash
pip install -r requirements.txt
pytest -q                                   # automated tests (uses its own database)
python tools/ui_check.py                    # UI integrity check
python tools/secret_scan.py . --fail-on high  # the project passes its own gate
```
On Windows: `scripts\VERIFY-PRIVPASS.bat`.

---

## Deployment

[`render.yaml`](render.yaml) deploys a public demo on Render with production security (secure cookies, no reset tokens in responses) and the demo sandbox. Push to GitHub → render.com → **New → Blueprint** → set `PRIVPASS_ADMIN_EMAIL` and `PRIVPASS_ADMIN_PASSWORD` → open the URL. Step by step, plus self-hosting with PostgreSQL/Redis and scaling notes: [`docs/DEPLOY.md`](docs/DEPLOY.md).

---

## Limitations

- The 15-character minimum is enforced in the browser; the server can't measure a password it never sees (a modified browser could choose a short, **non-breached** password for its own account).
- Someone holding both the database **and** `APP_SECRET` can test guesses against the breach-watch value faster than against the login verifier; that is the cost of re-checking accounts while nobody is signed in.
- No email service is included: in development, reset links appear on screen; a public deployment needs email delivery.
- MFA (TOTP) is available through the API but has no screen yet.
- The login-attack benchmark numbers are from synthetic traffic and are labelled as such.

---

## Documentation

| Document | Covers |
|---|---|
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | What is protected, how, and the honest trade-offs |
| [`docs/NIST-800-63B.md`](docs/NIST-800-63B.md) | NIST requirement → code → test |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Components and data flow |
| [`docs/AI-ML.md`](docs/AI-ML.md) | Models, training data, evaluation, AI guardrails |
| [`docs/VAULT.md`](docs/VAULT.md) | Zero-knowledge vault design |
| [`docs/SECRETGUARD-CI.md`](docs/SECRETGUARD-CI.md) | CLI, pre-commit hook, GitHub Actions gate |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Putting it online, self-hosting and scaling |
| [`SECURITY.md`](SECURITY.md) | Security notes |

## License

[MIT](LICENSE)
