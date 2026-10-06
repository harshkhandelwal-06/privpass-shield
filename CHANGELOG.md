# PrivPass Shield 7.3.0: server-enforced breach lock

- `app/breachwatch.py`: the browser sends the 5-char SHA-1 prefix and a slow per-user `watch` value (never the password/SHA-1/suffix). The server fetches the HIBP range itself (padded, fresh at sign-in), rejects matches (fail-closed when HIBP is unreachable) and derives the login verifier from the checked values (KDF v2), so a lying client can't sign in with a breached password.
- Account lock: `breach_locked`, all sessions revoked, `423 Locked` on every route (including sessions opened earlier), password and passkey sign-in refused, alerts raised; only a server-checked password reset unlocks. Old "must change password" flags migrate to locks.
- Breach watch: at every sign-in, on a schedule (`PRIVPASS_BREACH_WATCH_MINUTES`, default 360), *Re-check all passwords now* (admin, `/api/admin/breach-watch/run`) and *Check my password now* (user, `/api/auth/breach-recheck`, now server-run). Roster shows locked accounts and watch status.
- Storage: prefix sealed with the server key, only `HMAC(pepper, watch)` stored.
- Legacy accounts upgrade to KDF v2 at sign-in; demo accounts and the env-configured admin are provisioned as v2.
- UI: "Password breached: account locked" screen with *Reset my password* (email prefilled), shared-demo variant, Breach watch section in Security settings. Simulations now lock the account (and can't target the admin themselves).
- Tests: 115, incl. lying-client bypass attempts, background sweep of signed-out users, fail-closed, legacy upgrade, storage checks, passkey lock.

# PrivPass Shield 7.2.0: public demo, sample data, updated tour

- `PRIVPASS_PUBLIC_DEMO` (config.demo_enabled): production security with the demo workspace, demo assets and simulations kept on. Reset tokens are still never returned in production; in production the real admin must come from `PRIVPASS_ADMIN_EMAIL` / `PRIVPASS_ADMIN_PASSWORD` (no generated password on a server).
- `app/demo_seed.py` + `POST /api/admin/simulate/seed` (demo admin only) + *Load demo data* card; everything seeded is marked and removed by *Remove simulation data*. `PRIVPASS_DEMO_AUTOSEED=true` seeds an empty demo workspace at start-up.
- `render.yaml` switched to production + public demo; Dockerfile start command simplified (the app bootstraps itself; proxy headers kept for passkeys); new `.dockerignore`; `docs/DEPLOY.md` rewritten step by step.
- Guided tour: 15 steps (Exposure map, attack paths, demo sandbox); signs in as the demo admin and loads sample data when needed; role-aware.
- Tests: 106 (seed isolation/removal, public-demo security, production admin requirement). Rehearsed a production start with a fresh database end to end.

# PrivPass Shield 7.1.0: workspaces, real admin, realistic crack times, exposure map

- **Demo / live workspaces.** New `workspace` column on users and all telemetry tables; the request middleware sets the signed-in user's workspace and a SQLAlchemy `do_orm_execute` hook filters every SELECT/UPDATE/DELETE on scoped models. Existing databases are migrated in place (demo accounts' data → demo, everything else → live). Sign-in, sign-up and reset look across workspaces so emails stay unique. Anonymous breach-gate attempts are counted in live and, outside production, mirrored into demo.
- **Private real admin** (`PRIVPASS_ADMIN_EMAIL` / `PRIVPASS_ADMIN_PASSWORD`, or generated into `runtime/ADMIN-CREDENTIALS.txt`); `tools/admin_account.py`. Never shown in the Demo Center.
- **Demo restrictions:** no password change/reset, no user suspension/deletion by the demo admin, no GitHub fix PRs, no webhook forwarding, simulations only in demo. UI shows a "Demo workspace" pill, a read-only roster and an explanation in Security settings.
- **Word & name attack model** (`static/ml/structure-model.js`, `words-names.txt.gz`: 103k ranked English words, first names and surnames; see `WORDLIST-NOTICE.txt`). Guesses and crack time now use the most conservative of the neural model, the word & name model and the 1M leaked-password corpus, with targeted guesses from your name/company fields.
- **Password managers:** fills are detected via input/change/blur, the autofill animation hook and a value watcher; manager-filled new passwords also fill the confirmation.
- **Exposure map** redesign (`static/exposure.js`, `app/exposure.py`): exposure score + factors, interactive attack-surface map, attack paths with fixes, controls coverage, timeline; mobile layout.
- Dropdowns close with ✕ / Esc / toggle / outside click; bell and account menus are mutually exclusive. Removed the hero "Briefs" text.
- Tests: 103 (new `tests/test_v71_workspaces.py`).

# PrivPass Shield 7.0.0: the redesign

- New award-style interface across every page: dark/light design system, self-hosted fonts, editorial headlines, bento grid landing page, pinned k-anonymity scroll story, live "try it" hero card, marquee, count-ups, custom cursor, magnetic buttons, page transitions and a full-screen mobile menu (`static/motion.js`, purely presentational and progressive).
- Respects `prefers-reduced-motion`; animations stay static under browser automation so end-to-end tests see final states.
- Command Center: the ring under "Breach-gate rejection rate" now shows that rate (it was drawing the control-posture value).
- All existing features, IDs and flows unchanged; 97 tests and all browser end-to-end flows pass.

# PrivPass Shield 6.2.2: generator fix

- Fixed: the neural model panel, privacy preview and breach evidence now refresh when a password is produced by **Generate secure secret** (random or passphrase), not only on manual typing.
- Any new password (generated, preset, cleared or typed) resets the previous HIBP / local-corpus result, so stale breach evidence is never shown.

# PrivPass Shield 6.2.1: install fix

- Fixed a fresh-install failure: `webauthn` 3.0.1 requires `cryptography>=49`, but `cryptography` was still pinned to 46.0.4. It is now pinned to the tested 50.0.1, verified by a clean-venv install plus the full test suite.
- `START-PRIVPASS.bat` tells "Python missing" apart from "setup failed", and the launcher reports pip failures clearly instead of showing a traceback.

# PrivPass Shield 6.2.0: platform features

- **Live privacy proof**: an inspector wraps fetch/XHR/beacon before the app loads and checks every request for any typed password (plain text, NFKC, full SHA-1, SHA-1 suffix). Shown live in a drawer.
- **Offline breach corpus**: a Bloom filter of the top 1M leaked passwords (1.8 MB, 0.1% false positives) checked in the browser. The breach gate checks it first. `PRIVPASS_BREACH_FALLBACK=local` lets signups continue on the offline corpus when HIBP is down (default: fail closed).
- **Breach re-check at login**: if a password appears in a breach after it was set, the account is limited to the password-change flow until the password is changed.
- **Password change**: proves the current password with an HMAC challenge, runs the breach gate, and re-encrypts every vault item in the browser. All items or none are accepted, and other sessions are signed out.
- **Passkeys (WebAuthn)**: register, sign in without a password, list and remove. Covered by a full-ceremony test with a software authenticator and a browser virtual authenticator. The launcher now opens `localhost`.
- **Honeytokens**: fake API keys and canary URLs. A trip records IP and user agent, raises CRITICAL alerts, and returns a decoy 401. The scanner recognises your own honeytokens.
- **Fix deadlines (SLA)**: per-severity deadlines, countdown chips, transition timestamps, mean time to contain and rotate, compliance %, overdue count.
- **Notifications**: bell with unread count, and webhook forwarding (Slack, Teams, Discord).
- **GitHub**: hardened clone and scan by URL, including history. One-click fix PR built from the real file; a line that no longer matches the scan is refused.
- **Drop-in widget** `<privpass-password-field>` (form-associated custom element) and the fictional Acme demo page.
- **Guided tour** (12 steps with spotlight), "store rotated key in vault", copilot knows honeytokens and deadlines, `render.yaml` + `docs/DEPLOY.md`.
- **Admin demo simulations** (Command Center, admin only; disabled when `APP_ENV=production`): simulate a breach for any account, which locks it into a password change like a real re-check; inject login-attack traffic; **Remove all simulation data** deletes simulated sign-ins and alerts and unlocks simulated accounts. Real breach locks and real data are never touched, and the audit log keeps a record.
- Tests: 81 → 97.

# PrivPass Shield 6.1.0: AI & ML

# PrivPass Shield 6.0.0: enterprise-grade hardening

## Block the Breached Password (#20)
- Signup and reset now require a **server-issued, single-use breach-check ticket** bound to its purpose. The server re-checks the policy: live HIBP result only, fail-closed on unavailable or offline results, 15–128 characters. Every blocked attempt is recorded (aggregate only).
- **Test-account audit**: upload a CSV (or use the 40-account sample). Passwords are hashed in the browser, prefixes are fetched once each with `Add-Padding`, and only counts are stored. The Command Center headline and CSV export show "X % of N test accounts use a breached password".
- Removed the 60 synthetic seeded password events. Every metric now comes from real attempts or audits.
- NFKC normalization before SHA-1, PBKDF2 and the vault KDF (NIST SP 800-63B).
- Common-password and context-word (username / service name) blocklist at signup and reset.
- Vault "rotation reminders" are now optional "review reminders", off by default, with wording that follows NIST.
- Fixed: after a password reset the vault check marker is cleared, so the new vault can be unlocked.

## The Leaked Key Incident (#24)
- **Git history scanning** (`--history`, and automatically for uploaded ZIPs that include `.git`): each secret is reported at its introducing commit, with author, date, number of commits, and whether it is still in HEAD.
- **Risky code rules**: `shell=True`, `os.system`, `eval/exec`, TLS verify off, unsafe deserialization, string-built SQL, weak password hashing, debug mode, JWT verify off, `Math.random` tokens, `child_process.exec`.
- **False-positive controls**: vendor documentation keys (e.g. `AKIAIOSFODNN7EXAMPLE`) are downgraded to LOW; DB/Redis URLs without a real password are ignored; `.secretguardignore`; inline `secretguard:allow`; `--baseline` / `--write-baseline` for rotated fingerprints.
- **Opt-in live verification** (`--verify`, CI only) against read-only provider endpoints. `LIVE_VERIFIED` always blocks; `PROVIDER_REJECTED` is non-blocking.
- **"Rotate, don't just delete"** playbook printed on every block, in the PR comment, and in the UI for history-only findings.
- Hardened git execution: no pager, external diff, textconv, fsmonitor, hooks, signature helpers or global config.
- GitHub Actions: full-history checkout, tree and history scans, SARIF, PR comment, a real final gate step, Bandit (blocking), Semgrep (report-only), pinned to existing action majors (checkout v4, setup-python v5).
- The project's own gate passes (planted demo data is deliberately ignored; `docker-compose.yml` no longer hardcodes credentials).
- New demo asset: `PrivPass-History-Leak-Repo.zip` (clean HEAD, keys still in history). `tools/build_demo_assets.py` rebuilds all demo ZIPs.

## Platform security
- CSRF enforced on every state-changing API call (session-bound token after login, double-submit before).
- No account enumeration: decoy salts for unknown emails and one generic login error.
- Login, vault and reset challenges and breach tickets moved from process memory to hashed, single-use database tokens (multi-worker safe).
- MFA setup is now POST-only and cannot overwrite an enabled authenticator.
- Docs: `docs/THREAT-MODEL.md`, `docs/NIST-800-63B.md`, and a rewritten `docs/SECRETGUARD-CI.md`. The README has been cleaned up.
- Tests: 24 → 59.

# PrivPass Shield 5.9.0

- Fixed Windows SecretGuard demo visibility and added a one-click pre-commit block/pass demonstration.
- Pre-commit installer now supports dedicated demo repositories and target Git clones without duplicating scanner logic.

- Final UI spacing/radius correction based on supplied screenshots.
- Added cache-busting asset versions so browsers cannot reuse an older stylesheet or JavaScript bundle.
- Added hard guarantees for rounded major containers and internal content gutters across Password Shield, SecretGuard, Command Center and Demo Center.
- Removed legacy Demo Center "What to say / What not to claim" content.
- Added defensive removal of legacy `.demo-notes` at runtime.

# PrivPass Shield 5.6.0

## Security and password intelligence
- Reworked the human-password model so length cannot dominate predictable identity, dictionary, repetition, sequence or numeric structure.
- Added standalone-year detection to avoid falsely penalising random long numeric strings for containing incidental four-digit substrings.
- Added long mixed-class confidence floor for genuinely random-looking human-entered secrets.
- Added local email/account context to password analysis when the user is signed in.
- Kept exact construction entropy separate for Web Crypto generated secrets.

## Zero-knowledge password manager
- Added a client-encrypted password vault using AES-GCM-256.
- Added PBKDF2-HMAC-SHA-256 vault key derivation.
- Added separate vault unlock challenge/proof flow.
- Added vault check marker for wrong-password detection.
- Added local strength scoring for every saved login.
- Added optional HIBP check per saved password.
- Added reuse detection, rotation reminders, local search/filter, favorites, notes/tags and auto-lock.
- Added encrypted backup export.
- Server stores only opaque ciphertext for vault records; admins cannot read vault passwords.
- Forgot-password reset clears the zero-knowledge vault rather than introducing a server-side recovery key.

## Reliability
- Safe schema upgrade for existing SQLite databases adds vault columns without breaking old users.
- Added demo vault account and documentation.

## 5.6.1
- Fixed dark-theme Overview feature-card headings inheriting browser-default black text.
- Added theme-bound text colors to feature cards so both dark and light themes remain readable.
- Rounded Password Shield, SecretGuard, Command Center and Demo Center panels consistently.
- Added larger internal padding and gutters to prevent content touching card borders.
- Rounded upload, metric, finding and credential containers for a consistent visual system.
- Removed the Demo Center “What to say / What not to claim” speaker-coaching block.
- Extended the UI structural check so the removed Demo Center block cannot regress silently.

## 5.6.1 UI reliability patch
- Fixed Overview feature-card headings to use theme-aware text instead of browser-default button text.
- Rounded and padded Password Shield, SecretGuard, Command Center and Demo Center containers consistently.
- Removed the Demo Center “What to say / What not to claim” AI speaker-coaching block.
- Added structural UI regression checks for the color/radius/padding changes.

## 5.6.2 reliability hardening
- Wrapped browser localStorage access in safeStorage so privacy-restricted browser contexts cannot abort application JavaScript at startup.

## 5.8.1
- Fixed Windows SecretGuard demo script so expected blocking output remains visible instead of closing immediately.
- Fixed pre-commit installer for non-Git project folders by adding a dedicated demo repository mode.
- Installed hooks now call the single shared PrivPass scanner from the project instead of duplicating scanner code into target repositories.
- Added a one-click pre-commit block/pass demonstration.

## 5.8.1 — SecretGuard Findings UX
- Reworked the SecretGuard exposure queue into expandable, keyboard-accessible findings.
- Added compact evidence cards for confidence, entropy, validity and the CI decision gate.
- Added contextual explanation, redacted evidence, impact, and recommended response inside each finding.
- Added search, severity and status filters without duplicating detection logic.
- Kept the scanner engine unchanged and shared across web, CLI, pre-commit and CI.

## 5.9.0
- Connected Exposure Graph to persisted latest-scan and identity telemetry.
- Connected Incident Center to latest SecretGuard findings and lifecycle state.
- Added automatic UI refresh after scan and finding transitions.
- Reused existing SecretFinding/Scan records; no duplicate incident data model.
