# SecretGuard Developer Workflow

SecretGuard is one detector engine (`app/scanner.py`) with five entry points: web upload, CLI,
Git pre-commit, GitHub Actions and git-history mode. Provider patterns, risky-code rules, context,
entropy, validity checks, redaction and keyed fingerprints are identical everywhere.

## What it finds

| Category | Examples | Default gate |
|---|---|---|
| Provider secrets | AWS, GitHub, GitLab, Stripe, Slack, Google, OpenAI, SendGrid, JWT, private keys, DB URLs with passwords | HIGH/CRITICAL at ≥ 80 % confidence blocks |
| Generic secrets | `api_key = "…"` scored by entropy + context | blocks only when entropy/context push it ≥ 80 % |
| Risky code | `shell=True`, `verify=False`, string-built SQL, `pickle`/`yaml.load`, `eval`, JWT verify off, `Math.random()` tokens | HIGH blocks, MEDIUM reported |
| Git history | secrets added in *any* commit on *any* ref, even if deleted later | blocks like HEAD findings |

## Commands

```bash
# working tree (what CI checks on every push)
python tools/secret_scan.py . --fail-on high --fail-on-risky high --min-confidence 0.80

# every commit on every ref: finds keys "fixed" by deleting the line
python tools/secret_scan.py . --history

# exactly what is staged (pre-commit hook)
python tools/secret_scan.py --staged

# a ZIP; if it contains the .git folder, history is scanned too
python tools/secret_scan.py demo-assets/PrivPass-History-Leak-Repo.zip
```

Exit codes: `0` pass · `1` blocking findings · `2` scanner error.
`--json` and `--sarif` write machine-readable reports.

## Cutting false positives

1. **Offline structural validity**: provider formats, JWT header/payload decoding, and DB URLs must
   carry a real password (`redis://redis:6379` and `${DB_PASSWORD}` are ignored).
2. **Entropy + context**: generic assignments need high entropy; `test/`, `docs/`, `example`,
   `fixture` contexts lower confidence.
3. **Known vendor examples**: `AKIAIOSFODNN7EXAMPLE` and similar are reported as LOW / non-blocking.
4. **Opt-in live verification** (`--verify`, CI only): asks the provider's own read-only "who am I"
   endpoint whether the value works (GitHub, GitLab, Stripe, OpenAI, SendGrid, Slack).
   `LIVE_VERIFIED` → 99.9 % confidence, always blocks. `PROVIDER_REJECTED` → capped at 60 %, non-blocking.
   Enable it in GitHub by setting the repository variable `SECRETGUARD_VERIFY=true`.
   It is never used by the web upload or the pre-commit hook.
5. **Reviewed suppressions**:
   - `.secretguardignore`: glob per line, `dir/` for a subtree (this repo ignores its planted demo
     data and unit-test fixtures).
   - inline `# secretguard:allow` (also accepts `pragma: allowlist secret` and `gitleaks:allow`).
   - `.secretguard-baseline.json`: fingerprints of secrets that were **rotated** and recorded.

## Rotate, don't just delete

A pushed secret is compromised: deleting the line leaves it in every clone, fork, CI cache and the
git history. The CLI prints this guide whenever a secret blocks:

1. Revoke/rotate at the provider (this is what actually closes the incident).
2. Put the new value in a secret manager / CI secret and read it from the environment.
3. Check the provider's audit log for use since the introducing commit (SecretGuard reports the
   commit, author and date).
4. Optionally purge history (`git filter-repo --replace-text`, BFG) and force-push. This is hygiene, not remediation.
5. Record the rotation so the gate stops blocking:
   ```bash
   python tools/secret_scan.py . --history --write-baseline .secretguard-baseline.json \
       --baseline-note "rotated in Stripe dashboard 2026-09-26 by @riya"
   ```
   The baseline stores only HMAC fingerprints, never the secret. Set the
   `SECRETGUARD_FINGERPRINT_KEY` repository secret so fingerprints are stable and not computed
   with the public default key.

## GitHub Actions: making it a merge gate

`.github/workflows/secretguard.yml` runs on every push and pull request:

- checks out **full history** (`fetch-depth: 0`);
- scans the working tree (secrets + risky code) and the full history;
- uploads SARIF to Code Scanning, publishes JSON reports, and posts or updates a PR comment that
  lists findings with redacted previews;
- the final **Enforce security gate** step fails the job if either scan blocked;
- a **Bandit** job blocks on medium+ Python issues. A **Semgrep** job runs as a non-blocking second opinion.

A failing check only blocks a merge if the check is **required**:

1. Repository → **Settings → Rules → Rulesets** (or **Branches → Branch protection rules**).
2. Target the default branch (`main`).
3. Enable **Require status checks to pass** and add `SecretGuard gate` and `Bandit (Python SAST)`.
4. Enable **Require a pull request before merging** so nobody can push around the gate.

## Pre-commit

```bash
python tools/install_precommit.py --repo <path-to-git-clone>
```

On Windows, run `INSTALL-SECRETGUARD-HOOK.bat` then `RUN-SECRETGUARD-HOOK-DEMO.bat`: a secret
commit is blocked and a clean commit passes. The hook scans the staged index only.

## Web upload and hardened git

Uploading a ZIP that contains the `.git` folder triggers a history scan. Findings that exist only in
history are tagged **GIT HISTORY ONLY** with the introducing commit. Git runs with pager, external
diff, textconv, fsmonitor, hooks, signature helpers and system/global config disabled, so a hostile
`.git/config` cannot execute commands. A unit test enforces this. If git is not installed, the
upload still scans the working tree.
