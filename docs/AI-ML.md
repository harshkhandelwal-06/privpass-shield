# AI & ML in PrivPass Shield

PrivPass uses **trained ML models where accuracy must be measurable** and **generative AI where
explanation and action help**. Neither ever sees a password or a raw secret.

| # | Feature | Type | Where | Runs |
|---|---|---|---|---|
| 1 | Neural password-guessability model | char-GRU + Monte Carlo guess numbers | Password Shield | in the browser |
| 2 | Secret classifier | LightGBM + SHAP explanations | SecretGuard (web, CLI, CI) | server / CI |
| 3 | Login anomaly detector | Isolation Forest | AI Lab, copilot, incident report | server |
| 4 | Remediation copilot | LLM (Claude) or offline engine | SecretGuard → "AI fix", PR comments | server / CI |
| 5 | Hybrid triage | ML decides clear cases, LLM explains the grey zone | SecretGuard → "AI triage" | server |
| 6 | AI PR reviewer | LLM or offline | GitHub Actions comment | CI |
| 7 | Security copilot + incident report | LLM tool-use over read-only tools | AI Lab | server |
| 8 | Password coach | LLM on analysis flags only | Password Shield | server |

## 1. Neural password model (`ml/train_password_model.py`)

- **Data:** SecLists `Pwdb_top-10000000` (public, frequency-ranked leaked-password list). The
  top 3M unique passwords are used; 3% are held out and never trained on. 1.5M training examples
  are drawn with Zipf weights by rank to approximate real-world frequency.
- **Model:** character-level GRU (embedding 32, hidden 192, about 152k parameters) → P(next char).
- **Guess numbers:** Monte Carlo estimation (Dell'Amico & Filippone, CCS 2015) from 60,000 model
  samples, following Melicher et al., *Fast, Lean, and Accurate* (USENIX Security 2016).
- **Deployment:** int8-quantised weights plus a calibration table in `static/ml/password-model.json`
  (217 KB). Inference is in `static/ml/password-model.js` and needs no ML runtime. It matches the
  numpy reference to 0.14 bits.
- **Use:** Password Shield shows the neural estimate and crack time. The displayed score is the
  **minimum** of the rules score and the neural score, so the more conservative model wins.

| Metric (held-out) | Neural | Rules v5 | zxcvbn* |
|---|---|---|---|
| Leaked passwords rated guessable (≤ 10¹² guesses) | 87.5 % | 100 % | 99.1 % |
| Truly random 12–20 char passwords wrongly rated weak | **0 %** | 91.5 % | 0 % |
| 5-word passphrases wrongly rated weak | **0 %** | 4.8 % | 0 % |

\*zxcvbn's built-in dictionary *contains this same leaked list*, so its leaked-password number
is optimistic. The rules flag nearly everything as weak, including truly random passwords, so
they cannot tell strong passwords from weak ones. The neural model can, which is why the two are
combined.

## 2. Secret classifier (`ml/train_secret_classifier.py`)

- **Negatives (real):** 15,030 string literals from 2,593 real open-source Python/JS files.
  Provider-format values are dropped as ambiguous.
- **Hard negatives:** hashes named `checksum`/`commit`, `integrity` hashes, UUIDs, placeholders in
  secret-named variables, base64 images, identifiers, Stripe publishable keys, i18n keys, versions,
  URLs.
- **Positives:** realistic credentials (provider formats, random/hex/base64 tokens, hardcoded
  human passwords that contain digits or symbols, DB URLs with passwords) in realistic code and
  config lines, under both secret-like and neutral variable names.
- **Split:** grouped by source file (70/15/15), so no file appears in both train and test.
- **Threshold:** the lowest threshold with ≤ 0.2% false-positive rate on real code (validation files).
- **Explanations:** LightGBM's built-in SHAP contributions (`pred_contrib`), shown per finding.
- **Safety rules in the scanner:** ML re-scores generic rule hits and adds "Hardcoded secret (ML)"
  findings the rules missed. It never resurrects provider-shaped values the rules rejected
  (placeholders, password-less URLs, vendor examples).

| Test set (held-out files) | ML | Rules only |
|---|---|---|
| Recall (secrets caught) | **99.3 %** | 42.6 % |
| Precision | **98.7 %** | 98.3 % |
| False alarms on tricky look-alikes | **0.39 %** | 0.78 % |
| Flags on ordinary real code literals | 0.23 % | 0 % |

The honest trade-off: the rules only look at keyword-named assignments, so they almost never fire
on ordinary code, but they miss most secrets. The ML model finds 2.3× more secrets at the same
precision. Its remaining flags on real code are key-shaped values in library documentation examples.

## 3. Login anomaly detector (`app/ml/anomaly.py`)

- **Telemetry:** every sign-in attempt stores IP, **HMAC of the email**, success and reason. No
  email and nothing password-derived is stored.
- **Features per (IP, 5-minute window):** attempts, failures, failure ratio, distinct accounts,
  share of unknown accounts, attempts per minute, successes, distinct user agents, night-time,
  rate-limited requests.
- **Model:** Isolation Forest (250 trees, 1% contamination), fitted on a documented baseline of
  normal traffic. Each flagged window is explained (features beyond the normal 99th percentile) and
  classified as credential stuffing, brute force or enumeration.
- **Synthetic benchmark:** 100% stuffing, 97% brute force and 100% enumeration windows detected;
  1.0% false alarms. In production, refit on your own history.
- **Demo:** AI Lab → *Simulate attack traffic* injects clearly labelled simulated events;
  *Clear simulated* removes them.

## 4–8. Generative AI

All LLM features live in `app/ai/`:

- `provider.py` calls Claude when `ANTHROPIC_API_KEY` is set (model `PRIVPASS_AI_MODEL`, default
  `claude-sonnet-5`). Without a key, or on any error, the **offline engine** produces
  deterministic output from the same data, so the demo never breaks. Every response says which
  mode produced it.
- **Remediation copilot:** diff patch (Python, JS/TS, YAML, .env, plus risky-code fixes),
  provider-specific rotation runbook with a vetted console link, history-purge commands (after
  rotation), and verification steps. The UI shows *exactly* what the AI received.
- **Hybrid triage:** only grey-zone findings (ML 35–85%) go to the LLM. **Guardrail:** the AI can
  never dismiss a CRITICAL finding; it becomes `needs_human_review`.
- **Password coach:** a strict schema with `extra="forbid"`, numbers, booleans and enumerated
  labels only. There is no field that could carry a password (tested).
- **Security copilot:** Claude tool use over four read-only, role-scoped tools (overview, findings,
  anomalies, audit events). Admin and analyst only.
- **Incident report:** executive summary, scope, timeline, findings, rotation status, root cause,
  action checklist and lessons learned. Downloadable as Markdown.
- **PR reviewer:** `tools/ai_pr_review.py` builds the GitHub PR comment with a fix per blocking
  finding. Add `ANTHROPIC_API_KEY` as a repository secret to use Claude.

## Privacy guard (`app/redaction.py`)

1. At scan time each finding stores a **masked** ±3-line snippet. Provider keys become
   `<REDACTED:STRIPE_SECRET_KEY>`, and secret-like literals and high-entropy tokens become
   `<REDACTED:…>`. The raw value is never stored.
2. `assert_clean` inspects **every outbound AI payload**. Anything provider-shaped or high-entropy
   aborts the call before it leaves the process, and the feature falls back to offline mode.
3. Tests: `tests/test_v61_ai.py` (masking, guard blocks a leaking prompt with zero bytes sent, contexts never
   contain secrets, coach schema rejects smuggled passwords, PR comment contains no secrets).

## Enable Claude

```bash
# .env
ANTHROPIC_API_KEY=sk-ant-...        # from console.anthropic.com
PRIVPASS_AI_MODEL=claude-sonnet-5   # optional override
```

AI Lab shows **Claude connected** when the key is active.

## Re-train

```bash
pip install -r ml/requirements-train.txt
python ml/train_password_model.py --wordlist <SecLists>/Passwords/Common-Credentials/Pwdb_top-10000000.txt   # ~13 min on 2 CPU cores
python ml/train_secret_classifier.py --corpus <site-packages> <node_modules> --passwords <SecLists>/.../Pwdb_top-1000000.txt  # ~1 min
```
Reports are written to `ml/reports/` and shown in AI Lab.
