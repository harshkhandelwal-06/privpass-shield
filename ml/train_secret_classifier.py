"""Train the SecretGuard ML classifier (LightGBM) and compare it with the rule-based baseline.

Data
----
* Negatives (real): string literals assigned in real open-source code (installed Python packages and
  npm packages). Anything matching a provider key format is dropped as ambiguous.
* Hard negatives (synthetic): hashes named checksum/commit/integrity, UUIDs, placeholders in secret-named
  variables, base64 images, identifiers, publishable/public keys, i18n keys.
* Positives (synthetic): realistic credentials (provider formats, random tokens, hex/base64 secrets,
  human passwords from a public leaked-password list, DB URLs with passwords) placed in realistic
  code/config lines under secret-like and neutral variable names.

Splits are grouped by source file so no file contributes to both train and test.

Outputs
-------
app/ml/secret-classifier.txt           LightGBM text model (no pickle)
app/ml/secret-classifier.meta.json     feature list, threshold, metrics
ml/reports/secret-classifier-card.json full model card
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import re
import string
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ml.secret_features import FEATURES, Candidate, extract_candidates, features  # noqa: E402
from app.scanner import PATTERNS, scan_text  # noqa: E402

SEED = 7
rng = random.Random(SEED)
ALNUM = string.ascii_letters + string.digits
TEXT_EXT = {".py", ".js", ".ts", ".json", ".yml", ".yaml", ".cfg", ".ini", ".toml"}


def provider_match(value: str) -> bool:
    return any(rx.search(value) for name, rx, _ in PATTERNS if name != "Generic secret assignment")


# ------------------------------------------------------------------ real negatives
def harvest(roots: list[Path], max_files: int, per_file: int) -> list[tuple[Candidate, str]]:
    files = [p for r in roots if r.is_dir() for p in r.rglob("*") if p.suffix in TEXT_EXT and p.is_file()]
    rng.shuffle(files)
    out, seen = [], set()
    for f in files[:max_files]:
        try:
            if f.stat().st_size > 400_000:
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = "/".join(f.parts[-4:])
        got = 0
        for line in text.splitlines():
            if len(line) > 400:
                continue
            for c in extract_candidates(line, rel):
                if c.value in seen or provider_match(c.value):
                    continue
                seen.add(c.value)
                out.append((c, rel)); got += 1
            if got >= per_file:
                break
    return out


# ------------------------------------------------------------------ synthetic generators
def rnd(chars: str, n: int) -> str:
    return "".join(rng.choice(chars) for _ in range(n))


def secret_value(passwords: list[str]) -> tuple[str, bool]:
    kind = rng.random()
    if kind < 0.20:
        return rnd(ALNUM, rng.randint(16, 64)), False
    if kind < 0.32:
        return rnd("0123456789abcdef", rng.choice([32, 40, 48, 64])), False
    if kind < 0.42:
        raw = base64.b64encode(bytes(rng.getrandbits(8) for _ in range(rng.randint(18, 64)))).decode()
        return raw.rstrip("=") if rng.random() < .5 else raw, False
    if kind < 0.62:
        fmt = rng.choice([
            lambda: "AKIA" + rnd(string.ascii_uppercase + string.digits, 16),
            lambda: "ghp_" + rnd(ALNUM, 36), lambda: "github_pat_" + rnd(ALNUM + "_", 60),
            lambda: rng.choice(["sk_live_", "rk_live_"]) + rnd(ALNUM, 24),
            lambda: "xoxb-" + rnd(string.digits, 12) + "-" + rnd(string.digits, 12) + "-" + rnd(ALNUM, 24),
            lambda: "AIza" + rnd(ALNUM + "_-", 35), lambda: "sk-proj-" + rnd(ALNUM + "_-", 48),
            lambda: "SG." + rnd(ALNUM, 22) + "." + rnd(ALNUM, 43), lambda: "glpat-" + rnd(ALNUM, 20),
            lambda: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + rnd(ALNUM, 40) + "." + rnd(ALNUM + "_-", 43),
        ])
        return fmt(), True
    if kind < 0.85:
        pw = rng.choice(passwords)
        return (pw if len(pw) >= 8 else pw + rnd(string.digits, 8 - len(pw))), False
    user = rng.choice(["app", "admin", "svc", "payments", "root"])
    return f"postgres://{user}:{rnd(ALNUM, rng.randint(10, 24))}@db.internal:5432/{user}", False


SECRET_NAMES = ["api_key", "API_KEY", "secret", "client_secret", "CLIENT_SECRET", "auth_token", "access_token", "DB_PASSWORD",
                "password", "db_pass", "pwd", "private_key", "SECRET_KEY", "STRIPE_KEY", "token", "webhook_secret", "JWT_SECRET",
                "sendgrid_api_key", "SLACK_TOKEN", "aws_secret_access_key", "apiKey", "authToken", "clientSecret", "dbPassword",
                "SMTP_PASSWORD", "REDIS_PASSWORD", "OPENAI_API_KEY", "GITHUB_TOKEN", "bearer", "session_secret", "DATABASE_URL"]
NEUTRAL_NAMES = ["value", "data", "x", "default", "prod", "k", "v", "s", "param", "config_value", "result", "cfg", "item", "arg", "fallback"]
PASSWORDISH = {"password", "db_pass", "pwd", "DB_PASSWORD", "dbPassword", "SMTP_PASSWORD", "REDIS_PASSWORD"}


def render(name: str, value: str, path: str) -> str:
    ext = Path(path).suffix
    if Path(path).name.startswith(".env"):
        return f"{name.upper()}={value}"
    if ext in {".js", ".ts"}:
        return rng.choice([f'const {name} = "{value}";', f"  {name}: '{value}',", f"export const {name} = `{value}`;", f'config.{name} = "{value}";'])
    if ext in {".yml", ".yaml"}:
        return f'  {name}: "{value}"'
    if ext == ".json":
        return f'  "{name}": "{value}",'
    return rng.choice([f'{name} = "{value}"', f"    {name}='{value}',", f'settings["{name}"] = "{value}"',
                       f'client = Client({name}="{value}")', f'{name} = os.getenv("{name.upper()}", "{value}")'])


def synthetic_positives(n: int, paths: list[str], passwords: list[str]) -> list[tuple[Candidate, str]]:
    out = []
    for _ in range(n):
        value, prov = secret_value(passwords)
        if value.startswith("postgres://"):
            name = rng.choice(["DATABASE_URL", "db_url", "dsn", "SQLALCHEMY_DATABASE_URI"])
        elif not prov and rng.random() < 0.18:
            name = rng.choice(NEUTRAL_NAMES)
        else:
            name = rng.choice(SECRET_NAMES)
        if not prov and value in passwords and name not in PASSWORDISH:
            name = rng.choice(sorted(PASSWORDISH))
        path = rng.choice(paths) if rng.random() < .85 else rng.choice(["tests/test_client.py", "examples/demo.js", "docs/setup.md"])
        path = rng.choice([path, ".env", "config/settings.py", "src/config.js", "deploy/values.yaml", "config/app.json"]) if rng.random() < .35 else path
        line = render(name, value, path)
        cands = extract_candidates(line, path)
        if cands:
            c = cands[0]
            out.append((Candidate(c.value, c.name, c.line, c.path, provider_match(c.value)), "synthetic_pos"))
    return out


def synthetic_hard_negatives(n: int, paths: list[str]) -> list[tuple[Candidate, str]]:
    gens = [
        (lambda: rnd("0123456789abcdef", rng.choice([32, 40, 64])), ["sha", "checksum", "commit", "digest", "etag", "sha256", "file_hash", "revision", "md5", "fingerprint"]),
        (lambda: "sha512-" + base64.b64encode(bytes(rng.getrandbits(8) for _ in range(64))).decode(), ["integrity"]),
        (lambda: "-".join(rnd("0123456789abcdef", k) for k in (8, 4, 4, 4, 12)), ["id", "uuid", "request_id", "guid", "tenant_id", "trace_id"]),
        (lambda: rng.choice(["your-api-key-here", "<YOUR_API_KEY>", "xxxxxxxxxxxxxxxxxxxx", "changeme-please", "${API_KEY}", "REPLACE_WITH_TOKEN",
                             "dummy-secret-for-tests", "not-a-real-secret", "your_token_here", "INSERT_KEY_HERE", "sample-password-123",
                             "****************", "<password>", "{{API_TOKEN}}", "example-client-secret", "test-secret-key-value", "placeholder_token"]),
         SECRET_NAMES),
        (lambda: "iVBORw0KGgoAAAANSUhEUgAA" + base64.b64encode(bytes(rng.getrandbits(8) for _ in range(rng.randint(30, 120)))).decode(), ["logo", "icon", "image", "favicon", "thumbnail"]),
        (lambda: rng.choice(["password_confirmation", "user_password_hash", "reset_password_token", "api_key_header_name", "X-Api-Key",
                             "Authorization", "access_token_expires_in", "secret_manager_arn_prefix", "token_endpoint_url", "PasswordPolicy"]),
         ["password_field", "PASSWORD_FIELD", "token_name", "header", "api_key_param", "SECRET_NAME", "key_name", "auth_header"]),
        (lambda: rng.choice(["pk_live_", "pk_test_"]) + rnd(ALNUM, 24), ["STRIPE_PUBLISHABLE_KEY", "publishable_key", "stripePublicKey"]),
        (lambda: ".".join(rng.choice(["auth", "token", "password", "errors", "login", "form", "secret", "reset"]) for _ in range(3)) + "_" + rng.choice(["label", "message", "title"]),
         ["i18n_key", "message_id", "label", "text_key"]),
        (lambda: f"{rng.randint(1,9)}.{rng.randint(0,40)}.{rng.randint(0,99)}-" + rng.choice(["alpha", "beta", "rc"]) + str(rng.randint(1, 9)), ["version", "VERSION", "release"]),
        (lambda: "https://" + rng.choice(["api", "auth", "login"]) + "." + rnd(string.ascii_lowercase, 8) + ".com/" + rnd(string.ascii_lowercase, 6), ["token_url", "auth_url", "api_base"]),
    ]
    out = []
    for _ in range(n):
        gen, names = rng.choice(gens)
        value = gen(); name = rng.choice(names)
        path = rng.choice(paths)
        line = render(name, value, path)
        cands = extract_candidates(line, path)
        if cands:
            c = cands[0]
            out.append((Candidate(c.value, c.name, c.line, c.path, provider_match(c.value)), "synthetic_neg"))
    return out


def baseline_flag(c: Candidate) -> bool:
    """What SecretGuard 6.0 (rules only) would report as a blocking-confidence secret on this line."""
    return any(f.kind == "secret" and f.confidence >= 0.8 for f in scan_text(c.line, c.path, "baseline", include_code=False))


def metrics(y: np.ndarray, pred: np.ndarray) -> dict:
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn)
    return {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(2 * precision * recall / max(1e-9, precision + recall), 4),
            "false_positive_rate": round(fp / max(1, fp + tn), 5), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", nargs="+", type=Path, required=True)
    ap.add_argument("--passwords", type=Path, required=True)
    ap.add_argument("--max-files", type=int, default=14000)
    args = ap.parse_args()
    t0 = time.time()

    # Hardcoded human passwords are positives only when they cannot be mistaken for an identifier
    # (pure-letter words like "password" or "setStart" are indistinguishable from constants/event names).
    passwords = [w for w in (l.strip() for l in args.passwords.read_text(encoding="latin-1").splitlines()[:200000])
                 if 8 <= len(w) <= 40 and w.isprintable() and " " not in w and not re.fullmatch(r"[A-Za-z_.]+", w)]
    real = harvest(args.corpus, args.max_files, per_file=40)
    paths = sorted({p for _, p in real})
    print(f"[data] {len(real):,} real OSS literals from {len(paths):,} files ({time.time()-t0:.0f}s)", flush=True)
    pos = synthetic_positives(int(len(real) * 0.45), paths, passwords)
    hard = synthetic_hard_negatives(int(len(real) * 0.25), paths, )
    rows = [(c, 0, "real_oss") for c, _ in real] + [(c, 1, s) for c, s in pos] + [(c, 0, s) for c, s in hard]
    print(f"[data] positives={len(pos):,} hard_negatives={len(hard):,} total={len(rows):,}", flush=True)

    # Group split by file path: 70/15/15.
    groups = sorted({c.path for c, _, _ in rows}); rng.shuffle(groups)
    g_train = set(groups[: int(.7 * len(groups))]); g_val = set(groups[int(.7 * len(groups)): int(.85 * len(groups))])
    def split(r):
        return "train" if r[0].path in g_train else "val" if r[0].path in g_val else "test"
    parts = {"train": [], "val": [], "test": []}
    for r in rows:
        parts[split(r)].append(r)
    X = {k: np.array([features(c) for c, _, _ in v], dtype=np.float32) for k, v in parts.items()}
    Y = {k: np.array([y for _, y, _ in v]) for k, v in parts.items()}
    print(f"[split] " + " ".join(f"{k}={len(v):,}" for k, v in parts.items()) + f" ({time.time()-t0:.0f}s)", flush=True)

    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 31, "min_data_in_leaf": 40, "feature_fraction": 0.85,
              "bagging_fraction": 0.85, "bagging_freq": 1, "lambda_l2": 1.0, "verbose": -1, "seed": SEED, "num_threads": 2}
    dtrain = lgb.Dataset(X["train"], Y["train"], feature_name=FEATURES)
    dval = lgb.Dataset(X["val"], Y["val"], reference=dtrain)
    booster = lgb.train(params, dtrain, num_boost_round=800, valid_sets=[dval], callbacks=[lgb.early_stopping(50, verbose=False)])

    # Operating point: a merge gate must be quiet on ordinary code. Choose the lowest threshold whose
    # false-positive rate on REAL open-source literals (validation files) is <= 0.2 %.
    pv = booster.predict(X["val"])
    real_val = np.array([s == "real_oss" for _, _, s in parts["val"]])
    pos_val = Y["val"] == 1
    sweep = []
    for t in np.linspace(0.05, 0.99, 95):
        pred = pv >= t
        sweep.append({"threshold": round(float(t), 3), "recall": round(float(pred[pos_val].mean()), 4), "fp_rate_real_code": round(float(pred[real_val].mean()), 5)})
    best_t = next((r["threshold"] for r in sweep if r["fp_rate_real_code"] <= 0.002), 0.9)

    pt = booster.predict(X["test"])
    ml_pred = (pt >= best_t).astype(int)
    base_pred = np.array([int(baseline_flag(c)) for c, _, _ in parts["test"]])
    report = {"model": "LightGBM gradient-boosted trees", "features": FEATURES, "threshold": round(best_t, 3), "threshold_sweep_validation": sweep[::5],
              "trees": booster.num_trees(), "train_rows": len(parts["train"]), "test_rows": len(parts["test"]),
              "data": {"real_oss_literals": len(real), "files": len(paths), "synthetic_positives": len(pos), "synthetic_hard_negatives": len(hard)},
              "test": {"ml": metrics(Y["test"], ml_pred), "rules_baseline": metrics(Y["test"], base_pred)}, "by_source": {}}
    for src in ("real_oss", "synthetic_neg", "synthetic_pos"):
        idx = [i for i, (_, _, s) in enumerate(parts["test"]) if s == src]
        if not idx:
            continue
        y = Y["test"][idx]
        report["by_source"][src] = {"n": len(idx), "ml_flag_rate": round(float(ml_pred[idx].mean()), 4), "rules_flag_rate": round(float(base_pred[idx].mean()), 4)}
    real_idx = [i for i, (_, _, s) in enumerate(parts["test"]) if s == "real_oss"]
    report["false_positives_per_10k_real_literals"] = {
        "ml": round(float(ml_pred[real_idx].mean()) * 10000, 1), "rules_baseline": round(float(base_pred[real_idx].mean()) * 10000, 1)}
    imp = booster.feature_importance("gain")
    report["top_features"] = [[FEATURES[i], round(float(imp[i]), 1)] for i in np.argsort(-imp)[:10]]
    fp_examples = [parts["test"][i][0] for i in real_idx if ml_pred[i] == 1][:8]
    report["sample_ml_false_positives"] = [{"name": c.name, "value_preview": c.value[:4] + "…" + c.value[-4:], "path": c.path} for c in fp_examples]
    print(json.dumps({k: report[k] for k in ("threshold", "test", "false_positives_per_10k_real_literals", "by_source", "top_features")}, indent=1), flush=True)

    out = ROOT / "app" / "ml"
    booster.save_model(str(out / "secret-classifier.txt"))
    (out / "secret-classifier.meta.json").write_text(json.dumps({"features": FEATURES, "threshold": round(best_t, 3),
        "test": report["test"], "false_positives_per_10k_real_literals": report["false_positives_per_10k_real_literals"]}, indent=2), encoding="utf-8")
    (ROOT / "ml" / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "ml" / "reports" / "secret-classifier-card.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[done] {time.time()-t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
