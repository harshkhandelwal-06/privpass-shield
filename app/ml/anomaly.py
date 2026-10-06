"""Login anomaly detection with an Isolation Forest.

Login telemetry is aggregated into (source IP, 5-minute window) feature vectors. An Isolation Forest
(unsupervised: no attack labels needed) learns what ordinary sign-in traffic looks like and scores
every live window; windows that are easy to isolate are anomalies. Each flag is explained by the
features that sit far outside the normal range, and classified into a likely attack pattern.

Privacy: events store an HMAC of the email, never the email or anything about the password.
The baseline is generated deterministically from a documented model of normal traffic, so the
detector works on a fresh install; in production you would refit it on your own history.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

import numpy as np

WINDOW_MINUTES = 5
FEATURES = ["attempts", "failures", "fail_ratio", "distinct_accounts", "unknown_account_ratio", "attempts_per_min",
            "successes", "distinct_agents", "night", "rate_limited"]
LABELS = {
    "attempts": "sign-in attempts", "failures": "failed sign-ins", "fail_ratio": "failure ratio",
    "distinct_accounts": "different accounts targeted", "unknown_account_ratio": "share of non-existent accounts",
    "attempts_per_min": "attempts per minute", "successes": "successful sign-ins", "distinct_agents": "different user agents",
    "night": "night-time activity", "rate_limited": "rate-limited requests",
}


@dataclass
class Event:
    created_at: datetime
    ip: str
    account_hash: str
    known_account: bool
    success: bool
    reason: str
    agent_hash: str


def window_features(events: list[Event]) -> list[float]:
    attempts = len(events)
    failures = sum(not e.success for e in events)
    accounts = {e.account_hash for e in events}
    unknown = sum(not e.known_account for e in events)
    span = max(1.0, (max(e.created_at for e in events) - min(e.created_at for e in events)).total_seconds() / 60) if events else 1.0
    hour = events[0].created_at.hour if events else 12
    return [attempts, failures, failures / max(1, attempts), len(accounts), unknown / max(1, attempts),
            attempts / span, sum(e.success for e in events), len({e.agent_hash for e in events}),
            float(hour < 5), sum(e.reason == "rate_limited" for e in events)]


def group_windows(events: list[Event]) -> list[dict]:
    buckets: dict[tuple[str, datetime], list[Event]] = {}
    for e in events:
        start = e.created_at.replace(second=0, microsecond=0)
        start -= timedelta(minutes=start.minute % WINDOW_MINUTES)
        buckets.setdefault((e.ip, start), []).append(e)
    return [{"ip": ip, "start": start, "events": evs, "x": window_features(evs)} for (ip, start), evs in sorted(buckets.items(), key=lambda kv: kv[0][1])]


def normal_traffic(n: int, rng: np.random.Generator) -> np.ndarray:
    """Documented baseline of legitimate traffic per IP/5-minute window.

    * 80 % single users: 1-3 attempts, mostly successful, one account, one browser
    * 12 % users who mistype: 2-5 attempts, 1-3 failures, then success
    * 8 %  shared offices / NAT: 2-10 accounts, low failure ratio, several browsers
    """
    rows = []
    for _ in range(n):
        kind = rng.random()
        if kind < 0.80:
            att = int(rng.integers(1, 4)); fail = int(rng.binomial(att, 0.08)); acc = 1; agents = 1
        elif kind < 0.92:
            att = int(rng.integers(2, 6)); fail = min(att - 1, int(rng.integers(1, 4))); acc = 1; agents = 1
        else:
            acc = int(rng.integers(2, 11)); att = acc + int(rng.integers(0, 4)); fail = int(rng.binomial(att, 0.12)); agents = int(rng.integers(2, acc + 1))
        unknown = int(rng.binomial(fail, 0.15))
        span = float(rng.uniform(0.5, WINDOW_MINUTES))
        rows.append([att, fail, fail / att, acc, unknown / att, att / max(1.0, span), att - fail, agents, float(rng.random() < 0.06), 0])
    return np.array(rows, dtype=float)


def attack_traffic(kind: str, n: int, rng: np.random.Generator) -> np.ndarray:
    rows = []
    for _ in range(n):
        if kind == "credential_stuffing":
            acc = int(rng.integers(15, 120)); att = acc + int(rng.integers(0, 10)); fail = att - int(rng.integers(0, 3)); unknown = int(fail * rng.uniform(0.3, 0.8)); agents = int(rng.integers(1, 4)); rl = int(rng.integers(0, att // 3))
        elif kind == "brute_force":
            acc = 1; att = int(rng.integers(12, 80)); fail = att; unknown = 0; agents = 1; rl = int(rng.integers(0, att // 2))
        else:  # "enumeration"
            acc = int(rng.integers(20, 200)); att = acc; fail = att; unknown = int(att * rng.uniform(0.7, 1.0)); agents = 1; rl = 0
        span = float(rng.uniform(1, WINDOW_MINUTES))
        rows.append([att, fail, fail / att, acc, unknown / att, att / span, att - fail, agents, float(rng.random() < 0.4), rl])
    return np.array(rows, dtype=float)


@lru_cache(maxsize=1)
def model():
    from sklearn.ensemble import IsolationForest
    rng = np.random.default_rng(2026)
    base = normal_traffic(4000, rng)
    forest = IsolationForest(n_estimators=250, contamination=0.01, random_state=2026).fit(base)
    p99 = np.percentile(base, 99, axis=0)
    scores = -forest.score_samples(base)
    return forest, p99, float(np.percentile(scores, 50)), float(np.percentile(scores, 99.5))


def classify(x: list[float]) -> str:
    att, fail, fr, acc, unk = x[0], x[1], x[2], x[3], x[4]
    if acc >= 10 and unk >= 0.6:
        return "Account enumeration"
    if acc >= 10 and fr >= 0.7:
        return "Credential stuffing"
    if acc <= 2 and fail >= 8:
        return "Brute force on one account"
    return "Unusual sign-in pattern"


def score_windows(windows: list[dict]) -> list[dict]:
    if not windows:
        return []
    forest, p99, mid, high = model()
    X = np.array([w["x"] for w in windows], dtype=float)
    raw = -forest.score_samples(X)
    flags = forest.predict(X) == -1
    out = []
    for w, s, flag in zip(windows, raw, flags):
        norm = float(np.clip((s - mid) / max(1e-9, high - mid), 0, 1.5) / 1.5)
        reasons = [f"{w['x'][i]:.0f} {LABELS[f]} (normal ≤ {p99[i]:.0f})" if f not in {"fail_ratio", "unknown_account_ratio"} else f"{w['x'][i]:.0%} {LABELS[f]} (normal ≤ {p99[i]:.0%})"
                   for i, f in enumerate(FEATURES) if f not in {"night"} and w["x"][i] > p99[i] * 1.05 + (0.01 if f.endswith("ratio") else 0.5)]
        out.append({"ip": w["ip"], "window_start": w["start"].isoformat(), "attempts": int(w["x"][0]), "failures": int(w["x"][1]),
                    "accounts": int(w["x"][3]), "score": round(norm, 3), "anomalous": bool(flag) and norm >= 0.5,
                    "pattern": classify(w["x"]) if flag else "Normal", "reasons": reasons[:4],
                    "simulated": any(e.reason.startswith("sim") for e in w["events"])})
    return sorted(out, key=lambda r: -r["score"])


def evaluate() -> dict:
    """Detection rate per attack type and false-alarm rate on fresh normal traffic (synthetic benchmark)."""
    forest, *_ = model()
    rng = np.random.default_rng(99)
    normal = normal_traffic(3000, rng)
    res = {"false_alarm_rate": round(float((forest.predict(normal) == -1).mean()), 4)}
    for kind in ("credential_stuffing", "brute_force", "enumeration"):
        res[f"detect_{kind}"] = round(float((forest.predict(attack_traffic(kind, 500, rng)) == -1).mean()), 4)
    return {"model": "IsolationForest (250 trees, contamination 1%)", "window_minutes": WINDOW_MINUTES, "features": FEATURES,
            "evaluation": res, "note": "Synthetic benchmark: baseline and attacks are generated from the documented traffic models in app/ml/anomaly.py."}
