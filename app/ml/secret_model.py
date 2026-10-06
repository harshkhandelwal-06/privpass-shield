"""Runtime for the SecretGuard ML classifier.

Loads the LightGBM *text* model (no pickle, nothing executable) once, scores candidates in batches,
and explains each score with LightGBM's built-in SHAP contributions (pred_contrib=True).
If lightgbm is not installed the scanner silently falls back to the rule engine.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .secret_features import EXPLAIN, FEATURES, Candidate, features

HERE = Path(__file__).resolve().parent
MODEL_PATH = HERE / "secret-classifier.txt"
META_PATH = HERE / "secret-classifier.meta.json"


@lru_cache(maxsize=1)
def _load():
    try:
        import lightgbm as lgb
        import numpy as np
    except Exception:  # ImportError, or OSError when the native OpenMP runtime is missing
        return None
    if not MODEL_PATH.exists():
        return None
    meta = json.loads(META_PATH.read_text(encoding="utf-8")) if META_PATH.exists() else {"threshold": 0.5}
    try:
        booster = lgb.Booster(model_str=MODEL_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None
    return booster, np, float(meta.get("threshold", 0.5)), meta


def available() -> bool:
    return _load() is not None


def threshold() -> float:
    loaded = _load()
    return loaded[2] if loaded else 0.5


def model_meta() -> dict | None:
    loaded = _load()
    return loaded[3] if loaded else None


def score(candidates: list[Candidate], explain: bool = True) -> list[tuple[float, tuple[str, ...]]]:
    """Return (probability, top reasons) per candidate. Empty list if the model is unavailable."""
    loaded = _load()
    if loaded is None or not candidates:
        return []
    booster, np, _t, _meta = loaded
    X = np.array([features(c) for c in candidates], dtype=np.float32)
    probs = booster.predict(X)
    reasons: list[tuple[str, ...]] = [()] * len(candidates)
    if explain:
        contrib = booster.predict(X, pred_contrib=True)[:, :-1]   # last column is the bias term
        reasons = []
        for row in contrib:
            top = np.argsort(-np.abs(row))[:3]
            reasons.append(tuple(f"{'+' if row[i] > 0 else '−'} {EXPLAIN.get(FEATURES[i], FEATURES[i])}" for i in top if abs(row[i]) > 0.05))
    return [(float(p), r) for p, r in zip(probs, reasons)]
