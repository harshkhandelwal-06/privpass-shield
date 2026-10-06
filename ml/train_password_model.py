"""Train the PrivPass neural password-guessability model.

Approach (after Melicher et al., "Fast, Lean, and Accurate: Modeling Password Guessability Using
Neural Networks", USENIX Security 2016, and Dell'Amico & Filippone, "Monte Carlo Strength
Evaluation", CCS 2015):

1. A character-level GRU language model learns P(next char | prefix) from a public, frequency-ranked
   leaked-password list (SecLists Pwdb_top-10000000). Training examples are drawn with Zipf weights
   by rank, approximating how often each password really occurs in breaches.
2. P(password) = product of the per-character probabilities (including an end token).
3. Probability is turned into an estimated *guess number* (how many guesses an attacker who guesses
   in order of this model's probability would need) with Monte Carlo sampling from the model itself.

Outputs (all JSON; no pickles, runs in the browser without any ML runtime):
  static/ml/password-model.json   quantised weights + guess-number calibration table
  ml/reports/password-model-card.json   evaluation vs zxcvbn and the rule-based heuristic

Usage:  python ml/train_password_model.py --wordlist <Pwdb_top-10000000.txt>
"""
from __future__ import annotations

import argparse
import base64
import json
import math
import random
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CHARS = [chr(c) for c in range(32, 127)]           # printable ASCII
PAD, BOS, EOS, UNK = 0, 1, 2, 3
STOI = {c: i + 4 for i, c in enumerate(CHARS)}
VOCAB = len(CHARS) + 4
MAX_LEN = 32
SEED = 2026


def encode(pw: str) -> list[int]:
    return [STOI.get(c, UNK) for c in pw[:MAX_LEN]]


class CharGRU(nn.Module):
    def __init__(self, vocab: int, emb: int, hidden: int):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb, padding_idx=PAD)
        self.gru = nn.GRU(emb, hidden, batch_first=True)
        self.out = nn.Linear(hidden, vocab)

    def forward(self, x):
        h, _ = self.gru(self.emb(x))
        return self.out(h)


def load_list(path: Path, limit: int) -> list[str]:
    out = []
    with open(path, encoding="latin-1", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\r\n")
            if 1 <= len(pw) <= MAX_LEN and all(32 <= ord(c) < 127 for c in pw):
                out.append(pw)
            if len(out) >= limit:
                break
    return out


def batches(samples: list[str], batch_size: int):
    for i in range(0, len(samples), batch_size):
        chunk = samples[i:i + batch_size]
        seqs = [[BOS] + encode(p) + [EOS] for p in chunk]
        width = max(len(s) for s in seqs)
        arr = np.full((len(seqs), width), PAD, dtype=np.int64)
        for j, s in enumerate(seqs):
            arr[j, :len(s)] = s
        t = torch.from_numpy(arr)
        yield t[:, :-1], t[:, 1:]


@torch.no_grad()
def log2_prob(model: CharGRU, passwords: list[str], batch_size: int = 2048) -> np.ndarray:
    model.eval()
    res = []
    for inp, tgt in batches(passwords, batch_size):
        logp = torch.log_softmax(model(inp), dim=-1)
        tok = logp.gather(-1, tgt.unsqueeze(-1)).squeeze(-1)
        tok = tok.masked_fill(tgt == PAD, 0.0)
        res.append((tok.sum(dim=1) / math.log(2)).numpy())
    return np.concatenate(res)


@torch.no_grad()
def sample(model: CharGRU, n: int, batch: int = 4096) -> tuple[list[str], np.ndarray]:
    """Ancestral sampling; returns samples and their exact log2 probabilities."""
    model.eval()
    out, lps = [], []
    while len(out) < n:
        b = min(batch, n - len(out))
        x = torch.full((b, 1), BOS, dtype=torch.long)
        h = None
        done = torch.zeros(b, dtype=torch.bool)
        lp = torch.zeros(b)
        chars = [[] for _ in range(b)]
        for _ in range(MAX_LEN + 1):
            e = model.emb(x[:, -1:])
            o, h = model.gru(e, h)
            logits = model.out(o[:, -1])
            logits[:, PAD] = -1e9; logits[:, BOS] = -1e9; logits[:, UNK] = -1e9
            logp = torch.log_softmax(logits, dim=-1)
            nxt = torch.multinomial(logp.exp(), 1).squeeze(1)
            lp += torch.where(done, torch.zeros(b), logp.gather(1, nxt.unsqueeze(1)).squeeze(1))
            for i in range(b):
                if not done[i] and nxt[i].item() != EOS:
                    chars[i].append(CHARS[nxt[i].item() - 4])
            done |= nxt == EOS
            x = torch.cat([x, nxt.unsqueeze(1)], dim=1)
            if done.all():
                break
        for i in range(b):
            if done[i]:
                out.append("".join(chars[i])); lps.append(lp[i].item() / math.log(2))
    return out[:n], np.array(lps[:n])


def calibration_table(sample_lp: np.ndarray, points: int = 400) -> list[list[float]]:
    """Monte Carlo guess-number estimator (Dell'Amico & Filippone 2015).

    For a password with probability p, guesses(p) = sum over samples with p_i > p of 1/(n * p_i).
    We store (log2 p threshold, log10 guesses) pairs at quantiles for interpolation in JS.
    """
    n = len(sample_lp)
    order = np.argsort(-sample_lp)            # most probable first
    lp_sorted = sample_lp[order]
    inv = 1.0 / (n * np.exp2(lp_sorted))
    cum = np.cumsum(inv)
    idx = np.unique(np.linspace(0, n - 1, points).astype(int))
    return [[round(float(lp_sorted[i]), 3), round(float(math.log10(max(cum[i], 1.0))), 3)] for i in idx]


def guesses_from_table(lp2: float, table: list[list[float]]) -> float:
    """log10 guesses for a log2 probability, by interpolation; extrapolates beyond the table."""
    if lp2 >= table[0][0]:
        return 0.0
    for (a_lp, a_g), (b_lp, b_g) in zip(table, table[1:]):
        if b_lp <= lp2 <= a_lp:
            t = (a_lp - lp2) / max(1e-9, a_lp - b_lp)
            return a_g + t * (b_g - a_g)
    last_lp, last_g = table[-1]
    return last_g + (last_lp - lp2) * math.log10(2)   # each lost bit ~ doubles the guesses


def quantise(t: torch.Tensor) -> dict:
    arr = t.detach().float().numpy()
    scale = float(np.abs(arr).max()) / 127.0 or 1.0
    q = np.clip(np.round(arr / scale), -127, 127).astype(np.int8)
    return {"shape": list(arr.shape), "scale": scale, "data": base64.b64encode(q.tobytes()).decode()}


def dequantise(d: dict) -> np.ndarray:
    return np.frombuffer(base64.b64decode(d["data"]), dtype=np.int8).astype(np.float32).reshape(d["shape"]) * d["scale"]


def numpy_log2prob(weights: dict, pw: str) -> float:
    """Reference implementation of exactly what static/ml/password-model.js computes."""
    E = dequantise(weights["emb"]); Wi = dequantise(weights["w_ih"]); Wh = dequantise(weights["w_hh"])
    bi = np.array(weights["b_ih"], dtype=np.float32); bh = np.array(weights["b_hh"], dtype=np.float32)
    Wo = dequantise(weights["w_out"]); bo = np.array(weights["b_out"], dtype=np.float32)
    H = Wh.shape[1]
    h = np.zeros(H, dtype=np.float32)
    total = 0.0
    seq = [BOS] + encode(pw) + [EOS]
    for cur, nxt in zip(seq, seq[1:]):
        x = E[cur]
        gi = Wi @ x + bi; gh = Wh @ h + bh
        r = 1 / (1 + np.exp(-(gi[:H] + gh[:H]))); z = 1 / (1 + np.exp(-(gi[H:2*H] + gh[H:2*H])))
        n = np.tanh(gi[2*H:] + r * gh[2*H:])
        h = (1 - z) * n + z * h
        logits = Wo @ h + bo
        logits[[PAD, BOS, UNK]] = -1e9
        m = logits.max(); logz = m + math.log(np.exp(logits - m).sum())
        total += (logits[nxt] - logz) / math.log(2)
    return float(total)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", type=Path, required=True)
    ap.add_argument("--unique", type=int, default=3_000_000, help="top-N unique passwords to use")
    ap.add_argument("--train-draws", type=int, default=1_500_000)
    ap.add_argument("--zipf", type=float, default=0.9)
    ap.add_argument("--hidden", type=int, default=192)
    ap.add_argument("--emb", type=int, default=32)
    ap.add_argument("--epochs", type=int, default=2)
    ap.add_argument("--batch", type=int, default=512)
    ap.add_argument("--mc-samples", type=int, default=60_000)
    args = ap.parse_args()

    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)
    torch.set_num_threads(max(1, torch.get_num_threads()))
    t0 = time.time()
    uniq = load_list(args.wordlist, args.unique)
    ranks = np.arange(1, len(uniq) + 1)
    # Hold out 3% of unique passwords (stratified across ranks) - never seen in training.
    held = np.random.rand(len(uniq)) < 0.03
    train_idx = np.where(~held)[0]; test_idx = np.where(held)[0]
    w = 1.0 / ranks[train_idx] ** args.zipf
    draws = np.random.choice(train_idx, size=args.train_draws, p=w / w.sum())
    train = [uniq[i] for i in draws]
    print(f"[data] {len(uniq):,} unique, {len(train):,} Zipf draws, {len(test_idx):,} held out ({time.time()-t0:.0f}s)", flush=True)

    model = CharGRU(VOCAB, args.emb, args.hidden)
    opt = torch.optim.Adam(model.parameters(), lr=3e-3)
    lossf = nn.CrossEntropyLoss(ignore_index=PAD)
    steps_per_epoch = math.ceil(len(train) / args.batch)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=3e-3, total_steps=steps_per_epoch * args.epochs)
    for epoch in range(args.epochs):
        random.shuffle(train)
        model.train(); running = 0.0
        for step, (inp, tgt) in enumerate(batches(train, args.batch), 1):
            opt.zero_grad()
            loss = lossf(model(inp).reshape(-1, VOCAB), tgt.reshape(-1))
            loss.backward(); nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step()
            running += loss.item()
            if step % 200 == 0:
                print(f"[train] epoch {epoch+1} step {step}/{steps_per_epoch} loss {running/200:.3f} ({time.time()-t0:.0f}s)", flush=True)
                running = 0.0

    # ---- Monte Carlo calibration --------------------------------------------------------
    samples, s_lp = sample(model, args.mc_samples)
    table = calibration_table(s_lp)
    print(f"[mc] {len(samples):,} samples; e.g. {samples[:8]}", flush=True)

    weights = {
        "emb": quantise(model.emb.weight), "w_ih": quantise(model.gru.weight_ih_l0), "w_hh": quantise(model.gru.weight_hh_l0),
        "b_ih": [round(float(v), 5) for v in model.gru.bias_ih_l0.detach()], "b_hh": [round(float(v), 5) for v in model.gru.bias_hh_l0.detach()],
        "w_out": quantise(model.out.weight), "b_out": [round(float(v), 5) for v in model.out.bias.detach()],
    }

    # ---- Evaluation -----------------------------------------------------------------------
    rng = random.Random(SEED)
    held_pw = [uniq[i] for i in rng.sample(list(test_idx), min(3000, len(test_idx)))]
    alphabet = "".join(CHARS[1:])
    random_pw = ["".join(rng.choice(alphabet) for _ in range(rng.randint(12, 20))) for _ in range(1000)]
    words = [p for p in uniq[:200000] if p.isalpha() and p.islower() and 4 <= len(p) <= 8][:5000]
    phrases = [" ".join(rng.sample(words, 5)) for _ in range(500)]

    def neural_log10(pws):
        return [guesses_from_table(lp, table) for lp in log2_prob(model, pws)]

    try:
        from zxcvbn import zxcvbn
        zx = lambda pws: [math.log10(max(1.0, float(zxcvbn(p[:72])["guesses"]))) for p in pws]
    except ImportError:
        zx = None
    from app.passwords import analyze
    heur = lambda pws: [analyze(p)["log10_guesses"] for p in pws]

    def coverage(vals, thresholds=(6, 9, 12)):
        return {f"<=1e{t}": round(sum(v <= t for v in vals) / len(vals), 4) for t in thresholds}

    report = {"model": "char-GRU", "params": sum(p.numel() for p in model.parameters()),
              "hidden": args.hidden, "embedding": args.emb, "vocab": VOCAB, "train_draws": len(train),
              "unique_passwords": len(uniq), "held_out": len(held_pw), "mc_samples": len(samples),
              "source": "SecLists Pwdb_top-10000000 (public, frequency-ranked leaked-password list)",
              "method": "Melicher et al. 2016 (neural guessability) + Dell'Amico & Filippone 2015 (Monte Carlo guess numbers)",
              "evaluation": {}}
    for name, fn in [("neural", neural_log10), ("zxcvbn", zx), ("heuristic_v5", heur)]:
        if fn is None:
            continue
        leaked, rnd, phr = fn(held_pw), fn(random_pw), fn(phrases)
        report["evaluation"][name] = {
            "held_out_leaked_guessed_within": coverage(leaked),
            "random_12_20_char_rated_weak_within_1e12": round(sum(v <= 12 for v in rnd) / len(rnd), 4),
            "five_word_passphrase_rated_weak_within_1e12": round(sum(v <= 12 for v in phr) / len(phr), 4),
            "median_log10_leaked": round(float(np.median(leaked)), 2),
            "median_log10_random": round(float(np.median(rnd)), 2),
        }
        print(f"[eval] {name}: {report['evaluation'][name]}", flush=True)

    # Quantisation check: the JS/numpy int8 path must agree with the float model.
    probe = held_pw[:200]
    f_lp = log2_prob(model, probe)
    q_lp = np.array([numpy_log2prob(weights, p) for p in probe])
    report["quantisation_mean_abs_error_bits"] = round(float(np.mean(np.abs(f_lp - q_lp))), 4)
    report["examples"] = {p: round(guesses_from_table(numpy_log2prob(weights, p), table), 2) for p in
                          ["password", "iloveyou2024", "Summer2024!", "divy1023divy1032", "aaaasfiefifosdnofsdfn",
                           "river lantern copper orbit", "correct horse battery staple", "Xq7#vT2pLm9!rK4@", "3492847592039485720"]}
    print(f"[quant] mean |Δlog2p| = {report['quantisation_mean_abs_error_bits']} bits; examples {report['examples']}", flush=True)

    out_model = ROOT / "static" / "ml" / "password-model.json"
    out_model.parent.mkdir(parents=True, exist_ok=True)
    out_model.write_text(json.dumps({"version": 1, "vocab_offset": 4, "first_char": 32, "max_len": MAX_LEN,
                                     "special": {"pad": PAD, "bos": BOS, "eos": EOS, "unk": UNK},
                                     "hidden": args.hidden, "weights": weights, "calibration": table,
                                     "card": {k: report[k] for k in ("model", "params", "source", "method", "evaluation")}}),
                         encoding="utf-8")
    rep = ROOT / "ml" / "reports" / "password-model-card.json"
    rep.parent.mkdir(parents=True, exist_ok=True)
    rep.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[done] {out_model} ({out_model.stat().st_size/1024:.0f} KB) in {time.time()-t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
