"""Build the local breach corpus: a Bloom filter of SHA-1 hashes of leaked passwords.

The browser downloads the filter once and checks passwords entirely locally - not even the
5-character HIBP prefix leaves the device. Useful for air-gapped deployments and as a fallback
when the HIBP API is unreachable.

Hashing: SHA-1(NFKC(password)) -> h1 = first 4 bytes (uint32 BE), h2 = next 4 bytes | 1;
bit_i = (h1 + i*h2) mod m  for i in 0..k-1  (Kirsch-Mitzenmacher double hashing).
static/js implements the identical lookup.

    python tools/build_breach_bloom.py --wordlist Pwdb_top-1000000.txt --fpr 0.001
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def indices(digest: bytes, k: int, m: int) -> list[int]:
    h1 = int.from_bytes(digest[0:4], "big")
    h2 = int.from_bytes(digest[4:8], "big") | 1
    return [(h1 + i * h2) % m for i in range(k)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wordlist", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=1_000_000)
    ap.add_argument("--fpr", type=float, default=0.001)
    ap.add_argument("--out", type=Path, default=ROOT / "static" / "breach")
    args = ap.parse_args()
    words = []
    with open(args.wordlist, encoding="latin-1", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\r\n")
            if w:
                words.append(unicodedata.normalize("NFKC", w))
            if len(words) >= args.limit:
                break
    n = len(words)
    m = math.ceil(-n * math.log(args.fpr) / (math.log(2) ** 2))
    m += (-m) % 8
    k = max(1, round(m / n * math.log(2)))
    bits = bytearray(m // 8)
    for w in words:
        for idx in indices(hashlib.sha1(w.encode("utf-8"), usedforsecurity=False).digest(), k, m):  # HIBP-compatible lookup key, not a security hash
            bits[idx >> 3] |= 1 << (idx & 7)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "top1m.bloom").write_bytes(bytes(bits))
    meta = {"n": n, "m": m, "k": k, "fpr": args.fpr, "hash": "sha1-nfkc-double-hashing-v1",
            "source": "SecLists Pwdb_top-1000000 (public, frequency-ranked leaked passwords)", "bytes": len(bits)}
    (args.out / "top1m.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
