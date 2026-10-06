"""Rebuild static/ml/words-names.txt.gz (ranked dictionary for static/ml/structure-model.js).

    pip install wordfreq==3.1.1 names-dataset==3.3.1 msgpack
    python tools/build_wordlist.py

Sources and licences: see static/ml/WORDLIST-NOTICE.txt. Only aggregate word frequencies and name popularity ranks are used.
"""
from __future__ import annotations
import gzip
import pickle
import re
from pathlib import Path

import msgpack
import names_dataset
import wordfreq

OUT = Path(__file__).resolve().parents[1] / "static" / "ml" / "words-names.txt.gz"
OK = re.compile(r"^[a-z]{2,20}$")


def english(n: int) -> list[str]:
    data = msgpack.load(gzip.open(Path(wordfreq.__file__).parent / "data" / "large_en.msgpack.gz"), raw=False)
    out, seen = [], set()
    for bucket in data[1:]:                      # cB buckets, most frequent first
        for w in bucket:
            if OK.match(w) and w not in seen:
                seen.add(w); out.append(w)
        if len(out) >= n:
            break
    return out[:n]


def names(file: str, n: int) -> list[str]:
    # Offline build step: this file ships inside the pinned names-dataset wheel, never user input.
    data = pickle.load(gzip.open(Path(names_dataset.__file__).parent / "v3" / file))  # nosec B301 secretguard:allow
    rows = sorted((min(i["rank"].values()), -len(i["rank"]), k.lower()) for k, i in data.items() if i.get("rank") and OK.match(k.lower()))
    out, seen = [], set()
    for _, _, low in rows:
        if low not in seen:
            seen.add(low); out.append(low)
        if len(out) >= n:
            break
    return out


def main() -> None:
    best: dict[str, int] = {}
    for lst in (english(40000), names("first_names.pkl.gz", 30000), names("last_names.pkl.gz", 50000)):
        for i, w in enumerate(lst):          # an attacker interleaving 3 lists reaches list-rank r after ~3r guesses
            best[w] = min(best.get(w, 1 << 60), 3 * (i + 1))
    merged = sorted(best, key=best.get)
    OUT.write_bytes(gzip.compress("\n".join(merged).encode(), 9))
    print(f"{len(merged)} tokens -> {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
