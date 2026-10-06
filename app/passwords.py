from __future__ import annotations

import math
import re
import unicodedata

COMMON = {
    "password", "password1", "password123", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "asdfgh", "admin", "letmein", "welcome", "iloveyou", "abc123",
    "monkey", "dragon", "football", "secret", "changeme", "login", "passw0rd", "trustno1",
    "sunshine", "princess", "master", "hello", "freedom", "whatever", "zaq12wsx", "root", "user",
    "welcome1", "admin123", "1q2w3e4r", "qwertyuiop", "1234abcd", "password!", "password1!",
}

COMMON_WORDS = {
    "admin", "apple", "orange", "microsoft", "google", "company", "finance", "password", "welcome",
    "summer", "winter", "spring", "autumn", "football", "dragon", "monkey", "shadow", "secret",
    "master", "letmein", "hello", "india", "delhi", "ajmer", "college", "student", "github", "office",
    "corporate", "support", "security", "manager", "access", "system", "testing", "test", "demo", "oracle",
    "database", "server", "network", "cloud", "project", "privpass", "guess", "welcome", "login", "company",
    "finance", "math", "school", "developer", "dev", "user", "account", "instagram", "facebook", "amazon",
}

IDENTITY_TOKENS = {
    "divy", "divya", "mathur", "rahul", "rohit", "amit", "ankit", "anil", "arjun", "aditya", "aman", "ashish",
    "ayush", "deepak", "dev", "gaurav", "harsh", "karan", "kunal", "manish", "mohit", "nikhil", "pranav",
    "priyansh", "raj", "ravi", "roshan", "sachin", "sahil", "sameer", "sanjay", "shivam", "shubham", "sumit",
    "surya", "tarun", "varun", "vijay", "vivek", "yash", "yuvraj", "neha", "priya", "pooja", "riya", "simran",
    "shruti", "kavya", "ananya", "isha", "aisha", "sonam", "swati", "megha", "nisha", "komal", "tanya", "kriti",
    "akanksha", "muskan", "divyansh", "sharma", "verma", "gupta", "singh", "patel", "mehta", "jain", "agarwal",
    "kapoor", "malhotra", "saxena", "joshi", "kumar", "smith", "john", "jane", "robert", "michael", "david",
}

KEYBOARD_PATTERNS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "0987654321", "qazwsx", "qweasdzxc", "1qaz2wsx", "!qaz@wsx"
)


def _max_run(value: str) -> int:
    if not value:
        return 0
    best = run = 1
    for a, b in zip(value, value[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    return best


def _repeat_chunks(value: str) -> list[str]:
    hits: list[str] = []
    n = len(value)
    for size in range(2, min(8, n // 2 + 1)):
        for i in range(0, n - 2 * size + 1):
            chunk = value[i : i + size]
            if chunk == value[i + size : i + 2 * size]:
                hits.append(chunk.lower())
    return sorted(set(hits), key=lambda x: (-len(x), x))


def _sequence_run(value: str) -> int:
    best = 0
    for direction in (1, -1):
        run = 1
        for a, b in zip(value, value[1:]):
            if ord(b) - ord(a) == direction:
                run += 1
                best = max(best, run)
            else:
                run = 1
    return best


def _keyboard(value: str) -> bool:
    low = value.lower()
    return any(pattern in low for pattern in KEYBOARD_PATTERNS)


def _has_date_or_year(value: str) -> bool:
    # Treat a year as a date only when it is a standalone token; a random 20-digit
    # numeric secret naturally contains many 4-digit substrings that are not dates.
    if re.search(r"(?:^|[^0-9])(?:19|20)\d{2}(?:$|[^0-9])", value):
        return True
    return bool(re.search(r"(?:^|[^0-9])(?:0?[1-9]|[12]\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/]\d{2,4}(?:$|[^0-9])", value))


def _word_tokens(value: str) -> list[str]:
    return re.findall(r"[a-zA-Z]{3,}", value.lower())


def _embedded_hits(lower: str, words: set[str], min_len: int = 4) -> list[str]:
    hits = [token for token in words if len(token) >= min_len and token in lower]
    return sorted(set(hits), key=lambda x: (-len(x), x))


def _token_coverage(lower: str, tokens: list[str], text_len: int) -> float:
    if not tokens or not text_len:
        return 0.0
    total = 0
    cursor = [0] * len(lower)
    for token in tokens:
        start = 0
        while True:
            idx = lower.find(token, start)
            if idx < 0:
                break
            total += len(token)
            start = idx + max(1, len(token))
    return min(1.0, total / max(1, text_len))


def _human_score(n: int, classes: int, ratio: float, words: list[str], identity_coverage: float,
                dictionary_coverage: float, common_hit: bool, repeated_chunks: list[str], max_run: int,
                sequence_len: int, keyboard: bool, year_or_date: bool, repeated_word: bool,
                alternating: bool, trigram_repetition: int, digit_only: bool, letter_only: bool,
                separator_phrase: bool) -> float:
    if common_hit:
        return 4.0

    # Length is valuable, but it saturates quickly so it can't drown out predictable structure.
    length = min(38.0, max(0.0, (n - 7) * 2.15))
    diversity = min(20.0, classes * 4.0 + ratio * 6.0)
    uniqueness = 6.0 * min(1.0, max(0.0, (ratio - 0.40) / 0.60))
    score = 5.0 + length + diversity + uniqueness

    if separator_phrase and len(words) >= 4 and len(set(words)) == len(words) and identity_coverage < 0.12 and dictionary_coverage < 0.18:
        score += 28.0

    # Evidence penalties scale with how much of the password is predictable.
    if identity_coverage > 0.65:
        score -= 42
    elif identity_coverage > 0.40:
        score -= 28
    elif identity_coverage > 0.20:
        score -= 18
    elif identity_coverage > 0.08:
        score -= 8

    if dictionary_coverage > 0.60:
        score -= 30
    elif dictionary_coverage > 0.35:
        score -= 18
    elif dictionary_coverage > 0.15:
        score -= 9

    if digit_only:
        # Long random numeric secrets can still be useful, but a digit-only alphabet has a smaller space.
        if n < 10:
            score -= 35
        elif n < 15:
            score -= 24
        elif sequence_len >= 4 or repeated_chunks or alternating:
            score -= 18
        else:
            score -= 6
            if n >= 18 and ratio >= 0.55:
                score = max(score, 62.0)

    if letter_only and n < 20:
        score -= 5
    # Small punctuation runs are not as important as long repeated alphanumeric runs.
    alpha_runs = [len(m.group(0)) for m in re.finditer(r"([A-Za-z0-9])\1+", value)] if False else []
    if max_run >= 7:
        score -= 20
    elif max_run >= 5:
        score -= 9
    elif max_run >= 4:
        score -= 4
    if repeated_chunks:
        score -= min(24, 8 + 4 * len(repeated_chunks))
    if repeated_word:
        score -= 12
    if sequence_len >= 8:
        score -= 16
    elif sequence_len >= 5:
        score -= 8
    elif sequence_len >= 4:
        score -= 3
    if keyboard:
        score -= 24
    if year_or_date:
        score -= 8
    if alternating:
        score -= 10
    if trigram_repetition >= 6:
        score -= 8
    elif trigram_repetition >= 3:
        score -= 3
    if ratio < 0.35 and n >= 12:
        score -= 8
    elif ratio < 0.50 and n >= 12:
        score -= 3

    # Long mixed-class, high-uniqueness human strings with no strong attack pattern are genuinely strong.
    if n >= 24 and classes >= 3 and ratio >= 0.65 and identity_coverage < 0.08 and dictionary_coverage < 0.12:
        score += 18
    # Long, high-diversity human strings should not be crushed merely because they contain
    # a small amount of identity/dictionary context. Keep the warning visible, but score the
    # predictable portion proportionally to the whole string.
    if n >= 40 and classes >= 3 and ratio >= 0.55 and max_run <= 4 and sequence_len < 6 and not keyboard and len(repeated_chunks) <= 1 and identity_coverage <= 0.30 and dictionary_coverage <= 0.25:
        score = max(score, 90.0)
    elif n >= 40 and classes >= 3 and ratio >= 0.45 and max_run <= 4 and sequence_len < 6 and not keyboard and len(repeated_chunks) <= 1 and identity_coverage <= 0.35 and dictionary_coverage <= 0.30:
        score = max(score, 86.0)
    elif n >= 40 and classes >= 3 and ratio >= 0.30 and max_run <= 4 and sequence_len < 5 and not keyboard and len(repeated_chunks) <= 1 and identity_coverage <= 0.08 and dictionary_coverage <= 0.12:
        score = max(score, 88.0)
    elif n >= 24 and classes >= 3 and ratio >= 0.45 and max_run <= 4 and sequence_len < 5 and not keyboard and len(repeated_chunks) <= 1 and identity_coverage <= 0.20 and dictionary_coverage <= 0.20:
        score = max(score, 84.0)

    if separator_phrase and len(words) >= 4 and len(set(words)) == len(words) and identity_coverage < 0.12 and dictionary_coverage < 0.18:
        score = max(score, 88.0)

    return max(4.0 if n >= 10 else 0.0, min(96.0, score))


def analyze(password: str, contexts: list[str] | None = None, generated: bool = False):
    p = password or ""
    normalized = unicodedata.normalize("NFKC", p)
    if not normalized:
        return {
            "score": 0, "label": "Waiting", "verdict": "REVIEW", "length": 0, "log10_guesses": 0,
            "effective_bits": None, "unique_ratio": 0, "reasons": ["Type a password to begin local analysis."],
            "context": [], "identity_hits": [], "dictionary_hits": [],
            "flags": {"run": 0, "repeated": False, "repeated_word": False, "keyboard": False,
                      "sequence": False, "digit_only": False, "date": False, "alternating": False,
                      "identity_like": False, "dictionary_like": False, "generated": generated},
            "explain": {"why": "Nothing has been analyzed yet.", "action": "Use a long unique passphrase or a cryptographically generated secret."},
            "generated": generated,
        }

    lower = normalized.lower()
    n = len(normalized)
    meaningful = [ch.lower() for ch in normalized if ch.isalnum()]
    ratio = (len(set(meaningful)) / len(meaningful)) if meaningful else 0.0
    classes = sum(bool(re.search(rx, normalized)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    words = _word_tokens(normalized)
    common_hit = lower in COMMON
    repeated_chunks = _repeat_chunks(normalized)
    max_run = _max_run(normalized)
    sequence_len = _sequence_run(normalized)
    keyboard = _keyboard(normalized)
    year_or_date = _has_date_or_year(normalized)
    context_values = [str(x).strip().lower() for x in (contexts or []) if str(x).strip()]
    context_hits = [c for c in context_values if len(c) >= 3 and c in lower]
    identity_hits = _embedded_hits(lower, IDENTITY_TOKENS, 4)
    dictionary_hits = _embedded_hits(lower, COMMON_WORDS, 5)
    repeated_word = len(words) != len(set(words))
    digit_only = bool(normalized) and normalized.isdigit()
    letter_only = bool(normalized) and normalized.isalpha()
    alternating = bool(re.search(r"(.{2,4})\1{2,}", normalized, re.I))
    trigram_repetition = max(0, len([normalized[i:i+3].lower() for i in range(max(0, n - 2))]) - len(set(normalized[i:i+3].lower() for i in range(max(0, n - 2)))))
    separator_phrase = bool(re.findall(r"[A-Za-z]{3,}", normalized)) and len(words) >= 3 and bool(re.search(r"[\s-]", normalized))
    identity_like = bool(identity_hits) or bool(context_hits)
    dictionary_like = bool(dictionary_hits)
    identity_coverage = max(_token_coverage(lower, identity_hits + context_hits, n), min(1.0, sum(len(x) for x in context_hits) / max(1, n)))
    dictionary_coverage = _token_coverage(lower, dictionary_hits, n)

    if generated:
        # Exact construction entropy, not a visual score.
        alphabet = 70
        passphrase_count = normalized.count("-") + 1
        if passphrase_count >= 4 and re.fullmatch(r"[a-z]+(?:-[a-z]+)+", normalized, re.I):
            construction_bits = round(passphrase_count * math.log2(2048), 1)
        else:
            construction_bits = round(n * math.log2(alphabet), 1)
        score = 100 if construction_bits >= 120 else int(round(min(99, 78 + construction_bits * 0.18)))
    else:
        construction_bits = None
        score = int(round(_human_score(n, classes, ratio, words, identity_coverage, dictionary_coverage, common_hit,
                                     repeated_chunks, max_run, sequence_len, keyboard, year_or_date, repeated_word,
                                     alternating, trigram_repetition, digit_only, letter_only, separator_phrase)))

    # Very short secrets and obvious identity exacts are hard-block territory for the UX model.
    if n < 8:
        score = min(score, 12)
    if n <= 12 and identity_coverage >= 0.75:
        score = min(score, 12)
    if digit_only and n < 12:
        score = min(score, 20)
    if common_hit:
        score = 4

    # Human-chosen score is never an exact entropy claim.
    if generated:
        log10_guesses = round(construction_bits / math.log2(10), 2)
        effective_bits = construction_bits
    else:
        # Conservative displayed model estimate tied to the score, not a claim about an exact attacker cost.
        log10_guesses = round(max(0.3, min(20.0, 1.2 + score * 0.19)), 2)
        effective_bits = round(log10_guesses * math.log2(10), 1)

    if common_hit or score < 20:
        label = "Critical"
    elif score < 45:
        label = "Weak"
    elif score < 65:
        label = "Fair"
    elif score < 85:
        label = "Strong"
    else:
        label = "Excellent"

    reasons: list[str] = []
    if n < 15:
        reasons.append("Below the 15-character password-only baseline")
    if common_hit:
        reasons.append("Matches a commonly guessed password")
    if identity_hits:
        reasons.append(f"Identity-like token detected: {identity_hits[0]}")
    if context_hits:
        reasons.append("Contains supplied account or organization context")
    if dictionary_hits:
        reasons.append(f"Common word/pattern detected: {dictionary_hits[0]}")
    if max_run >= 3:
        reasons.append(f"Repeated-character run of {max_run}")
    if repeated_chunks:
        reasons.append(f"Repeated substring pattern detected ({repeated_chunks[0]!r})")
    if repeated_word:
        reasons.append("Repeated word/token structure detected")
    if sequence_len >= 3:
        reasons.append(f"Predictable sequence of {sequence_len}+ characters")
    if keyboard:
        reasons.append("Keyboard-pattern sequence detected")
    if year_or_date:
        reasons.append("Contains a likely year/date pattern")
    if digit_only:
        reasons.append("Numeric-only password uses a smaller alphabet; random long numeric secrets can still be useful")
    if trigram_repetition >= 2:
        reasons.append("Repeated 3-character patterns suggest human-made structure")
    if separator_phrase and len(words) >= 4 and len(set(words)) == len(words):
        reasons.append("Distinct multi-word passphrase structure detected")
    if generated:
        reasons.append("Generated locally with Web Crypto; construction entropy is shown separately")
    if not reasons:
        reasons.append("No dominant low-effort guessing pattern detected")

    if common_hit or score < 20:
        verdict = "BLOCK"
    elif score < 60 or identity_like or dictionary_like or digit_only or keyboard or n < 15:
        verdict = "REVIEW"
    else:
        verdict = "ACCEPT"

    return {
        "score": score, "score100": score, "label": label, "verdict": verdict, "length": n,
        "unique_ratio": round(ratio, 3), "effective_bits": effective_bits, "construction_bits": construction_bits,
        "log10_guesses": log10_guesses, "reasons": reasons[:10], "context": context_hits,
        "identity_hits": identity_hits, "dictionary_hits": dictionary_hits,
        "flags": {"common": common_hit, "runs": max_run, "repeat_substring": bool(repeated_chunks),
                  "repeated_word": repeated_word, "sequence": sequence_len >= 3, "sequence_length": sequence_len,
                  "keyboard": keyboard, "context_hits": context_hits, "identity_like": identity_like,
                  "dictionary_like": dictionary_like, "year": year_or_date, "digit_only": digit_only,
                  "letter_only": letter_only, "alternating": alternating, "trigram_repetition": trigram_repetition,
                  "separator_phrase": separator_phrase, "generated": generated, "identity_coverage": round(identity_coverage, 3),
                  "dictionary_coverage": round(dictionary_coverage, 3)},
        "explain": {"why": f"Model guess-rank estimate is about 10^{log10_guesses:.2f}; this is a heuristic, not an exact crack-time promise.",
                    "action": "Prefer a unique long passphrase or a cryptographically generated secret. The blocklist and HIBP result are stronger evidence than this score."},
        "generated": generated,
    }
