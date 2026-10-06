"""Feature extraction for the SecretGuard ML classifier.

Shared by training (ml/train_secret_classifier.py) and inference (app/ml/secret_model.py) so the
two can never drift. A *candidate* is a string literal assigned to something in source code:

    STRIPE_KEY = "sk_live_..."        name="STRIPE_KEY"  value="sk_live_..."
    "checksum": "9f86d081884c7d65"    name="checksum"    value="9f86d0..."
    DB_PASSWORD=hunter2hunter2        (.env style)

The model answers: "is this a hardcoded credential that must not be committed?"
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

ASSIGNMENT = re.compile(
    r"""(?P<name>[A-Za-z_][\w.\-\[\]'"]{0,60}?)['"]?\s*(?::=|=>|:|=)\s*[rbuf]?(?P<q>['"`])(?P<value>[^'"`\s]{8,256})(?P=q)""")
ENV_LINE = re.compile(r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]{1,60})\s*=\s*(?P<value>[^\s'\"#]{8,256})\s*$")

SECRET_WORDS = ("key", "secret", "token", "passw", "pwd", "pass", "auth", "credential", "cred", "private", "api", "bearer", "session", "cookie", "signing", "access", "dsn", "conn")
NONSECRET_WORDS = ("hash", "sha", "md5", "checksum", "digest", "uuid", "guid", "color", "colour", "version", "etag", "commit", "revision", "fingerprint", "name", "path", "url", "uri", "file", "dir", "id", "format", "pattern", "regex", "template", "label", "title", "message", "msg", "text", "lang", "locale", "mime", "type", "icon", "image", "font", "class", "style", "encoding", "hostname", "host", "email", "user", "username", "public")
PLACEHOLDER = re.compile(r"example|dummy|fake|sample|changeme|change[_-]?me|your[_-]|replace|placeholder|redacted|xxxx|\*\*\*\*|<[^>]*>|\$\{|\{\{|todo|insert|test[_-]?key|not[_-]?a[_-]?real|lorem|foobar|secret123|password123", re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|spec|specs|__tests__|fixtures?|mocks?|examples?|samples?|docs?|demo)(/|$)|_test\.|\.test\.|\.spec\.|test_", re.I)
ENV_READ = re.compile(r"os\.environ|getenv|process\.env|System\.getenv|ENV\[|config\(|settings\.", re.I)
HEX = re.compile(r"^[0-9a-fA-F]+$")
B64 = re.compile(r"^[A-Za-z0-9+/_-]+=*$")
UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
IDENT = re.compile(r"^[A-Za-z_][A-Za-z_.]*$")
CODE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php", ".cs", ".rs", ".kt", ".swift", ".sh", ".ps1"}
CONFIG_EXT = {".env", ".yml", ".yaml", ".json", ".ini", ".cfg", ".toml", ".properties", ".conf", ".xml", ".tf"}

FEATURES = [
    "length", "log_length", "entropy", "entropy_ratio", "frac_upper", "frac_lower", "frac_digit", "frac_symbol",
    "char_classes", "unique_ratio", "is_hex", "is_base64ish", "is_uuid", "has_path_or_url", "max_run", "vowel_ratio",
    "identifier_like", "digit_only", "case_transitions", "placeholder_hit", "name_secret_word", "name_nonsecret_word",
    "name_len", "name_upper_snake", "path_testlike", "ext_code", "ext_config", "ext_doc", "is_dotenv",
    "line_is_comment", "line_reads_env", "provider_match", "line_len", "dots", "dashes",
]

# Human-readable explanations for the top SHAP contributions.
EXPLAIN = {
    "entropy": "randomness of the value", "entropy_ratio": "how close to maximally random", "length": "value length",
    "log_length": "value length", "name_secret_word": "variable name suggests a credential",
    "name_nonsecret_word": "variable name suggests a hash/id/label", "placeholder_hit": "looks like a placeholder",
    "path_testlike": "test/docs/example path", "is_hex": "hex-only value (often a hash)", "is_uuid": "UUID format",
    "provider_match": "matches a provider key format", "identifier_like": "looks like an identifier, not a secret",
    "has_path_or_url": "looks like a path or URL", "is_dotenv": ".env file", "ext_config": "config file",
    "line_reads_env": "line reads from the environment", "vowel_ratio": "word-like letters",
    "frac_digit": "digit mix", "frac_upper": "uppercase mix", "frac_symbol": "symbol mix", "char_classes": "character variety",
    "unique_ratio": "character variety", "case_transitions": "mixed-case randomness", "digit_only": "digits only",
    "name_upper_snake": "CONSTANT_STYLE name", "line_is_comment": "inside a comment", "is_base64ish": "base64-like",
    "max_run": "repeated characters", "ext_code": "source file", "ext_doc": "documentation file", "name_len": "name length",
    "line_len": "line length", "dots": "dot-separated", "dashes": "dash-separated",
}


@dataclass(frozen=True)
class Candidate:
    value: str
    name: str
    line: str
    path: str
    provider_match: bool = False


def shannon(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for c in value:
        counts[c] = counts.get(c, 0) + 1
    n = len(value)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def extract_candidates(line: str, path: str) -> list[Candidate]:
    out = []
    for m in ASSIGNMENT.finditer(line):
        name = re.sub(r"[\[\]'\"]", "", m.group("name")).split(".")[-1]
        out.append(Candidate(m.group("value"), name, line, path))
    if not out and (PurePosixPath(path).name.lower().startswith(".env") or PurePosixPath(path).suffix.lower() in {".env", ".properties", ".ini", ".cfg"}):
        m = ENV_LINE.match(line)
        if m:
            out.append(Candidate(m.group("value"), m.group("name"), line, path))
    return out


def features(c: Candidate) -> list[float]:
    v, name, low_name = c.value, c.name, c.name.lower()
    n = len(v)
    ent = shannon(v)
    alpha = len(set(v))
    upper = sum(ch.isupper() for ch in v); lower = sum(ch.islower() for ch in v)
    digit = sum(ch.isdigit() for ch in v); symbol = n - upper - lower - digit
    letters = [ch for ch in v.lower() if ch.isalpha()]
    vowels = sum(ch in "aeiou" for ch in letters)
    run = best = 1
    for a, b in zip(v, v[1:]):
        run = run + 1 if a == b else 1
        best = max(best, run)
    transitions = sum(1 for a, b in zip(v, v[1:]) if a.isalpha() and b.isalpha() and a.isupper() != b.isupper())
    p = PurePosixPath(c.path.replace("\\", "/"))
    ext = p.suffix.lower()
    stripped = c.line.strip()
    return [
        n, math.log(n + 1), ent, ent / max(1e-9, math.log2(max(2, min(n, 64)))),
        upper / n, lower / n, digit / n, symbol / n,
        sum(x > 0 for x in (upper, lower, digit, symbol)), alpha / n,
        float(bool(HEX.match(v))), float(bool(B64.match(v)) and not HEX.match(v)), float(bool(UUID.match(v))),
        float("/" in v or "://" in v or "\\" in v), best, vowels / max(1, len(letters)),
        float(bool(IDENT.match(v))), float(v.isdigit()), transitions / n, float(bool(PLACEHOLDER.search(v))),
        float(any(w in low_name for w in SECRET_WORDS)), float(any(re.search(rf"(^|_|-|\b){w}(s)?($|_|-|\b)", low_name) for w in NONSECRET_WORDS)),
        len(name), float(bool(re.fullmatch(r"[A-Z][A-Z0-9_]+", name))), float(bool(TEST_PATH.search(c.path))),
        float(ext in CODE_EXT), float(ext in CONFIG_EXT or p.name.lower().startswith(".env")), float(ext in {".md", ".txt", ".rst", ".html"}),
        float(p.name.lower().startswith(".env")),
        float(stripped.startswith(("#", "//", "/*", "*", "--"))), float(bool(ENV_READ.search(c.line))),
        float(c.provider_match), min(len(c.line), 400), v.count("."), v.count("-"),
    ]
