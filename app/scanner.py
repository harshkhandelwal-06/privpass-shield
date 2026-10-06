from __future__ import annotations

import fnmatch
import hashlib
import hmac
import io
import json
import math
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

MAX_FILES = 5000
MAX_UNCOMPRESSED = 50 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
TEXT_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".env", ".ini", ".cfg",
    ".toml", ".txt", ".md", ".sql", ".sh", ".ps1", ".java", ".go", ".rs", ".php", ".rb",
    ".cs", ".xml", ".properties", ".conf", ".pem", ".key", ".gradle", ".properties"
}
IGNORE_PARTS = {".git", "node_modules", ".venv", "__pycache__", ".next", "dist", "build", ".pytest_cache", "coverage"}
PLACEHOLDER_WORDS = {
    "example", "example-key", "changeme", "change-me", "replace-me", "your-key", "your_token", "dummy",
    "sample", "test-key", "not-a-real-key", "not_real", "redacted", "null", "none", "undefined",
    "this-is-a-placeholder", "placeholder", "placeholder-value"
}

PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("AWS temporary access key", re.compile(r"\bASIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "CRITICAL"),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"), "CRITICAL"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "HIGH"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "HIGH"),
    ("OpenAI API key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"), "CRITICAL"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}\b"), "HIGH"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "CRITICAL"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "HIGH"),
    ("Connection string", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+"), "HIGH"),
    ("Azure/SAS-style secret", re.compile(r"(?i)\b(?:sig|sv|se|sp|skoid|skt)=[A-Za-z0-9%+/=._-]{10,}"), "HIGH"),
    ("Generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret|access[_-]?token)\b\s*[:=]\s*['\"]([^'\"\s]{10,})['\"]"), "MEDIUM"),
]

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Values published in vendor documentation. They match provider formats but are never live,
# so they are reported as LOW / non-blocking instead of CRITICAL (false-positive control).
KNOWN_EXAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE", "ASIAIOSFODNN7EXAMPLE",  # secretguard:allow (vendor docs)
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",  # secretguard:allow
}

# Inline suppression markers (compatible with common tools) for reviewed, intentional test data.
INLINE_ALLOW = re.compile(r"secretguard:\s*allow|pragma:\s*allowlist\s+secret|gitleaks:allow", re.I)

IGNORE_FILE = ".secretguardignore"

# Risky code patterns (the "Secure Code Checker" half of the brief). Regexes are written with
# \s* so this file's own rule definitions never match themselves.
CODE_RULES = [
    ("Risky: subprocess with shell=True", re.compile(r"\bsubprocess\.\w+\(.*\bshell\s*=\s*True"), "HIGH", {".py"},
     "Pass an argument list and keep shell=False; shell=True turns any interpolated value into command injection."),
    ("Risky: os.system call", re.compile(r"\bos\.system\s*\("), "MEDIUM", {".py"},
     "Use subprocess.run([...]) with an argument list instead of a shell string."),
    ("Risky: eval/exec of dynamic code", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(\s*(?![\'\"])"), "HIGH", {".py", ".js", ".ts", ".jsx", ".tsx"},
     "Never evaluate strings built from input; parse data with json/ast.literal_eval or an explicit dispatcher."),
    ("Risky: TLS verification disabled", re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), "HIGH", {".py", ".js", ".ts", ".env", ".yml", ".yaml"},
     "Keep certificate verification on; pin a CA bundle if you need a private CA."),
    ("Risky: unsafe deserialization", re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)"), "MEDIUM", {".py"},
     "Use yaml.safe_load / JSON for untrusted data; pickle executes code on load."),
    ("Risky: SQL built from strings", re.compile(r"\.execute(?:many)?\s*\(\s*(?:f[\'\"]|[\'\"][^\'\"]*[\'\"]\s*(?:%|\+|\.format))", re.I), "HIGH", {".py"},
     "Use parameterised queries (cursor.execute(sql, params)) or the ORM; string-built SQL enables injection."),
    ("Risky: weak hash for passwords", re.compile(r"\b(?:md5|sha1)\s*\(.*pass(?:word|wd)?", re.I), "MEDIUM", {".py", ".js", ".ts", ".php"},
     "Store passwords with Argon2id, scrypt or bcrypt - never a fast hash."),
    ("Risky: debug mode enabled", re.compile(r"\.run\s*\(.*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b"), "MEDIUM", {".py"},
     "Drive debug mode from configuration and keep it off in production (debuggers allow code execution)."),
    ("Risky: JWT signature not verified", re.compile(r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]", re.I), "HIGH", {".py", ".js", ".ts"},
     "Always verify JWT signatures with an explicit algorithm allow-list."),
    ("Risky: Math.random for secrets", re.compile(r"Math\.random\s*\(\).*(?:token|secret|password|key|otp)|(?:token|secret|password|otp)\w*\s*=.*Math\.random\s*\(", re.I), "MEDIUM", {".js", ".ts", ".jsx", ".tsx"},
     "Use crypto.getRandomValues / crypto.randomBytes for anything security-sensitive."),
    ("Risky: child_process exec", re.compile(r"\bchild_process\b.*\.exec\s*\(|\bexecSync\s*\("), "MEDIUM", {".js", ".ts"},
     "Prefer execFile/spawn with an argument array so input cannot become shell syntax."),
]


@dataclass(frozen=True)
class Finding:
    file_path: str
    line_no: int
    secret_type: str
    severity: str
    confidence: float
    fingerprint: str
    redacted_preview: str
    reason: str
    entropy: float = 0.0
    validity: str = "UNKNOWN"
    kind: str = "secret"                 # "secret" | "code"
    commit: str | None = None            # history mode: commit that introduced the value
    author: str | None = None
    commit_date: str | None = None
    commits_seen: int = 0                # history mode: how many commits add this value
    in_head: bool | None = None          # history mode: still present in HEAD?
    advice: str = ""
    ml_probability: float | None = None  # SecretGuard ML classifier score (None if not scored)
    ml_reasons: tuple[str, ...] = ()     # top SHAP contributions, human readable
    context: str = ""                    # masked +/-3 line snippet (never contains the secret)

    def to_dict(self) -> dict:
        return asdict(self)


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def fingerprint(secret: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()


def redact(value: str) -> str:
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "…" + value[-4:]


def _is_placeholder(secret: str) -> bool:
    low = secret.strip().lower()
    if low in PLACEHOLDER_WORDS:
        return True
    normalized = re.sub(r"[-_\s]+", "_", low)
    return normalized in {"replace_me", "your_secret", "your_secret_here", "your_token_here", "your_api_key", "test_key", "dummy_key", "fake_key"}


def _jwt_structurally_valid(value: str) -> bool:
    pieces = value.split(".")
    if len(pieces) != 3:
        return False
    try:
        decoded = []
        for piece in pieces[:2]:
            padding = "=" * (-len(piece) % 4)
            raw = __import__("base64").urlsafe_b64decode(piece + padding).decode("utf-8")
            decoded.append(json.loads(raw))
        return isinstance(decoded[0], dict) and isinstance(decoded[1], dict)
    except Exception:
        return False


def _connection_structurally_valid(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme.lower() in {"postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis"} and bool(parsed.netloc)
    except Exception:
        return False


def validate_candidate(secret_type: str, secret: str) -> tuple[bool, str]:
    """Cheap offline validity checks; no network calls and no credential testing.

    The detector verifies provider structure only. It intentionally does not call a provider
    to test whether a credential is live, which avoids transmitting secrets from developer machines.
    """
    if _is_placeholder(secret):
        return False, "PLACEHOLDER"
    if secret_type in {"AWS access key", "AWS temporary access key"}:
        return bool(re.fullmatch(r"(?:AKIA|ASIA)[0-9A-Z]{16}", secret)), "AWS_FORMAT_VALID"
    if secret_type == "GitHub token":
        return bool(re.fullmatch(r"(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", secret)), "GITHUB_FORMAT_VALID"
    if secret_type == "GitLab token":
        return bool(re.fullmatch(r"glpat-[A-Za-z0-9_-]{20,}", secret)), "GITLAB_FORMAT_VALID"
    if secret_type == "Stripe secret key":
        return bool(re.fullmatch(r"sk_(?:live|test)_[A-Za-z0-9]{16,}", secret)), "STRIPE_FORMAT_VALID"
    if secret_type == "Slack token":
        return bool(re.fullmatch(r"xox[baprs]-[0-9A-Za-z-]{10,}", secret)), "SLACK_FORMAT_VALID"
    if secret_type == "Google API key":
        return bool(re.fullmatch(r"AIza[0-9A-Za-z_-]{30,}", secret)), "GOOGLE_FORMAT_VALID"
    if secret_type == "OpenAI API key":
        return bool(re.fullmatch(r"sk-proj-[A-Za-z0-9_-]{20,}", secret)), "OPENAI_FORMAT_VALID"
    if secret_type == "Anthropic API key":
        return bool(re.fullmatch(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}", secret)), "ANTHROPIC_FORMAT_VALID"
    if secret_type == "SendGrid API key":
        return bool(re.fullmatch(r"SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}", secret)), "SENDGRID_FORMAT_VALID"
    if secret_type == "JWT":
        valid = _jwt_structurally_valid(secret)
        return valid, "JWT_STRUCTURE_VALID" if valid else "JWT_STRUCTURE_INVALID"
    if secret_type == "Connection string":
        try:
            password = urlparse(secret).password
        except ValueError:
            password = None
        # A URL without an embedded password (redis://redis:6379/0) or with an env placeholder
        # (${DB_PASSWORD}) carries no credential - skip it instead of raising a false positive.
        if not password or password.startswith(("$", "{", "<", "%")) or _is_placeholder(password):
            return False, "PLACEHOLDER"
        valid = _connection_structurally_valid(secret)
        return valid, "CONNECTION_STRING_VALID" if valid else "CONNECTION_STRING_INVALID"
    if secret_type == "Private key":
        return "-----BEGIN" in secret, "PRIVATE_KEY_MARKER"
    if secret_type == "Generic secret assignment":
        return len(secret) >= 10 and not _is_placeholder(secret), "GENERIC_VALUE_PRESENT"
    return True, "FORMAT_MATCH"


def _context_adjustment(path: str, line: str) -> tuple[float, str]:
    low_line = line.lower()
    low_path = path.lower()
    if any(token in low_line for token in ("example", "sample", "dummy", "fake", "fixture", "test_key", "test-key")):
        return -0.16, "test/example context reduces confidence"
    if any(part in low_path for part in ("/docs/", "\\docs\\", "/test/", "\\test\\", "/tests/", "\\tests\\", "fixture")):
        return -0.10, "test/documentation path reduces confidence"
    return 0.0, "source context supports a production-code finding"


Verifier = Callable[[str, str], Optional[str]]


def _mask_line(line: str) -> str:
    """Code-pattern previews show the line, with anything token-like masked."""
    masked = re.sub(r"[A-Za-z0-9_\-/+=]{20,}", lambda m: redact(m.group(0)), line.strip())
    return masked[:160]


def scan_code_line(line: str, path: str, lineno: int, secret_key: str) -> list[Finding]:
    ext = Path(path).suffix.lower() or (".env" if Path(path).name.lower().startswith(".env") else "")
    out: list[Finding] = []
    for name, rx, severity, exts, advice in CODE_RULES:
        if ext not in exts or not rx.search(line):
            continue
        out.append(Finding(
            file_path=path, line_no=lineno, secret_type=name, severity=severity, confidence=0.85,
            fingerprint=fingerprint(f"code:{path}:{name}:{line.strip()}", secret_key),
            redacted_preview=_mask_line(line), reason=f"Risky code pattern; {advice}", entropy=0.0,
            validity="CODE_PATTERN", kind="code", advice=advice,
        ))
    return out


def _scan_text_rules(text: str, path: str, secret_key: str, verifier: Verifier | None = None, include_code: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if INLINE_ALLOW.search(line):
            continue
        if include_code:
            findings.extend(scan_code_line(line, path, lineno, secret_key))
        for secret_type, rx, base_severity in PATTERNS:
            for match in rx.finditer(line):
                severity = base_severity
                secret = match.group(1) if match.lastindex else match.group(0)
                if secret_type == "Generic secret assignment" and (_is_placeholder(secret) or len(secret) < 12):
                    continue
                ent = round(entropy(secret), 3)
                valid, validity = validate_candidate(secret_type, secret)
                if not valid and validity == "PLACEHOLDER":
                    continue
                confidence = 0.58
                if secret_type == "Generic secret assignment":
                    if ent >= 4.0 and len(secret) >= 20:
                        confidence = 0.90
                        reason = "High-entropy secret-like assignment"
                    elif ent >= 3.0 and len(secret) >= 16:
                        confidence = 0.82
                        reason = "Moderate-entropy secret-like assignment"
                    else:
                        confidence = 0.68
                        reason = "Contextual secret-like assignment"
                else:
                    confidence = 0.98 if valid and severity == "CRITICAL" else 0.94 if valid else 0.70
                    reason = f"Recognized {secret_type} format" if valid else f"Possible {secret_type}; structural validity is uncertain"

                adjustment, context_reason = _context_adjustment(path, line)
                confidence = max(0.50, min(0.995, confidence + adjustment))
                reason = f"{reason}; {context_reason}"
                if secret_type == "Generic secret assignment" and ent < 2.5:
                    confidence = min(confidence, 0.66)
                    reason += "; low entropy lowers confidence"
                if secret in KNOWN_EXAMPLE_VALUES or re.fullmatch(r"(?:AKIA|ASIA)[0-9A-Z]{9}EXAMPLE", secret):
                    severity, confidence, validity = "LOW", 0.30, "KNOWN_DOCUMENTATION_EXAMPLE"
                    reason = f"{secret_type} format, but this is a published vendor documentation example (non-blocking)"
                elif verifier is not None:
                    outcome = verifier(secret_type, secret)
                    if outcome == "LIVE_VERIFIED":
                        confidence, validity = 0.999, "LIVE_VERIFIED"
                        reason = f"{reason}; provider confirmed the credential is ACTIVE - rotate immediately"
                    elif outcome == "PROVIDER_REJECTED":
                        confidence, validity = min(confidence, 0.60), "PROVIDER_REJECTED"
                        reason = f"{reason}; provider rejected the credential (revoked/invalid) - remove it, lower priority"
                    elif outcome:
                        validity = f"{validity}+{outcome}"
                findings.append(Finding(
                    file_path=path,
                    line_no=lineno,
                    secret_type=secret_type,
                    severity=severity,
                    confidence=round(confidence, 3),
                    fingerprint=fingerprint(secret, secret_key),
                    redacted_preview=redact(secret),
                    reason=reason,
                    entropy=ent,
                    validity=validity,
                ))
    return findings


ML_ENABLED = os.environ.get("PRIVPASS_DISABLE_ML", "") != "1"


def scan_text(text: str, path: str, secret_key: str, verifier: Verifier | None = None, include_code: bool = True,
              use_ml: bool | None = None, with_context: bool = True) -> list[Finding]:
    """Rules + ML classifier.

    1. The rule engine finds provider-format keys, generic assignments and risky code.
    2. Every quoted literal that is assigned to something becomes an ML candidate. The classifier
       re-scores generic rule hits (confidence := ML probability) and adds secrets the rules missed
       (neutral variable names, hardcoded passwords, hex/base64 secrets) as "Hardcoded secret (ML)".
    3. Each finding gets a masked context snippet for review/AI remediation.
    """
    findings = _scan_text_rules(text, path, secret_key, verifier=verifier, include_code=include_code)
    use_ml = ML_ENABLED if use_ml is None else use_ml
    lines = text.splitlines()
    if use_ml:
        findings = _apply_ml(findings, lines, path, secret_key)
    if with_context and findings:
        from .redaction import masked_context
        findings = [replace(f, context=masked_context(lines, f.line_no)) if 1 <= f.line_no <= len(lines) else f for f in findings]
    return deduplicate(findings)


def _apply_ml(findings: list[Finding], lines: list[str], path: str, secret_key: str) -> list[Finding]:
    try:
        from .ml import secret_model
        from .ml.secret_features import Candidate, extract_candidates
    except Exception:  # pragma: no cover - optional dependency
        return findings
    if not secret_model.available():
        return findings
    cands, where = [], []
    for lineno, line in enumerate(lines, 1):
        if INLINE_ALLOW.search(line) or len(line) > 600:
            continue
        for c in extract_candidates(line, path):
            if _is_placeholder(c.value) or c.value in KNOWN_EXAMPLE_VALUES:
                continue
            prov = any(rx.search(c.value) for name, rx, _ in PATTERNS if name != "Generic secret assignment")
            cands.append(Candidate(c.value, c.name, c.line, c.path, prov)); where.append(lineno)
    if not cands:
        return findings
    scores = secret_model.score(cands)
    cut = secret_model.threshold()
    by_key = {(f.line_no, f.fingerprint): i for i, f in enumerate(findings) if f.kind == "secret"}
    out = list(findings)
    for cand, lineno, (prob, reasons) in zip(cands, where, scores):
        fp = fingerprint(cand.value, secret_key)
        idx = by_key.get((lineno, fp))
        if idx is not None:
            f = out[idx]
            if f.validity == "KNOWN_DOCUMENTATION_EXAMPLE":
                continue
            if f.secret_type == "Generic secret assignment" and f.validity not in {"LIVE_VERIFIED", "PROVIDER_REJECTED"}:
                out[idx] = replace(f, confidence=round(max(0.5, min(0.995, prob)), 3), ml_probability=round(prob, 4), ml_reasons=reasons,
                                   reason=f"{f.reason}; ML classifier probability {prob:.0%}")
            else:
                out[idx] = replace(f, ml_probability=round(prob, 4), ml_reasons=reasons)
        elif prob >= cut and not cand.provider_match:
            # Provider-shaped values the rule engine rejected (placeholders, password-less URLs,
            # documentation examples) stay rejected: ML only adds what the rules could not see.
            ent = round(entropy(cand.value), 3)
            out.append(Finding(
                file_path=path, line_no=lineno, secret_type="Hardcoded secret (ML)", severity="HIGH" if prob >= 0.9 else "MEDIUM",
                confidence=round(min(0.995, prob), 3), fingerprint=fp, redacted_preview=redact(cand.value),
                reason=f"ML classifier probability {prob:.0%} that `{cand.name}` holds a hardcoded credential; rules did not match",
                entropy=ent, validity="ML_CLASSIFIER", ml_probability=round(prob, 4), ml_reasons=reasons,
            ))
    return out


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse overlapping provider+generic matches for the same secret at one location."""
    best: dict[tuple[str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.file_path, finding.line_no, finding.fingerprint)
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        if _SEVERITY_RANK.get(finding.severity, 0) > _SEVERITY_RANK.get(current.severity, 0):
            winner, loser = finding, current
        elif finding.confidence > current.confidence:
            winner, loser = finding, current
        else:
            winner, loser = current, finding
        reason = winner.reason if loser.secret_type == winner.secret_type else f"{winner.reason}; generic assignment also matched"
        best[key] = Finding(**{**winner.to_dict(), "reason": reason})
    return sorted(best.values(), key=lambda f: (f.file_path, f.line_no, -_SEVERITY_RANK.get(f.severity, 0), f.secret_type))


def load_ignore_patterns(text: str | None) -> list[str]:
    """Parse a .secretguardignore file: one glob per line, '#' comments, 'dir/' matches a subtree."""
    patterns: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            line = line.replace("\\", "/")
            patterns.append(line[2:] if line.startswith("./") else line.lstrip("/"))
    return patterns


def is_ignored(path: str, patterns: list[str]) -> bool:
    path = path.replace("\\", "/").lstrip("/")
    for pat in patterns:
        if pat.endswith("/"):
            base = pat.rstrip("/")
            if path == base or path.startswith(base + "/") or fnmatch.fnmatch(path, base + "/*"):
                return True
        elif fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(Path(path).name, pat):
            return True
    return False


def scan_bytes(data: bytes, path: str, secret_key: str, verifier: Verifier | None = None, include_code: bool = True) -> list[Finding]:
    name = Path(path).name.lower()
    ext = Path(path).suffix.lower()
    if len(data) > MAX_FILE_BYTES or (ext not in TEXT_EXTS and not name.startswith(".env")):
        return []
    if b"\x00" in data[:4096]:
        return []
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return []
    return scan_text(text, path, secret_key, verifier=verifier, include_code=include_code)


def scan_dir(root: Path, secret_key: str, verifier: Verifier | None = None, include_code: bool = True) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files = 0
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"directory not found: {root}")
    ignore_file = root / IGNORE_FILE
    ignores = load_ignore_patterns(ignore_file.read_text(encoding="utf-8", errors="ignore")) if ignore_file.is_file() else []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink() or any(part in IGNORE_PARTS for part in path.parts):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if is_ignored(rel, ignores):
            continue
        files += 1
        if files > MAX_FILES:
            raise ValueError(f"directory exceeds maximum of {MAX_FILES} scanned files")
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        findings.extend(scan_bytes(path.read_bytes(), rel, secret_key, verifier, include_code))
    return deduplicate(findings), files


def _zip_git_root(infos: list[zipfile.ZipInfo]) -> str | None:
    """Return the in-archive prefix of a repository whose .git directory was included in the ZIP."""
    for info in infos:
        name = info.filename.replace("\\", "/")
        if name.endswith(".git/HEAD"):
            prefix = name[: -len(".git/HEAD")]
            if prefix.count("/") <= 1:
                return prefix
    return None


def _safe_extract(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], dest: Path) -> None:
    dest = dest.resolve()
    for info in infos:
        name = info.filename.replace("\\", "/")
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:  # symlink entries are never materialised
            continue
        target = (dest / name).resolve()
        if dest not in target.parents and target != dest:
            continue
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out, 1024 * 1024)


def scan_zip(data: bytes, secret_key: str, verifier: Verifier | None = None, include_code: bool = True, history: bool = True) -> tuple[list[Finding], int]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > MAX_FILES:
            raise ValueError("archive has too many files")
        total = sum(max(0, info.file_size) for info in infos)
        if total > MAX_UNCOMPRESSED:
            raise ValueError("archive exceeds decompressed size limit")
        git_prefix = _zip_git_root(infos)
        ignores: list[str] = []
        for info in infos:
            if info.filename.replace("\\", "/") in {IGNORE_FILE, f"{git_prefix or ''}{IGNORE_FILE}"}:
                ignores = load_ignore_patterns(archive.read(info).decode("utf-8", "ignore"))
        findings: list[Finding] = []
        count = 0
        for info in infos:
            path = info.filename.replace("\\", "/")
            if "../" in path or path.startswith("/") or "\x00" in path:
                continue
            if any(part in IGNORE_PARTS for part in path.split("/")):
                continue
            rel = path[len(git_prefix):] if git_prefix and path.startswith(git_prefix) else path
            if is_ignored(rel, ignores):
                continue
            count += 1
            if info.file_size > MAX_FILE_BYTES:
                continue
            findings.extend(scan_bytes(archive.read(info), path, secret_key, verifier, include_code))
        findings = deduplicate(findings)
        if history and git_prefix is not None and git_available():
            with tempfile.TemporaryDirectory(prefix="secretguard-") as tmp:
                _safe_extract(archive, [i for i in archive.infolist()], Path(tmp))
                repo = Path(tmp) / git_prefix if git_prefix else Path(tmp)
                try:
                    hist, _commits = scan_git_history(repo, secret_key, verifier=verifier, include_code=False)
                except ValueError:
                    hist = []
            findings = merge_history(findings, hist, path_prefix=git_prefix or "")
        return findings, count


# ---------------------------------------------------------------------------------------------
# Git integration. Every git invocation is hardened so a hostile repository (e.g. an uploaded ZIP
# containing .git/config) cannot make git run external programs: no pager, no external diff, no
# textconv, no fsmonitor, no signature helpers, no system/global config.
# ---------------------------------------------------------------------------------------------
_GIT_HARDENING = [
    "-c", "core.pager=cat", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
    "-c", "diff.external=", "-c", "log.showSignature=false", "-c", "protocol.allow=never",
    "-c", "safe.directory=*",
]


def git_available() -> bool:
    return shutil.which("git") is not None


def _git(repo: Path, *args: str) -> bytes:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "GIT_EXTERNAL_DIFF": ""}
    env.pop("GIT_DIR", None)
    return subprocess.check_output(["git", *_GIT_HARDENING, "-C", str(repo), *args], env=env, stderr=subprocess.DEVNULL)


def scan_staged_git(root: Path, secret_key: str, verifier: Verifier | None = None, include_code: bool = True) -> tuple[list[Finding], int]:
    """Scan exactly the staged Git index, not uncommitted working-tree contents."""
    root = root.resolve()
    try:
        top = _git(root, "rev-parse", "--show-toplevel").decode().strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("not inside a Git repository or Git is unavailable") from exc
    repo = Path(top).resolve()
    ignore_file = repo / IGNORE_FILE
    ignores = load_ignore_patterns(ignore_file.read_text(encoding="utf-8", errors="ignore")) if ignore_file.is_file() else []
    raw = _git(repo, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR")
    paths = [entry.decode("utf-8", "surrogateescape") for entry in raw.split(b"\0") if entry]
    findings: list[Finding] = []
    scanned = 0
    for rel in paths:
        rel_path = Path(rel)
        if rel_path.is_absolute() or any(part in IGNORE_PARTS for part in rel_path.parts) or is_ignored(rel, ignores):
            continue
        try:
            blob = _git(repo, "cat-file", "-p", f":{rel}")
        except (OSError, subprocess.CalledProcessError):
            continue
        scanned += 1
        if len(blob) <= MAX_FILE_BYTES:
            findings.extend(scan_bytes(blob, rel.replace("\\", "/"), secret_key, verifier, include_code))
    return deduplicate(findings), scanned


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _head_fingerprints(repo: Path, secret_key: str) -> set[str]:
    """Fingerprints of every secret in the HEAD tree (read from git, not the working tree)."""
    try:
        tar_bytes = _git(repo, "archive", "--format=tar", "HEAD")
    except (OSError, subprocess.CalledProcessError):
        return set()
    prints: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size > MAX_FILE_BYTES:
                continue
            handle = tar.extractfile(member)
            if handle:
                prints.update(f.fingerprint for f in scan_bytes(handle.read(), member.name, secret_key, include_code=False))
    return prints


def scan_git_history(root: Path, secret_key: str, verifier: Verifier | None = None, include_code: bool = False,
                     max_commits: int = 5000) -> tuple[list[Finding], int]:
    """Scan every line ever added in any commit on any ref.

    Each unique secret is reported once, at the commit that FIRST introduced it, with how many
    commits add it and whether it is still present in HEAD. A secret deleted in a later commit is
    still reported: deleting a line does not remove it from history - the credential must be rotated.
    """
    root = root.resolve()
    try:
        repo = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip())
        _git(repo, "rev-parse", "--verify", "HEAD")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("not a Git repository with at least one commit (or Git is unavailable)") from exc
    ignore_file = repo / IGNORE_FILE
    ignores = load_ignore_patterns(ignore_file.read_text(encoding="utf-8", errors="ignore")) if ignore_file.is_file() else []
    raw = _git(repo, "log", "--all", f"--max-count={max_commits}", "--no-color", "--no-ext-diff", "--no-textconv",
               "--no-renames", "-p", "--unified=0", "--format=%x00COMMIT%x1f%H%x1f%an%x1f%aI")
    by_print: dict[tuple[str, str], Finding] = {}
    seen_commits: dict[tuple[str, str], set[str]] = {}
    commits = 0
    commit = author = date = None
    path: str | None = None
    new_line = 0
    for raw_line in raw.decode("utf-8", "replace").splitlines():
        if raw_line.startswith("\x00COMMIT\x1f"):
            _tag, commit, author, date = raw_line.split("\x1f", 3)
            commits += 1
            path = None
            continue
        if raw_line.startswith("+++ "):
            target = raw_line[4:].strip()
            path = None if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
            if path and (any(part in IGNORE_PARTS for part in path.split("/")) or is_ignored(path, ignores)
                         or (Path(path).suffix.lower() not in TEXT_EXTS and not Path(path).name.lower().startswith(".env"))):
                path = None
            continue
        if raw_line.startswith("@@"):
            m = _HUNK.match(raw_line)
            new_line = int(m.group(1)) if m else 0
            continue
        if raw_line.startswith("+") and path and commit:
            for finding in scan_text(raw_line[1:], path, secret_key, verifier=verifier, include_code=include_code):
                key = (finding.fingerprint, finding.secret_type)
                seen_commits.setdefault(key, set()).add(commit)
                # git log is newest-first, so the last occurrence we see is the introducing commit.
                by_print[key] = replace(finding, line_no=new_line, commit=commit, author=author, commit_date=date)
            new_line += 1
    head = _head_fingerprints(repo, secret_key)
    results = []
    for key, finding in by_print.items():
        in_head = finding.fingerprint in head
        where = "still present in HEAD" if in_head else "DELETED from HEAD but still in git history"
        results.append(replace(
            finding, commits_seen=len(seen_commits[key]), in_head=in_head,
            reason=f"{finding.reason}; introduced in commit {finding.commit[:10]} by {finding.author} ({(finding.commit_date or '')[:10]}); {where}",
        ))
    results.sort(key=lambda f: (f.in_head is True, -_SEVERITY_RANK.get(f.severity, 0), f.file_path, f.line_no))
    return results, commits


def merge_history(current: list[Finding], history: list[Finding], path_prefix: str = "") -> list[Finding]:
    """Enrich working-tree findings with their introducing commit and append history-only secrets."""
    by_print = {(f.fingerprint, f.secret_type): f for f in history}
    merged: list[Finding] = []
    used: set[tuple[str, str]] = set()
    for finding in current:
        key = (finding.fingerprint, finding.secret_type)
        hist = by_print.get(key)
        if hist:
            used.add(key)
            finding = replace(finding, commit=hist.commit, author=hist.author, commit_date=hist.commit_date,
                              commits_seen=hist.commits_seen, in_head=True)
        merged.append(finding)
    for key, hist in by_print.items():
        if key not in used and not hist.in_head:
            merged.append(replace(hist, file_path=f"{path_prefix}{hist.file_path}"))
    return merged


def rule_id(secret_type: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", secret_type).strip("-").lower()
    return f"PP-SECRET-{slug.upper()}"


def findings_to_sarif(findings: list[Finding], tool_version: str = "6.2.0") -> dict:
    results = []
    for finding in findings:
        stable = hashlib.sha256(f"{finding.file_path}:{finding.line_no}:{finding.secret_type}:{finding.fingerprint}".encode()).hexdigest()
        level = "error" if finding.severity in {"CRITICAL", "HIGH"} else "warning"
        results.append({
            "ruleId": rule_id(finding.secret_type),
            "level": level,
            "message": {"text": f"{finding.secret_type} • confidence {round(finding.confidence * 100)}% • {finding.validity}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}, "region": {"startLine": finding.line_no}}}],
            "partialFingerprints": {"privpassStable": stable},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "entropy": finding.entropy,
                "validity": finding.validity,
                "fingerprint": finding.fingerprint[:16],
                "redactedPreview": finding.redacted_preview,
                "kind": finding.kind,
                "introducedInCommit": finding.commit,
                "commitsSeen": finding.commits_seen,
                "inHead": finding.in_head,
            },
        })
    rules = []
    seen = set()
    for finding in findings:
        rid = rule_id(finding.secret_type)
        if rid in seen:
            continue
        seen.add(rid)
        rules.append({"id": rid, "name": finding.secret_type, "shortDescription": {"text": finding.secret_type}})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "PrivPass SecretGuard", "version": tool_version, "rules": rules}},
            "results": results,
        }],
    }


def findings_to_json(findings: list[Finding], files_scanned: int, mode: str, tool_version: str = "6.2.0") -> dict:
    return {
        "tool": "PrivPass SecretGuard",
        "version": tool_version,
        "mode": mode,
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
