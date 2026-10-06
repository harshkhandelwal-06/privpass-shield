from __future__ import annotations
import base64, hashlib, hmac, os, secrets, time, uuid
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher
from .config import APP_SECRET, COOKIE_SECURE, SESSION_MINUTES

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
MASTER_KEY = hashlib.sha256(APP_SECRET.encode()).digest()

def uid() -> str: return str(uuid.uuid4())
def b64e(b: bytes) -> str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def b64d(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha256_hex(v: bytes | str) -> str:
    return hashlib.sha256(v if isinstance(v, bytes) else v.encode()).hexdigest()
def hmac_hex(key: bytes | str, msg: bytes | str) -> str:
    k = key if isinstance(key, bytes) else key.encode(); m = msg if isinstance(msg, bytes) else msg.encode()
    return hmac.new(k, m, hashlib.sha256).hexdigest()

def encrypt_verifier(verifier_b64: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(MASTER_KEY).encrypt(nonce, verifier_b64.encode(), None)
    return b64e(nonce + ct)

def decrypt_verifier(ciphertext: str) -> bytes:
    raw = b64d(ciphertext)
    return AESGCM(MASTER_KEY).decrypt(raw[:12], raw[12:], None)

def verifier_integrity(verifier_b64: str) -> str:
    return ph.hash(verifier_b64)

def verify_verifier_hash(stored: str, verifier_b64: str) -> bool:
    try: return ph.verify(stored, verifier_b64)
    except Exception: return False

def new_session_token() -> str: return secrets.token_urlsafe(48)
def token_hash(token: str) -> str: return sha256_hex(token)
def csrf_token() -> str: return secrets.token_urlsafe(32)
def session_expiry() -> datetime: return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=SESSION_MINUTES)

def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://api.pwnedpasswords.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https://api.pwnedpasswords.com; frame-ancestors 'none'; base-uri 'self'"
    return response

def cookie_kwargs():
    return {"httponly": True, "secure": COOKIE_SECURE, "samesite": "lax", "path": "/"}

def require_same_origin(request) -> None:
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("host", "")
        if origin.rstrip("/").split("//")[-1] != host:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="cross-origin request blocked")

BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip('=')
def totp_code(secret: str, for_time: int | None = None) -> str:
    raw = base64.b32decode(secret + '=' * (-len(secret)%8))
    counter = int((for_time or int(time.time())) // 30)
    msg = counter.to_bytes(8,'big')
    digest = hmac.new(raw,msg,hashlib.sha1).digest()
    off = digest[-1] & 15
    num = ((digest[off] & 0x7f)<<24) | (digest[off+1]<<16) | (digest[off+2]<<8) | digest[off+3]
    return str(num % 1000000).zfill(6)
def verify_totp(secret: str, code: str) -> bool:
    try:
        for drift in (-30,0,30):
            if hmac.compare_digest(totp_code(secret,int(time.time())+drift),code): return True
    except Exception: pass
    return False
