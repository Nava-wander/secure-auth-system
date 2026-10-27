"""Cryptographic and validation helpers: passwords, JWTs, refresh tokens, field encryption."""
import base64
import hashlib
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet

JWT_ALG = "HS256"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------- passwords --
def _prehash(password: str) -> bytes:
    # bcrypt silently truncates at 72 bytes; SHA-256 + base64 (44 bytes) avoids that
    # and makes long passphrases safe. base64 output never contains NUL bytes.
    return base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())


def hash_password(password: str, rounds: int = 12) -> str:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prehash(password), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def needs_rehash(hashed: str, rounds: int) -> bool:
    try:
        return int(hashed.split("$")[2]) < rounds
    except (IndexError, ValueError):
        return True


_dummy_hash = None


def dummy_verify(password: str, rounds: int) -> None:
    """Burn the same CPU as a real check so unknown users can't be spotted by timing."""
    global _dummy_hash
    if _dummy_hash is None or needs_rehash(_dummy_hash, rounds):
        _dummy_hash = hash_password(secrets.token_urlsafe(16), rounds)
    verify_password(password, _dummy_hash)


COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "qwerty", "qwertyuiop", "letmein",
    "welcome", "welcome1", "admin", "administrator", "iloveyou", "123456", "12345678",
    "123456789", "1234567890", "111111", "abc123", "monkey", "dragon", "football", "baseball",
    "changeme", "trustno1", "sunshine", "princess", "master", "login", "starwars", "whatever",
}


def password_problems(password, email: str = "") -> list:
    if not isinstance(password, str):
        return ["Password is required."]
    problems = []
    if len(password) < 12:
        problems.append("Must be at least 12 characters.")
    if len(password) > 128:
        problems.append("Must be at most 128 characters.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        problems.append("Use at least 3 of: lowercase, uppercase, digits, symbols.")
    squashed = re.sub(r"[^a-z0-9]", "", password.lower())
    if squashed in COMMON_PASSWORDS or any(c in squashed for c in ("password", "qwerty", "123456")):
        problems.append("Too common or guessable.")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 4 and local in password.lower():
        problems.append("Must not contain your email name.")
    return problems


# ------------------------------------------------------------- validation --
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{7,20}$")


def normalize_email(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if len(value) <= 254 and EMAIL_RE.match(value) else None


# ------------------------------------------------------------------- JWT ---
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "sub", "sid", "jti", "iss", "aud"]


def create_access_token(cfg, user_id: str, session_id: str, now=None):
    now = now or utcnow()
    payload = {
        "iss": cfg.jwt_issuer, "aud": cfg.jwt_audience, "typ": "access",
        "sub": user_id, "sid": session_id, "jti": uuid.uuid4().hex,
        "iat": now, "nbf": now, "exp": now + timedelta(seconds=cfg.access_ttl),
    }
    return jwt.encode(payload, cfg.secret_key, algorithm=JWT_ALG), cfg.access_ttl


def decode_access_token(cfg, token: str) -> dict:
    """Verify signature, expiry, issuer, audience and required claims.

    The algorithm list is pinned, so `alg: none` and algorithm-confusion tokens are rejected.
    Raises jwt.InvalidTokenError on any problem.
    """
    claims = jwt.decode(
        token, cfg.secret_key, algorithms=[JWT_ALG], audience=cfg.jwt_audience,
        issuer=cfg.jwt_issuer, leeway=5, options={"require": REQUIRED_CLAIMS},
    )
    if claims.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return claims


# ---------------------------------------------------------- refresh tokens --
def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)  # 384 bits, opaque


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ------------------------------------------------------ lockout (shared) ----
def is_locked(user: dict, now) -> bool:
    return bool(user.get("locked_until") and user["locked_until"] > now)


def next_lock_state(attempts: int, locked_until, now, max_attempts: int, lock_minutes: int):
    if locked_until and locked_until <= now:       # previous lock expired -> fresh start
        attempts, locked_until = 0, None
    attempts += 1
    if attempts >= max_attempts:
        locked_until = now + timedelta(minutes=lock_minutes)
    return attempts, locked_until


def session_is_active(session: dict, now) -> bool:
    return bool(session) and session["revoked_at"] is None and session["expires_at"] > now


# ------------------------------------------------------ field encryption ----
class FieldEncryptor:
    """Fernet (AES-128-CBC + HMAC-SHA256) with key rotation via MultiFernet."""

    def __init__(self, keys):
        self._f = MultiFernet([Fernet(k.encode()) for k in keys])

    def encrypt(self, value):
        return None if value is None else self._f.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, token):
        if token is None:
            return None
        try:
            return self._f.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None
