"""Authentication blueprint: register, login, refresh, logout, profile, sessions."""
import uuid
from datetime import timedelta
from functools import wraps

import jwt
from flask import Blueprint, current_app, g, jsonify, request

from . import security as sec
from .repository import DuplicateEmailError

bp = Blueprint("auth", __name__, url_prefix="/auth")

INVALID_CREDENTIALS = "Invalid credentials."


# ----------------------------------------------------------------- helpers --
def _ext():
    return current_app.extensions["auth"]


def err(status: int, code: str, message: str, **extra):
    resp = jsonify({"error": code, "message": message, **extra})
    resp.status_code = status
    return resp


def _unauthorized(message="Authentication required."):
    resp = err(401, "unauthorized", message)
    resp.headers["WWW-Authenticate"] = 'Bearer realm="api"'
    return resp


def _json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _public_user(user: dict) -> dict:
    enc = _ext().encryptor
    return {
        "id": user["id"],
        "email": user["email"],
        "full_name": enc.decrypt(user.get("full_name_enc")),
        "phone": enc.decrypt(user.get("phone_enc")),
        "created_at": user["created_at"].isoformat(),
    }


def _issue_tokens(user: dict, family_id: str | None = None) -> dict:
    ext = _ext()
    now = sec.utcnow()
    refresh = sec.new_refresh_token()
    session = ext.repo.create_session(
        user["id"], family_id or str(uuid.uuid4()), sec.hash_token(refresh),
        now + timedelta(seconds=ext.cfg.refresh_ttl),
        (request.headers.get("User-Agent") or "")[:255], request.remote_addr,
    )
    access, ttl = sec.create_access_token(ext.cfg, user["id"], session["id"], now)
    return {
        "token_type": "Bearer", "access_token": access, "expires_in": ttl,
        "refresh_token": refresh, "refresh_expires_in": ext.cfg.refresh_ttl,
    }


def rate_limited(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        limiter = _ext().limiter
        if limiter and not limiter.allow(f"{view.__name__}:{request.remote_addr}"):
            resp = err(429, "rate_limited", "Too many requests. Try again shortly.")
            resp.headers["Retry-After"] = "60"
            return resp
        return view(*args, **kwargs)
    return wrapper


def login_required(view):
    """Validates the Bearer JWT *and* that its server-side session is still active."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        ext = _ext()
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return _unauthorized()
        try:
            claims = sec.decode_access_token(ext.cfg, token.strip())
        except jwt.ExpiredSignatureError:
            return _unauthorized("Token expired.")
        except jwt.InvalidTokenError:
            return _unauthorized("Invalid token.")

        try:
            session = ext.repo.get_session(claims["sid"])
            user = ext.repo.get_user_by_id(claims["sub"])
        except Exception:  # malformed ids etc. -> treat as invalid, never 500 on attacker input
            return _unauthorized("Invalid token.")
        if (not sec.session_is_active(session, sec.utcnow()) or not user
                or session["user_id"] != user["id"] or not user["is_active"]):
            return _unauthorized("Session is no longer valid.")
        g.user, g.session = user, session
        return view(*args, **kwargs)
    return wrapper


def _validate_profile(data: dict, errors: dict) -> dict:
    """Returns encrypted-column updates for the optional full_name / phone fields."""
    enc, out = _ext().encryptor, {}
    if "full_name" in data:
        v = data["full_name"]
        if v is None or v == "":
            out["full_name_enc"] = None
        elif isinstance(v, str) and 1 <= len(v.strip()) <= 100:
            out["full_name_enc"] = enc.encrypt(v.strip())
        else:
            errors["full_name"] = ["Must be a string of 1-100 characters."]
    if "phone" in data:
        v = data["phone"]
        if v is None or v == "":
            out["phone_enc"] = None
        elif isinstance(v, str) and sec.PHONE_RE.match(v.strip()):
            out["phone_enc"] = enc.encrypt(v.strip())
        else:
            errors["phone"] = ["Invalid phone number."]
    return out


# ------------------------------------------------------------------ routes --
@bp.post("/register")
@rate_limited
def register():
    ext, data = _ext(), _json_body()
    if data is None:
        return err(400, "invalid_request", "Body must be a JSON object.")

    errors = {}
    email = sec.normalize_email(data.get("email"))
    if not email:
        errors["email"] = ["A valid email is required."]
    problems = sec.password_problems(data.get("password"), email or "")
    if problems:
        errors["password"] = problems
    profile = _validate_profile(data, errors)
    if errors:
        return err(400, "validation_failed", "Please fix the highlighted fields.", details=errors)

    password_hash = sec.hash_password(data["password"], ext.cfg.bcrypt_rounds)
    try:
        user = ext.repo.create_user(email, password_hash, profile.get("full_name_enc"), profile.get("phone_enc"))
    except DuplicateEmailError:
        return err(409, "email_taken", "An account with this email already exists.")
    return jsonify({"user": _public_user(user)}), 201


@bp.post("/login")
@rate_limited
def login():
    ext, data = _ext(), _json_body()
    if data is None:
        return err(400, "invalid_request", "Body must be a JSON object.")
    email, password = sec.normalize_email(data.get("email")), data.get("password")
    if not email or not isinstance(password, str) or not 0 < len(password) <= 128:
        sec.dummy_verify("x", ext.cfg.bcrypt_rounds)
        return _unauthorized(INVALID_CREDENTIALS)

    now = sec.utcnow()
    user = ext.repo.get_user_by_email(email)
    # One bcrypt run on every path (unknown user / locked / wrong password) -> uniform timing,
    # and one uniform response so attackers cannot tell which case they hit.
    if not user or sec.is_locked(user, now) or not user["is_active"]:
        sec.dummy_verify(password, ext.cfg.bcrypt_rounds)
        return _unauthorized(INVALID_CREDENTIALS)

    if not sec.verify_password(password, user["password_hash"]):
        ext.repo.record_failed_login(user["id"], ext.cfg.max_failed_logins, ext.cfg.lockout_minutes)
        return _unauthorized(INVALID_CREDENTIALS)

    ext.repo.reset_failed_logins(user["id"])
    if sec.needs_rehash(user["password_hash"], ext.cfg.bcrypt_rounds):  # transparently upgrade cost
        ext.repo.update_password(user["id"], sec.hash_password(password, ext.cfg.bcrypt_rounds))
    return jsonify({**_issue_tokens(user), "user": _public_user(user)})


@bp.post("/refresh")
@rate_limited
def refresh():
    """Rotate the refresh token. Presenting an already-used token revokes the whole login chain."""
    ext, data = _ext(), _json_body()
    token = data.get("refresh_token") if data else None
    if not isinstance(token, str) or not 20 <= len(token) <= 256:
        return err(400, "invalid_request", "refresh_token is required.")

    session = ext.repo.get_session_by_refresh_hash(sec.hash_token(token))
    if not session:
        return _unauthorized("Invalid refresh token.")
    if session["revoked_at"] is not None:            # reuse of a rotated/revoked token => possible theft
        ext.repo.revoke_family(session["family_id"])
        return _unauthorized("Refresh token no longer valid.")
    if session["expires_at"] <= sec.utcnow():
        return _unauthorized("Refresh token expired.")
    if not ext.repo.revoke_session(session["id"]):   # lost a race with another use of the same token
        ext.repo.revoke_family(session["family_id"])
        return _unauthorized("Refresh token no longer valid.")

    user = ext.repo.get_user_by_id(session["user_id"])
    if not user or not user["is_active"]:
        return _unauthorized("Account unavailable.")
    return jsonify(_issue_tokens(user, family_id=session["family_id"]))


@bp.post("/logout")
@login_required
def logout():
    _ext().repo.revoke_family(g.session["family_id"])
    return jsonify({"message": "Logged out."})


@bp.post("/logout-all")
@login_required
def logout_all():
    _ext().repo.revoke_all_user_sessions(g.user["id"])
    return jsonify({"message": "Logged out of all devices."})


@bp.get("/me")
@login_required
def me():
    return jsonify({"user": _public_user(g.user)})


@bp.patch("/me")
@login_required
def update_me():
    data = _json_body()
    if data is None:
        return err(400, "invalid_request", "Body must be a JSON object.")
    errors = {}
    updates = _validate_profile(data, errors)
    if errors:
        return err(400, "validation_failed", "Please fix the highlighted fields.", details=errors)
    user = _ext().repo.update_profile(g.user["id"], updates)
    return jsonify({"user": _public_user(user)})


@bp.post("/change-password")
@login_required
@rate_limited
def change_password():
    ext, data = _ext(), _json_body()
    if data is None:
        return err(400, "invalid_request", "Body must be a JSON object.")
    current, new = data.get("current_password"), data.get("new_password")
    if not isinstance(current, str) or not sec.verify_password(current, g.user["password_hash"]):
        return err(403, "wrong_password", "Current password is incorrect.")
    problems = sec.password_problems(new, g.user["email"])
    if isinstance(new, str) and new == current:
        problems.append("Must differ from the current password.")
    if problems:
        return err(400, "validation_failed", "New password rejected.", details={"new_password": problems})
    ext.repo.update_password(g.user["id"], sec.hash_password(new, ext.cfg.bcrypt_rounds))
    ext.repo.revoke_all_user_sessions(g.user["id"])  # force re-login everywhere
    return jsonify({"message": "Password changed. Please log in again."})


@bp.get("/sessions")
@login_required
def list_sessions():
    rows = _ext().repo.list_active_sessions(g.user["id"])
    return jsonify({"sessions": [
        {"id": s["id"], "created_at": s["created_at"].isoformat(), "expires_at": s["expires_at"].isoformat(),
         "ip": s["ip"], "user_agent": s["user_agent"], "current": s["id"] == g.session["id"]}
        for s in rows]})


@bp.delete("/sessions/<session_id>")
@login_required
def revoke_session(session_id):
    try:
        uuid.UUID(session_id)
    except ValueError:
        return err(404, "not_found", "Session not found.")
    if not _ext().repo.revoke_user_session(g.user["id"], session_id):
        return err(404, "not_found", "Session not found.")
    return jsonify({"message": "Session revoked."})
