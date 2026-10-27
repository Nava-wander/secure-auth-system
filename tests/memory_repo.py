"""In-memory repository with the same interface as PostgresRepository (fast tests, no database)."""
import uuid

from app.repository import DuplicateEmailError
from app.security import next_lock_state, utcnow


class MemoryRepository:
    def __init__(self):
        self.users, self.sessions = {}, {}

    def init_schema(self): pass

    def create_user(self, email, password_hash, full_name_enc=None, phone_enc=None):
        if any(u["email"] == email for u in self.users.values()):
            raise DuplicateEmailError(email)
        now = utcnow()
        u = {"id": str(uuid.uuid4()), "email": email, "password_hash": password_hash,
             "full_name_enc": full_name_enc, "phone_enc": phone_enc, "is_active": True,
             "failed_attempts": 0, "locked_until": None, "password_changed_at": now,
             "created_at": now, "updated_at": now}
        self.users[u["id"]] = u
        return dict(u)

    def get_user_by_email(self, email):
        return next((dict(u) for u in self.users.values() if u["email"] == email), None)

    def get_user_by_id(self, user_id):
        u = self.users.get(user_id)
        return dict(u) if u else None

    def record_failed_login(self, user_id, max_attempts, lock_minutes):
        u = self.users[user_id]
        u["failed_attempts"], u["locked_until"] = next_lock_state(
            u["failed_attempts"], u["locked_until"], utcnow(), max_attempts, lock_minutes)

    def reset_failed_logins(self, user_id):
        self.users[user_id].update(failed_attempts=0, locked_until=None)

    def update_password(self, user_id, password_hash):
        self.users[user_id].update(password_hash=password_hash, password_changed_at=utcnow(),
                                   failed_attempts=0, locked_until=None)

    def update_profile(self, user_id, fields):
        self.users[user_id].update({k: v for k, v in fields.items() if k in {"full_name_enc", "phone_enc"}})
        return self.get_user_by_id(user_id)

    def create_session(self, user_id, family_id, refresh_hash, expires_at, user_agent=None, ip=None):
        s = {"id": str(uuid.uuid4()), "user_id": user_id, "family_id": family_id,
             "refresh_hash": refresh_hash, "expires_at": expires_at, "revoked_at": None,
             "user_agent": user_agent, "ip": ip, "created_at": utcnow()}
        self.sessions[s["id"]] = s
        return dict(s)

    def get_session(self, session_id):
        s = self.sessions.get(session_id)
        return dict(s) if s else None

    def get_session_by_refresh_hash(self, refresh_hash):
        return next((dict(s) for s in self.sessions.values() if s["refresh_hash"] == refresh_hash), None)

    def revoke_session(self, session_id):
        s = self.sessions.get(session_id)
        if s and s["revoked_at"] is None:
            s["revoked_at"] = utcnow()
            return True
        return False

    def revoke_user_session(self, user_id, session_id):
        s = self.sessions.get(session_id)
        return bool(s and s["user_id"] == user_id and self.revoke_session(session_id))

    def revoke_family(self, family_id):
        for s in self.sessions.values():
            if s["family_id"] == family_id and s["revoked_at"] is None:
                s["revoked_at"] = utcnow()

    def revoke_all_user_sessions(self, user_id):
        for s in self.sessions.values():
            if s["user_id"] == user_id and s["revoked_at"] is None:
                s["revoked_at"] = utcnow()

    def list_active_sessions(self, user_id):
        now = utcnow()
        return sorted((dict(s) for s in self.sessions.values()
                       if s["user_id"] == user_id and s["revoked_at"] is None and s["expires_at"] > now),
                      key=lambda s: s["created_at"], reverse=True)

    def purge_old_sessions(self, older_than_days=30): return 0
