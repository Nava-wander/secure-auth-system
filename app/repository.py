"""PostgreSQL storage. Every query is parameterised (no string-built SQL with user input)."""
from contextlib import contextmanager
from pathlib import Path

from .security import next_lock_state, utcnow


class DuplicateEmailError(Exception):
    pass


_PROFILE_COLUMNS = {"full_name_enc", "phone_enc"}  # whitelist for dynamic UPDATE


class PostgresRepository:
    def __init__(self, dsn: str, minconn: int = 1, maxconn: int = 10):
        import psycopg2
        import psycopg2.errors
        import psycopg2.extras
        import psycopg2.pool

        self._pg = psycopg2
        self._extras = psycopg2.extras
        self._pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, dsn)

    # ------------------------------------------------------------ plumbing --
    @contextmanager
    def _cur(self):
        conn = self._pool.getconn()
        try:
            with conn.cursor(cursor_factory=self._extras.RealDictCursor) as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.putconn(conn)

    def init_schema(self):
        sql = (Path(__file__).resolve().parent.parent / "schema.sql").read_text()
        with self._cur() as cur:
            cur.execute(sql)

    def close(self):
        self._pool.closeall()

    # --------------------------------------------------------------- users --
    def create_user(self, email, password_hash, full_name_enc=None, phone_enc=None):
        try:
            with self._cur() as cur:
                cur.execute(
                    "INSERT INTO users (email, password_hash, full_name_enc, phone_enc) "
                    "VALUES (%s, %s, %s, %s) RETURNING *",
                    (email, password_hash, full_name_enc, phone_enc),
                )
                return dict(cur.fetchone())
        except self._pg.errors.UniqueViolation:
            raise DuplicateEmailError(email)

    def get_user_by_email(self, email):
        with self._cur() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id):
        with self._cur() as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def record_failed_login(self, user_id, max_attempts, lock_minutes):
        with self._cur() as cur:  # row lock makes concurrent failures count correctly
            cur.execute("SELECT failed_attempts, locked_until FROM users WHERE id = %s FOR UPDATE", (user_id,))
            row = cur.fetchone()
            if not row:
                return
            attempts, locked = next_lock_state(
                row["failed_attempts"], row["locked_until"], utcnow(), max_attempts, lock_minutes)
            cur.execute("UPDATE users SET failed_attempts = %s, locked_until = %s WHERE id = %s",
                        (attempts, locked, user_id))

    def reset_failed_logins(self, user_id):
        with self._cur() as cur:
            cur.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = %s", (user_id,))

    def update_password(self, user_id, password_hash):
        with self._cur() as cur:
            cur.execute(
                "UPDATE users SET password_hash = %s, password_changed_at = now(), updated_at = now(), "
                "failed_attempts = 0, locked_until = NULL WHERE id = %s", (password_hash, user_id))

    def update_profile(self, user_id, fields: dict):
        fields = {k: v for k, v in fields.items() if k in _PROFILE_COLUMNS}
        if not fields:
            return self.get_user_by_id(user_id)
        assignments = ", ".join(f"{col} = %s" for col in fields)  # column names come from the whitelist
        with self._cur() as cur:
            cur.execute(f"UPDATE users SET {assignments}, updated_at = now() WHERE id = %s RETURNING *",
                        (*fields.values(), user_id))
            row = cur.fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------ sessions --
    def create_session(self, user_id, family_id, refresh_hash, expires_at, user_agent=None, ip=None):
        with self._cur() as cur:
            cur.execute(
                "INSERT INTO sessions (user_id, family_id, refresh_hash, expires_at, user_agent, ip) "
                "VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (user_id, family_id, refresh_hash, expires_at, user_agent, ip))
            return dict(cur.fetchone())

    def get_session(self, session_id):
        with self._cur() as cur:
            cur.execute("SELECT * FROM sessions WHERE id = %s", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_session_by_refresh_hash(self, refresh_hash):
        with self._cur() as cur:
            cur.execute("SELECT * FROM sessions WHERE refresh_hash = %s", (refresh_hash,))
            row = cur.fetchone()
            return dict(row) if row else None

    def revoke_session(self, session_id) -> bool:
        """Atomically revoke; True only for the single caller that actually flipped it."""
        with self._cur() as cur:
            cur.execute("UPDATE sessions SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (session_id,))
            return cur.rowcount == 1

    def revoke_user_session(self, user_id, session_id) -> bool:
        with self._cur() as cur:
            cur.execute("UPDATE sessions SET revoked_at = now() "
                        "WHERE id = %s AND user_id = %s AND revoked_at IS NULL", (session_id, user_id))
            return cur.rowcount == 1

    def revoke_family(self, family_id):
        with self._cur() as cur:
            cur.execute("UPDATE sessions SET revoked_at = now() WHERE family_id = %s AND revoked_at IS NULL",
                        (family_id,))

    def revoke_all_user_sessions(self, user_id):
        with self._cur() as cur:
            cur.execute("UPDATE sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                        (user_id,))

    def list_active_sessions(self, user_id):
        with self._cur() as cur:
            cur.execute("SELECT * FROM sessions WHERE user_id = %s AND revoked_at IS NULL AND expires_at > now() "
                        "ORDER BY created_at DESC", (user_id,))
            return [dict(r) for r in cur.fetchall()]

    def purge_old_sessions(self, older_than_days: int = 30) -> int:
        with self._cur() as cur:
            cur.execute("DELETE FROM sessions WHERE expires_at < now() - make_interval(days => %s)",
                        (older_than_days,))
            return cur.rowcount
