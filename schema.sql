-- PostgreSQL 13+ (gen_random_uuid is built in)
CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash       TEXT NOT NULL,            -- bcrypt, never the password
    full_name_enc       TEXT,                     -- Fernet-encrypted at the application layer
    phone_enc           TEXT,                     -- Fernet-encrypted at the application layer
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per refresh token. The row id is the "sid" claim inside the access token.
CREATE TABLE IF NOT EXISTS sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id    UUID NOT NULL,                   -- all rotations of one login share a family
    refresh_hash CHAR(64) NOT NULL UNIQUE,        -- SHA-256 of the opaque refresh token
    user_agent   TEXT,
    ip           TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_family ON sessions(family_id);
