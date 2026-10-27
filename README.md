# Secure Authentication System

Flask REST API for secure user registration, login and session management using **JWT access tokens**, **rotating refresh tokens**, **bcrypt** password hashing, **Fernet field encryption**, and **PostgreSQL**.

## Security design

| Concern | What this project does |
|---|---|
| Password storage | bcrypt (cost 12) over a SHA-256 prehash, so passwords longer than 72 bytes aren't silently truncated. Hashes are upgraded automatically if you raise the cost. |
| Password policy | 12-128 chars, 3 of 4 character classes, common/guessable passwords and the email name rejected. |
| Access tokens | Short-lived (15 min) HS256 JWT with `iss`, `aud`, `sub`, `sid`, `jti`, `iat`, `nbf`, `exp`. The algorithm is pinned, so `alg: none` and confusion attacks fail; all claims are required. |
| Sessions | The `sid` claim points to a server-side session row. Every request checks the session is active, so **logout and revocation take effect immediately**, not when the JWT expires. |
| Refresh tokens | Opaque 384-bit random tokens, stored only as SHA-256 hashes. **Rotated on every use**; reusing an old one revokes the whole login chain (theft detection). |
| Brute force | Per-account lockout (5 failures -> 15 min) plus per-IP rate limiting on auth endpoints. |
| User enumeration | Login returns one identical `401` for unknown user, wrong password, or locked account, and does one bcrypt check on every path to keep timing uniform. |
| Encryption at rest | `full_name` and `phone` are Fernet-encrypted (AES + HMAC) before reaching the database. Supports key rotation via `ENCRYPTION_KEYS=new,old`. |
| SQL injection | All queries are parameterised; the one dynamic `UPDATE` uses a column whitelist. |
| Mass assignment | `PATCH /auth/me` only accepts `full_name` and `phone`. |
| Transport / headers | HSTS, `nosniff`, `X-Frame-Options: DENY`, CSP `default-src 'none'`, `Cache-Control: no-store`. Run behind HTTPS. |
| Errors | Uniform JSON errors; stack traces go to logs, never to clients. 16 KB request body cap. |
| Secrets | Read from environment; the app refuses to start with a missing/short `SECRET_KEY` or invalid encryption key. |

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

docker compose up -d                       # PostgreSQL 16, schema.sql applied automatically
cp .env.example .env                       # then fill in the two keys:
python -c "import secrets; print(secrets.token_urlsafe(64))"                         # SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # ENCRYPTION_KEYS

set -a; source .env; set +a
python run.py                              # http://127.0.0.1:5000
# production: gunicorn -w 4 'run:app'  (behind a TLS-terminating proxy; set TRUSTED_PROXY_COUNT)
```
Without Docker, create a database yourself and run `flask --app run init-db`.

## API
| Method & path | Auth | Description |
|---|---|---|
| `POST /auth/register` | - | `{email, password, full_name?, phone?}` -> `201` |
| `POST /auth/login` | - | `{email, password}` -> `access_token`, `refresh_token`, `user` |
| `POST /auth/refresh` | - | `{refresh_token}` -> new token pair (old refresh token is burned) |
| `POST /auth/logout` | Bearer | Revoke this login (access + refresh) |
| `POST /auth/logout-all` | Bearer | Revoke every session of the user |
| `GET /auth/me` | Bearer | Current profile (decrypted) |
| `PATCH /auth/me` | Bearer | Update `full_name`, `phone` |
| `POST /auth/change-password` | Bearer | `{current_password, new_password}`; revokes all sessions |
| `GET /auth/sessions` | Bearer | List active sessions/devices |
| `DELETE /auth/sessions/<id>` | Bearer | Revoke one session |
| `GET /health` | - | Liveness check |

```bash
curl -s -X POST localhost:5000/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Correct-Horse-Battery-9","full_name":"Alice"}'

curl -s -X POST localhost:5000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"Correct-Horse-Battery-9"}'

curl -s localhost:5000/auth/me -H "Authorization: Bearer $ACCESS_TOKEN"
```
Clients should keep the access token in memory and the refresh token in secure storage (mobile keychain, or an HttpOnly cookie if you add a browser front end), call `/auth/refresh` when the access token expires, and handle `401` by logging in again.

## Project layout
```
app/__init__.py     app factory, security headers, error handlers, CLI (init-db, purge-sessions)
app/auth.py         routes, login_required, rate limiting
app/security.py     bcrypt, JWT, refresh tokens, password policy, Fernet encryption, lockout logic
app/repository.py   PostgreSQL data access (psycopg2, connection pool)
app/ratelimit.py    sliding-window limiter
schema.sql          users + sessions tables
tests/              unit + API tests (in-memory repo) and PostgreSQL integration tests
```

## Tests
```bash
python -m unittest discover -s tests -t . -v          # 37 tests, no database needed (3 skipped)

# integration tests against real PostgreSQL (truncates the tables - use a throwaway DB):
TEST_DATABASE_URL=postgresql://auth_user:change-me@localhost:5432/auth_db \
  python -m unittest tests.test_postgres -v
```

## Trade-offs and next steps
- `409 email_taken` on registration reveals that an email is registered. Hiding it needs email-based verification (send "you already have an account" instead).
- The rate limiter is in-process; with multiple workers/servers switch to a shared store such as Redis.
- Two tabs refreshing with the same token at the same instant looks like token reuse and logs the user out. This is the deliberate cost of theft detection.
- Refresh lifetime is sliding (7 days per use). Add an absolute cap if you need one.
- Not included: email verification, password reset, MFA, JWT key rotation (`kid`), audit logging. These are the natural next features.
- Run `flask --app run purge-sessions` periodically (cron) to delete old session rows.
