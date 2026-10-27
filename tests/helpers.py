import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.fernet import Fernet  # noqa: E402

from app import create_app  # noqa: E402
from app.config import Config  # noqa: E402

GOOD_PW = "Correct-Horse-Battery-9"


def make_config(**overrides):
    base = dict(secret_key="k" * 48, encryption_keys=(Fernet.generate_key().decode(),),
                bcrypt_rounds=4,                 # bcrypt minimum: keeps tests fast
                rate_limit_per_minute=0, hsts=True)
    base.update(overrides)
    return Config(**base)


def make_app(repo, **overrides):
    app = create_app(make_config(**overrides), repo=repo)
    app.testing = True
    return app


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def register_and_login(client, email="alice@example.com", password=GOOD_PW, **profile):
    r = client.post("/auth/register", json={"email": email, "password": password, **profile})
    assert r.status_code == 201, r.get_json()
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.get_json()
    return r.get_json()
