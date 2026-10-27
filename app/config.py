import os
from dataclasses import dataclass

from cryptography.fernet import Fernet


@dataclass(frozen=True)
class Config:
    secret_key: str
    encryption_keys: tuple
    database_url: str = ""
    jwt_issuer: str = "secure-auth-system"
    jwt_audience: str = "secure-auth-clients"
    access_ttl: int = 15 * 60               # seconds
    refresh_ttl: int = 7 * 24 * 3600        # seconds
    bcrypt_rounds: int = 12
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    rate_limit_per_minute: int = 20         # 0 disables
    trusted_proxy_count: int = 0            # >0 only when behind that many reverse proxies
    hsts: bool = True

    def validate(self) -> None:
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters")
        if not self.encryption_keys:
            raise ValueError("At least one ENCRYPTION_KEY is required")
        for k in self.encryption_keys:
            Fernet(k.encode())  # raises ValueError if the key is malformed
        if not 4 <= self.bcrypt_rounds <= 18:
            raise ValueError("BCRYPT_ROUNDS must be between 4 and 18")

    @classmethod
    def from_env(cls) -> "Config":
        def need(name):
            v = os.environ.get(name, "").strip()
            if not v:
                raise RuntimeError(f"Missing required environment variable {name} (see .env.example)")
            return v

        cfg = cls(
            secret_key=need("SECRET_KEY"),
            encryption_keys=tuple(k.strip() for k in need("ENCRYPTION_KEYS").split(",") if k.strip()),
            database_url=need("DATABASE_URL"),
            access_ttl=int(os.environ.get("ACCESS_TOKEN_TTL", 900)),
            refresh_ttl=int(os.environ.get("REFRESH_TOKEN_TTL", 7 * 24 * 3600)),
            bcrypt_rounds=int(os.environ.get("BCRYPT_ROUNDS", 12)),
            max_failed_logins=int(os.environ.get("MAX_FAILED_LOGINS", 5)),
            lockout_minutes=int(os.environ.get("LOCKOUT_MINUTES", 15)),
            rate_limit_per_minute=int(os.environ.get("RATE_LIMIT_PER_MINUTE", 20)),
            trusted_proxy_count=int(os.environ.get("TRUSTED_PROXY_COUNT", 0)),
        )
        cfg.validate()
        return cfg
