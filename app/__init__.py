import logging
from types import SimpleNamespace

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .ratelimit import RateLimiter
from .security import FieldEncryptor


def create_app(config: Config | None = None, repo=None) -> Flask:
    cfg = config or Config.from_env()
    cfg.validate()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024          # auth payloads are tiny
    app.json.sort_keys = False
    if cfg.trusted_proxy_count:                            # trust X-Forwarded-For only behind known proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=cfg.trusted_proxy_count, x_proto=cfg.trusted_proxy_count)

    if repo is None:
        from .repository import PostgresRepository
        repo = PostgresRepository(cfg.database_url)

    app.extensions["auth"] = SimpleNamespace(
        cfg=cfg, repo=repo, encryptor=FieldEncryptor(cfg.encryption_keys),
        limiter=RateLimiter(cfg.rate_limit_per_minute) if cfg.rate_limit_per_minute > 0 else None,
    )

    from .auth import bp, err
    app.register_blueprint(bp)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        resp.headers["Cache-Control"] = "no-store"          # never cache tokens or profile data
        if cfg.hsts:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(HTTPException)
    def http_error(e):
        return err(e.code, e.name.lower().replace(" ", "_"), e.description)

    @app.errorhandler(Exception)
    def unexpected(e):
        app.logger.exception("Unhandled error")           # details go to logs, never to the client
        return err(500, "server_error", "Something went wrong.")

    @app.cli.command("init-db")
    def init_db():
        """Create tables from schema.sql."""
        repo.init_schema()
        print("Schema applied.")

    @app.cli.command("purge-sessions")
    def purge_sessions():
        """Delete sessions that expired more than 30 days ago."""
        print(f"Deleted {repo.purge_old_sessions()} sessions.")

    logging.getLogger("werkzeug").setLevel(logging.INFO)
    return app
