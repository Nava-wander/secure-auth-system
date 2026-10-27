"""Entry point.  Dev: python run.py   |   Prod: gunicorn -w 4 'run:app' (behind a TLS-terminating proxy)."""
import os

try:  # optional convenience: load .env if python-dotenv is installed
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
