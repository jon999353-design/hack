"""Top-level entrypoint so `uvicorn main:app` just works for deploy tooling.

The real application lives in ``app/main.py``.
"""
from app.main import app  # noqa: F401
