"""
db/engine.py — Moteur SQLAlchemy PostgreSQL partagé.

Remplace tous les `sqlite3.connect()` dispersés dans les services.
Le pool de connexions gère la concurrence — tous les threading.Lock()
liés aux accès DB peuvent être supprimés.

Usage dans les services :
    from db.engine import db_conn
    from sqlalchemy import text

    with db_conn() as conn:
        row = conn.execute(text("SELECT * FROM users WHERE username = :u"), {"u": username}).mappings().fetchone()
        conn.execute(text("UPDATE users SET last_login = :ts WHERE username = :u"), {...})
        # commit automatique en sortie de bloc (autocommit=False + commit dans __exit__)
"""

import logging
import os
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool

logger = logging.getLogger("db.engine")

_engine = None


def get_engine():
    """
    Retourne le moteur SQLAlchemy (singleton).
    Crée l'engine au premier appel depuis DATABASE_URL.
    """
    global _engine
    if _engine is not None:
        return _engine

    url = os.getenv("DATABASE_URL", "")
    if not url:
        raise RuntimeError(
            "DATABASE_URL n'est pas défini. "
            "Ajoutez DATABASE_URL=postgresql://user:pass@host:5432/repod dans backend.env."
        )

    _engine = create_engine(
        url,
        poolclass=QueuePool,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,       # vérifie la connexion avant usage (évite les connexions stales)
        pool_recycle=1800,        # recycle les connexions toutes les 30 min
        echo=os.getenv("SQL_ECHO", "").lower() in ("1", "true"),
    )
    from urllib.parse import urlparse
    _parsed = urlparse(url)
    _safe = f"{_parsed.scheme}://{_parsed.hostname}:{_parsed.port or 5432}/{_parsed.path.lstrip('/')}"
    logger.info("[db] Moteur PostgreSQL initialisé — %s pool_size=10 max_overflow=20", _safe)
    return _engine


@contextmanager
def db_conn():
    """
    Context manager qui fournit une connexion transactionnelle.

    - Commit automatique en fin de bloc si aucune exception.
    - Rollback automatique en cas d'exception.
    - La connexion est rendue au pool à la sortie du bloc.

    Usage :
        with db_conn() as conn:
            conn.execute(text("INSERT INTO ..."), {...})
            # commit implicite ici
    """
    engine = get_engine()
    with engine.begin() as conn:
        yield conn


def check_connection() -> dict:
    """
    Vérifie que la connexion PostgreSQL est opérationnelle.
    Retourne {"ok": bool, "error": str | None}.
    Utilisé par le health check.
    """
    try:
        with db_conn() as conn:
            conn.execute(text("SELECT 1"))
        return {"ok": True, "error": None}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
