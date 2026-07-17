"""
Élection de leader pour les déploiements HA actif-passif.

Sur PostgreSQL, un verrou consultatif (`pg_try_advisory_lock`) est acquis
sur une connexion dédiée conservée pour la durée de vie du processus — les
verrous consultatifs sont liés à la session, donc si le processus leader
meurt, PostgreSQL libère automatiquement le verrou et un autre réplique peut
l'acquérir à son prochain démarrage.

Sur SQLite (tests, déploiement mono-instance), `pg_try_advisory_lock`
n'existe pas — ce réplique est toujours considéré comme leader.

En cas d'erreur inattendue (permissions, etc.), on bascule en mode
"fail-open" (leader=True) pour qu'un déploiement mono-instance reste
pleinement fonctionnel.
"""
import logging
import socket
import uuid

from sqlalchemy import text

from db.engine import get_engine

logger = logging.getLogger("leader_election")

LOCK_KEY = 0x72_65_70_6f_64  # bigint arbitraire ("repod" packé)
INSTANCE_ID = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"

_conn = None
_is_leader = False


def _is_postgres() -> bool:
    return get_engine().dialect.name == "postgresql"


def acquire_leadership() -> bool:
    """
    Appelé une fois au démarrage (lifespan). Retourne True si ce réplique
    est (ou devient) le leader.
    """
    global _conn, _is_leader

    if not _is_postgres():
        _is_leader = True
        return True

    try:
        _conn = get_engine().connect()
        got = _conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_KEY}).scalar()
        _is_leader = bool(got)
        if not _is_leader:
            _conn.close()
            _conn = None
        return _is_leader
    except Exception:
        logger.exception("[ha] Échec de l'élection de leader — fallback : leader")
        _is_leader = True
        return True


def is_leader() -> bool:
    return _is_leader


def release() -> None:
    """Libère le verrou consultatif et ferme la connexion dédiée (arrêt propre)."""
    global _conn, _is_leader

    if _conn is not None:
        try:
            _conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
        except Exception:
            pass
        _conn.close()
        _conn = None
    _is_leader = False


# ── Dépendance FastAPI ────────────────────────────────────────────────────────

from fastapi import HTTPException, status  # noqa: E402


def require_leader() -> None:
    """
    Dépendance FastAPI bloquant les endpoints qui démarrent un job en
    mémoire (sync/mirror/install/scan) sur les répliques passives.
    """
    if not is_leader():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Cette instance est une réplique passive — réessayez sur "
                "l'instance leader (voir GET /health → info.ha.is_leader)."
            ),
        )
