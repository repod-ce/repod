# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
auth/token_revocation.py — Révocation de JWT (logout / compromission de compte).

Les JWT sont par nature stateless : un token signé reste valide jusqu'à son
`exp`, même après un logout. Pour permettre une révocation immédiate, chaque
JWT créé par `create_access_token()` embarque désormais un claim `jti`
(JWT ID, identifiant aléatoire unique).

`POST /auth/logout` insère ce `jti` dans la table `revoked_tokens`, avec
comme `expires_at` la date d'expiration naturelle du token (`exp`).
`decode_token()` rejette tout token dont le `jti` figure dans cette table.

TTL : les entrées dont `expires_at` est dépassé peuvent être purgées sans
risque — le token serait de toute façon rejeté par la vérification `exp`
de PyJWT. La purge est effectuée par la tâche de rétention quotidienne
(`services/retention.py::run_retention`) via `purge_expired()`.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn

logger = logging.getLogger("token_revocation")


def revoke_jti(jti: str, username: str, expires_at: datetime) -> None:
    """
    Marque un JWT (identifié par son `jti`) comme révoqué.

    `expires_at` doit correspondre au claim `exp` du token — au-delà de
    cette date, l'entrée devient inutile (le token expire naturellement)
    et peut être purgée par `purge_expired()`.

    Idempotent : un `jti` déjà révoqué n'est pas dupliqué.
    """
    if not jti:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            text(
                "INSERT INTO revoked_tokens (jti, username, revoked_at, expires_at) "
                "VALUES (:jti, :u, :ra, :ea) "
                "ON CONFLICT (jti) DO NOTHING"
            ),
            {"jti": jti, "u": username, "ra": now_iso, "ea": expires_at.isoformat()},
        )
    logger.info(f"[token_revocation] Token révoqué — jti={jti[:8]}… user={username}")


def is_revoked(jti: str | None) -> bool:
    """Retourne True si `jti` figure dans la table des tokens révoqués."""
    if not jti:
        return False
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT 1 FROM revoked_tokens WHERE jti = :jti"),
            {"jti": jti},
        ).fetchone()
    return row is not None


def purge_expired() -> int:
    """
    Supprime les entrées dont `expires_at` est dans le passé.
    Retourne le nombre d'entrées supprimées. Appelé par la rétention quotidienne.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        result = conn.execute(
            text("DELETE FROM revoked_tokens WHERE expires_at < :now"),
            {"now": now_iso},
        )
    deleted = result.rowcount or 0
    if deleted:
        logger.info(f"[token_revocation] Purge : {deleted} entrée(s) expirée(s) supprimée(s)")
    return deleted
