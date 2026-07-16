"""
Persistance des décisions de sécurité RSSI — PostgreSQL (table decision_records).

Cycle de vie d'un paquet soumis à révision :

  pending_review   → le RSSI doit agir
  ├── accept_risk  → paquet promu dans APT/RPM, risque accepté formellement
  ├── exception    → exception temporaire avec date d'expiration
  ├── reject       → quarantaine définitive
  └── upgrade_req  → en attente de la version patchée (reste hors dépôt)

Les décisions "accept_risk" et "exception" ont une date d'expiration.
À expiration, le statut repasse à "pending_review" (géré par le scheduler).
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from sqlalchemy import text

from db.engine import db_conn

# Conservé pour migration uniquement (lecture lors du démarrage si la migration Alembic n'a pas encore tourné)
DECISIONS_DIR = Path(os.getenv("SECURITY_CACHE_DIR", "/repos/security")) / "decisions"

VALID_ACTIONS = {"accept_risk", "exception", "reject", "upgrade_required"}

ACTION_TO_STATUS = {
    "accept_risk":      "accepted_risk",
    "exception":        "exception",
    "reject":           "quarantined",
    "upgrade_required": "upgrade_required",
}


def save_decision(
    name: str,
    version: str,
    arch: str,
    action: str,
    justification: str,
    decided_by: str,
    expires_in_days: int | None = None,
    target_version: str | None = None,
    cve_ids: list[str] | None = None,
    assigned_to: str | None = None,
    assigned_to_type: str | None = None,
) -> dict:
    if action not in VALID_ACTIONS:
        raise ValueError(f"Action invalide : {action}. Valeurs : {VALID_ACTIONS}")

    now = datetime.now(timezone.utc)
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = (now + timedelta(days=expires_in_days)).isoformat()

    assigned_at = now.isoformat() if assigned_to else None

    with db_conn() as conn:
        # Vérifier si une décision existe déjà (upsert)
        existing = conn.execute(
            text("SELECT id FROM decision_records WHERE package = :pkg AND version = :ver AND arch = :arch"),
            {"pkg": name, "ver": version, "arch": arch},
        ).fetchone()

        rec_id = existing[0] if existing else str(uuid.uuid4())

        conn.execute(
            text(
                "INSERT INTO decision_records "
                "(id, package, version, arch, action, status, justification, "
                " decided_by, decided_at, expires_at, expires_in_days, target_version, "
                " cve_ids, assigned_to, assigned_to_type, assigned_at, "
                " patch_available_notified, resolved_at, resolved_by, resolution_note) "
                "VALUES (:id, :pkg, :ver, :arch, :action, :status, :just, "
                " :by, :at, :exp_at, :exp_days, :tgt_ver, "
                " :cve_ids, :asgn, :asgn_type, :asgn_at, "
                " false, NULL, NULL, NULL) "
                "ON CONFLICT (package, version, arch) DO UPDATE SET "
                "  action = EXCLUDED.action, "
                "  status = EXCLUDED.status, "
                "  justification = EXCLUDED.justification, "
                "  decided_by = EXCLUDED.decided_by, "
                "  decided_at = EXCLUDED.decided_at, "
                "  expires_at = EXCLUDED.expires_at, "
                "  expires_in_days = EXCLUDED.expires_in_days, "
                "  target_version = EXCLUDED.target_version, "
                "  cve_ids = EXCLUDED.cve_ids, "
                "  assigned_to = EXCLUDED.assigned_to, "
                "  assigned_to_type = EXCLUDED.assigned_to_type, "
                "  assigned_at = EXCLUDED.assigned_at, "
                "  patch_available_notified = false, "
                "  resolved_at = NULL, "
                "  resolved_by = NULL, "
                "  resolution_note = NULL"
            ),
            {
                "id":        rec_id,
                "pkg":       name,
                "ver":       version,
                "arch":      arch,
                "action":    action,
                "status":    ACTION_TO_STATUS[action],
                "just":      justification,
                "by":        decided_by,
                "at":        now.isoformat(),
                "exp_at":    expires_at,
                "exp_days":  expires_in_days,
                "tgt_ver":   target_version,
                "cve_ids":   json.dumps(cve_ids or []),
                "asgn":      assigned_to,
                "asgn_type": assigned_to_type,
                "asgn_at":   assigned_at,
            },
        )

    return load_decision(name, version, arch)


def load_decision(name: str, version: str, arch: str = "amd64") -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM decision_records WHERE package = :pkg AND version = :ver AND arch = :arch"),
            {"pkg": name, "ver": version, "arch": arch},
        ).mappings().fetchone()
    return _row_to_dict(row) if row else None


def _row_to_dict(row) -> dict:
    d = dict(row)
    if isinstance(d.get("cve_ids"), str):
        try:
            d["cve_ids"] = json.loads(d["cve_ids"])
        except Exception:
            d["cve_ids"] = []
    return d


def mark_patch_notified(name: str, version: str, arch: str = "amd64") -> bool:
    with db_conn() as conn:
        result = conn.execute(
            text(
                "UPDATE decision_records SET patch_available_notified = true "
                "WHERE package = :pkg AND version = :ver AND arch = :arch"
            ),
            {"pkg": name, "ver": version, "arch": arch},
        )
    return result.rowcount > 0


def resolve_decision(
    name: str, version: str, arch: str, resolved_by: str, note: str = "",
) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        result = conn.execute(
            text(
                "UPDATE decision_records SET resolved_at = :ts, resolved_by = :by, resolution_note = :note "
                "WHERE package = :pkg AND version = :ver AND arch = :arch"
            ),
            {"ts": now, "by": resolved_by, "note": note or None,
             "pkg": name, "ver": version, "arch": arch},
        )
    if result.rowcount == 0:
        return None
    return load_decision(name, version, arch)


def delete_decision(name: str, version: str, arch: str = "amd64") -> bool:
    with db_conn() as conn:
        result = conn.execute(
            text("DELETE FROM decision_records WHERE package = :pkg AND version = :ver AND arch = :arch"),
            {"pkg": name, "ver": version, "arch": arch},
        )
    return result.rowcount > 0


def update_decision(
    decision_id: str,
    action: str,
    justification: str,
    expires_in_days: int | None,
    target_version: str | None,
    updated_by: str,
) -> dict | None:
    if action not in VALID_ACTIONS:
        raise ValueError(f"Action invalide : {action}")
    now = datetime.now(timezone.utc)
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = (now + timedelta(days=expires_in_days)).isoformat()

    with db_conn() as conn:
        result = conn.execute(
            text(
                "UPDATE decision_records SET "
                "  action = :action, "
                "  status = :status, "
                "  justification = :just, "
                "  expires_in_days = :exp_days, "
                "  expires_at = :exp_at, "
                "  target_version = :tgt_ver, "
                "  decided_by = :by, "
                "  decided_at = :at "
                "WHERE id = :id"
            ),
            {
                "action":   action,
                "status":   ACTION_TO_STATUS[action],
                "just":     justification,
                "exp_days": expires_in_days,
                "exp_at":   expires_at,
                "tgt_ver":  target_version,
                "by":       updated_by,
                "at":       now.isoformat(),
                "id":       decision_id,
            },
        )
    if result.rowcount == 0:
        return None
    return get_decision_by_id(decision_id)


def get_decision_by_id(decision_id: str) -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM decision_records WHERE id = :id"),
            {"id": decision_id},
        ).mappings().fetchone()
    return _row_to_dict(row) if row else None


def assign_decision(
    decision_id: str,
    assigned_to: str | None,
    assigned_to_type: str | None,
) -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    assigned_at = now if assigned_to else None
    with db_conn() as conn:
        result = conn.execute(
            text(
                "UPDATE decision_records "
                "SET assigned_to = :asgn, assigned_to_type = :asgn_type, assigned_at = :asgn_at "
                "WHERE id = :id"
            ),
            {"asgn": assigned_to or None, "asgn_type": assigned_to_type or None,
             "asgn_at": assigned_at, "id": decision_id},
        )
    if result.rowcount == 0:
        return None
    return get_decision_by_id(decision_id)


def list_all_decisions() -> list[dict]:
    with db_conn() as conn:
        rows = conn.execute(
            text("SELECT * FROM decision_records ORDER BY decided_at DESC")
        ).mappings().fetchall()
    return [_row_to_dict(r) for r in rows]


def list_decisions_for_user(username: str, group_ids: list[str]) -> list[dict]:
    """Décisions assignées à l'utilisateur ou à l'un de ses groupes."""
    params: dict = {"u": username}
    group_clause = ""
    if group_ids:
        placeholders = ", ".join(f":gid{i}" for i in range(len(group_ids)))
        for i, gid in enumerate(group_ids):
            params[f"gid{i}"] = gid
        group_clause = f"OR (assigned_to_type = 'group' AND assigned_to IN ({placeholders}))"

    with db_conn() as conn:
        rows = conn.execute(
            text(
                f"SELECT * FROM decision_records "
                f"WHERE (assigned_to_type = 'user' AND assigned_to = :u) {group_clause} "
                f"ORDER BY decided_at DESC"
            ),
            params,
        ).mappings().fetchall()
    return [_row_to_dict(r) for r in rows]


def is_decision_expired(decision: dict) -> bool:
    expires_at = decision.get("expires_at")
    if not expires_at:
        return False
    try:
        exp = datetime.fromisoformat(expires_at)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False


def get_sla_status(decision: dict) -> dict:
    expires_at = decision.get("expires_at")
    if not expires_at:
        return {"has_sla": False}
    try:
        exp = datetime.fromisoformat(expires_at)
        now = datetime.now(timezone.utc)
        remaining = (exp - now).days
        return {
            "has_sla":        True,
            "expires_at":     expires_at,
            "remaining_days": remaining,
            "expired":        remaining < 0,
            "warning":        0 <= remaining <= 7,
        }
    except Exception:
        return {"has_sla": False}
