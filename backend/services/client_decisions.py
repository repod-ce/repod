"""
Décisions RSSI sur CVE détectées dans les machines clientes (flux Conformité Patch).
Stockage PostgreSQL (table client_decision_records).
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from db.engine import db_conn

VALID_ACTIONS = {"accept_risk", "exception", "upgrade_required"}

ACTION_LABELS = {
    "accept_risk":      "Risque accepté",
    "exception":        "Exception temporaire",
    "upgrade_required": "Patch obligatoire",
}


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("cve_ids", "client_ids", "hostnames"):
        if isinstance(d.get(field), str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError, ValueError):
                d[field] = []
    return d


def save_client_decision(
    package:        str,
    version:        str,
    arch:           str,
    distro_family:  str,
    action:         str,
    justification:  str,
    decided_by:     str,
    client_ids:     list[str],
    hostnames:      list[str],
    cve_ids:        list[str],
    expires_in_days: int | None = None,
    target_version:  str | None = None,
    assigned_to:     str | None = None,
    assigned_to_type: str | None = None,
) -> dict:
    now = datetime.now(timezone.utc)
    expires_at = None
    if expires_in_days and expires_in_days > 0:
        expires_at = (now + timedelta(days=expires_in_days)).isoformat()

    assigned_at = now.isoformat() if assigned_to else None
    rec_id = str(uuid.uuid4())

    with db_conn() as conn:
        conn.execute(
            text(
                "INSERT INTO client_decision_records "
                "(id, source, package, version, arch, distro_family, action, justification, "
                " decided_by, decided_at, expires_at, expires_in_days, target_version, "
                " cve_ids, client_ids, hostnames, "
                " assigned_to, assigned_to_type, assigned_at) "
                "VALUES (:id, 'compliance', :pkg, :ver, :arch, :distro, :action, :just, "
                " :by, :at, :exp_at, :exp_days, :tgt_ver, "
                " :cve_ids, :cli_ids, :hosts, "
                " :asgn, :asgn_type, :asgn_at)"
            ),
            {
                "id":        rec_id,
                "pkg":       package,
                "ver":       version,
                "arch":      arch,
                "distro":    distro_family,
                "action":    action,
                "just":      justification,
                "by":        decided_by,
                "at":        now.isoformat(),
                "exp_at":    expires_at,
                "exp_days":  expires_in_days,
                "tgt_ver":   target_version,
                "cve_ids":   json.dumps(cve_ids or []),
                "cli_ids":   json.dumps(client_ids or []),
                "hosts":     json.dumps(hostnames or []),
                "asgn":      assigned_to,
                "asgn_type": assigned_to_type,
                "asgn_at":   assigned_at,
            },
        )

    return load_client_decision(rec_id)


def list_client_decisions() -> list[dict]:
    with db_conn() as conn:
        rows = conn.execute(
            text("SELECT * FROM client_decision_records ORDER BY decided_at DESC")
        ).mappings().fetchall()
    return [_row_to_dict(r) for r in rows]


def load_client_decision(decision_id: str) -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM client_decision_records WHERE id = :id"),
            {"id": decision_id},
        ).mappings().fetchone()
    return _row_to_dict(row) if row else None


def resolve_client_decision(decision_id: str, resolved_by: str, note: str = "") -> dict:
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            text(
                "UPDATE client_decision_records "
                "SET resolved_at = :ts, resolved_by = :by, resolve_note = :note "
                "WHERE id = :id"
            ),
            {"ts": now, "by": resolved_by, "note": note.strip() or None, "id": decision_id},
        )
    d = load_client_decision(decision_id)
    if d is None:
        raise FileNotFoundError(f"Décision introuvable : {decision_id}")
    return d


def get_sla_status(decision: dict) -> dict:
    expires_at = decision.get("expires_at")
    if not expires_at:
        return {"status": "permanent", "days_remaining": None, "expired": False}
    try:
        exp = datetime.fromisoformat(expires_at)
    except ValueError:
        return {"status": "unknown", "days_remaining": None, "expired": False}
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    now  = datetime.now(timezone.utc)
    days = (exp - now).days
    if days < 0:
        return {"status": "expired",         "days_remaining": days, "expired": True}
    if days <= 7:
        return {"status": "expiring_soon",   "days_remaining": days, "expired": False}
    return     {"status": "active",          "days_remaining": days, "expired": False}
