"""
services/pending_promotions.py — Persistance des demandes de promotion en attente.

Une demande est créée automatiquement quand promote() retourne pending_review.
Le RSSI peut ensuite l'approuver ou la rejeter via les endpoints dédiés.

Stockage : un fichier JSON par demande dans PENDING_PROMOTIONS_DIR
  {PENDING_DIR}/{uuid4}.json

Cycle de vie :
  pending  → created by promote()
  ├── approved  → approve_pending() → reprepro exécuté, paquet promu
  └── rejected  → reject_pending()  → aucune action reprepro, notification envoyée
"""

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

PENDING_DIR = Path(
    os.getenv("PENDING_PROMOTIONS_DIR", "/repos/security/pending_promotions")
)
PENDING_DIR.mkdir(parents=True, exist_ok=True)

_lock = Lock()

VALID_STATUSES = frozenset({"pending", "approved", "rejected", "blocked", "already_present"})

# SEC-2 : regex UUID v4 stricte — bloque tout caractère de traversal de chemin
_UUID4_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_pending_id(pending_id: str) -> None:
    """Lève ValueError si pending_id n'est pas un UUID v4 valide.

    Protège contre les attaques de traversal de chemin du type :
      ../../../etc/passwd
      %2F..%2F..%2Fetc%2Fpasswd
      id\x00.json   (null-byte injection)
    """
    if not isinstance(pending_id, str) or not _UUID4_RE.match(pending_id):
        raise ValueError(f"pending_id invalide (UUID v4 attendu) : {pending_id!r}")


def _path(pending_id: str) -> Path:
    """Retourne le chemin absolu du fichier JSON pour pending_id.

    Valide le format UUID puis vérifie que le chemin résolu reste
    à l'intérieur de PENDING_DIR (défense en profondeur).
    """
    _validate_pending_id(pending_id)
    candidate = (PENDING_DIR / f"{pending_id}.json").resolve()
    # Vérification de confinement (defense-in-depth)
    if not str(candidate).startswith(str(PENDING_DIR.resolve()) + os.sep):
        raise ValueError(f"Chemin hors de PENDING_DIR : {candidate}")
    return candidate


def _load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


# ── CRUD ──────────────────────────────────────────────────────────────────────

def create_pending(
    name: str,
    version: str | None,
    from_dist: str,
    to_dist: str,
    requested_by: str,
    policy_verdict: dict,
    status: str = "pending",
    decided_by: str | None = None,
    decided_at: str | None = None,
    decision_note: str = "",
) -> dict:
    """
    Crée et persiste un enregistrement de promotion.

    status="pending"  → demande en attente d'approbation RSSI (défaut)
    status="approved" / "already_present" / "blocked" → résultat immédiat
      (promotion directe sans intervention RSSI ; decided_by = requested_by)

    Retourne le document complet (id inclus).
    """
    now        = datetime.now(timezone.utc)
    pending_id = str(uuid.uuid4())
    record = {
        "id":             pending_id,
        "name":           name,
        "version":        version,
        "from_dist":      from_dist,
        "to_dist":        to_dist,
        "requested_by":   requested_by,
        "requested_at":   now.isoformat(),
        "policy_verdict": policy_verdict,
        "status":         status,
        "decided_by":     decided_by,
        "decided_at":     decided_at,
        "decision_note":  decision_note,
    }
    with _lock:
        _path(pending_id).write_text(
            json.dumps(record, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return record


def get_pending(pending_id: str) -> dict | None:
    """Charge une demande par son ID. Retourne None si absente ou ID invalide."""
    try:
        p = _path(pending_id)
    except ValueError:
        return None
    if not p.exists():
        return None
    return _load(p)


def update_pending(pending_id: str, **fields) -> dict | None:
    """
    Met à jour des champs d'une demande existante (threadsafe).
    Retourne le document mis à jour, ou None si absent ou ID invalide.
    """
    try:
        with _lock:
            p = _path(pending_id)
            if not p.exists():
                return None
            record = _load(p)
            if record is None:
                return None
            record.update(fields)
            p.write_text(
                json.dumps(record, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        return record
    except ValueError:
        return None


def list_pending(status: str | None = None) -> list[dict]:
    """
    Retourne toutes les demandes, optionnellement filtrées par statut.
    Triées par requested_at décroissant (plus récentes en premier).
    """
    records: list[dict] = []
    for path in PENDING_DIR.glob("*.json"):
        r = _load(path)
        if r is not None:
            records.append(r)

    if status:
        records = [r for r in records if r.get("status") == status]

    records.sort(key=lambda r: r.get("requested_at", ""), reverse=True)
    return records


def delete_pending(pending_id: str) -> bool:
    """Supprime une demande. Retourne True si existait, False sinon ou ID invalide."""
    try:
        p = _path(pending_id)
    except ValueError:
        return False
    with _lock:
        if p.exists():
            p.unlink()
            return True
    return False


def purge_old_decided(max_age_days: int = 90) -> int:
    """
    Supprime les demandes décidées (approved/rejected) de plus de max_age_days jours.
    Retourne le nombre de fichiers supprimés.
    Used by services/retention.py.
    """
    if max_age_days <= 0:
        return 0

    now     = datetime.now(timezone.utc)
    deleted = 0

    for path in list(PENDING_DIR.glob("*.json")):
        r = _load(path)
        if r is None:
            continue
        if r.get("status") not in ("approved", "rejected"):
            continue
        decided_at = r.get("decided_at") or r.get("requested_at", "")
        if not decided_at:
            continue
        try:
            dt    = datetime.fromisoformat(decided_at)
            age   = (now - dt).days
            if age >= max_age_days:
                with _lock:
                    if path.exists():
                        path.unlink()
                        deleted += 1
        except Exception:
            continue

    return deleted
