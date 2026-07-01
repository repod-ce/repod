"""
services/webhook.py — P3-C : Traitement des webhooks entrants

Fonctions :
  verify_github_signature()  — Vérifie un header X-Hub-Signature-256 (HMAC-SHA256)
  parse_github_advisory()    — Parse un payload GitHub Security Advisory
  parse_kev_entry()          — Parse une entrée CISA KEV
  update_kev_flag()          — Propage in_kev=True sur les manifests affectés

Sécurité :
  • HMAC-SHA256 avec hmac.compare_digest() (timing-safe, résiste aux attaques temporelles)
  • Format de signature GitHub : "sha256=<hex>" dans X-Hub-Signature-256
  • Si WEBHOOK_SECRET="" → vérification désactivée (mode dev uniquement)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Vérification de signature HMAC-SHA256 ─────────────────────────────────────

def verify_github_signature(
    payload_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """
    Vérifie la signature HMAC-SHA256 d'un webhook GitHub.

    Args:
        payload_body:      Corps de la requête en bytes bruts.
        signature_header:  Valeur du header X-Hub-Signature-256 ("sha256=<hex>").
        secret:            Secret partagé (WEBHOOK_SECRET).

    Returns:
        True si la signature est valide, False dans tous les autres cas.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_hex = signature_header[7:]   # strip "sha256="
    if not expected_hex:
        return False

    computed_hex = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    # hmac.compare_digest : comparaison en temps constant (résiste aux timing attacks)
    return hmac.compare_digest(computed_hex, expected_hex)


# ── Parsing des payloads entrants ─────────────────────────────────────────────

def parse_github_advisory(payload: dict) -> Optional[dict]:
    """
    Parse un payload GitHub security_advisory webhook.

    Extrait l'ID CVE depuis :
      1. security_advisory.cve_id  (champ direct)
      2. security_advisory.identifiers[]  (fallback)

    Returns:
        dict avec {cve_id, severity, description, ghsa_id, action, source}
        ou None si aucune CVE n'est identifiable.
    """
    advisory = payload.get("security_advisory") or {}

    # Extraction CVE
    cve_id: Optional[str] = advisory.get("cve_id")
    if not cve_id:
        for ident in advisory.get("identifiers") or []:
            if ident.get("type") == "CVE":
                cve_id = ident.get("value")
                break

    if not cve_id:
        return None

    return {
        "cve_id":      cve_id,
        "severity":    advisory.get("severity", "unknown"),
        "description": advisory.get("summary", ""),
        "ghsa_id":     advisory.get("ghsa_id"),
        "action":      payload.get("action"),
        "source":      "github_advisory",
    }


def parse_kev_entry(payload: dict) -> Optional[dict]:
    """
    Parse une entrée CISA KEV (format catalog.json).

    Returns:
        dict avec {cve_id, vendor, product, date_added, due_date, description, source}
        ou None si cveID est absent.
    """
    cve_id: Optional[str] = payload.get("cveID")
    if not cve_id:
        return None

    return {
        "cve_id":      cve_id,
        "vendor":      payload.get("vendorProject"),
        "product":     payload.get("product"),
        "date_added":  payload.get("dateAdded"),
        "due_date":    payload.get("dueDate"),
        "description": payload.get("shortDescription", ""),
        "source":      "cisa_kev",
    }


# ── Propagation du flag KEV sur les manifests ─────────────────────────────────

def update_kev_flag(cve_id: str) -> int:
    """
    Marque in_kev=True pour tous les paquets ayant cve_id dans leurs résultats CVE.

    Itère sur list_manifests(), modifie les entrées CVE correspondantes et
    sauvegarde les manifests changés via save_manifest().

    Args:
        cve_id: Identifiant CVE à marquer (ex. "CVE-2024-12345").

    Returns:
        Nombre de manifests effectivement mis à jour (0 si aucun changé).
    """
    from services.manifest import list_manifests, save_manifest

    updated = 0
    for manifest in list_manifests():
        changed = False
        for cve in manifest.get("cve_results") or []:
            if cve.get("id") == cve_id and not cve.get("in_kev"):
                cve["in_kev"] = True
                changed = True

        if changed:
            save_manifest(manifest)   # invalide le cache automatiquement
            updated += 1
            logger.info(
                "[webhook] in_kev=True propagé sur %s %s (CVE %s)",
                manifest.get("name"), manifest.get("version"), cve_id,
            )

    return updated
