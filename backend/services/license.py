"""
services/license.py — Système de licence Repod.

Éditions :
  community  : gratuit, quotas limités, fonctionnalités de base
  enterprise : licence payante, quotas configurables, toutes les fonctionnalités

Format de la clé de licence :
  repod_lic_<base64url(json_payload)>.<hmac_sha256_hex>

  Le payload JSON contient :
    edition, license_id, issued_to, issued_at, expires_at,
    max_packages, max_users, max_distributions, features[]

  La signature HMAC-SHA256 est calculée sur le payload base64url
  avec la clé vendeur (REPOD_LICENSE_VENDOR_KEY).

Stockage :
  La clé de licence est persistée dans settings.json (section "license.key").
  Elle est vérifiée au démarrage et à chaque appel à get_license_status().

Limites Community (sans licence) :
  max_packages      : 50
  max_users         : 5
  max_distributions : 1
  features          : []  (LDAP, OIDC, SBOM, CVE policy avancée = Enterprise uniquement)
"""

import base64
import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("license")

# ── Clé vendeur ────────────────────────────────────────────────────────────────
# Clé de signature des licences côté vendeur.
# En production : définir REPOD_LICENSE_VENDOR_KEY avec une valeur aléatoire de 64 hex.
# En développement / tests : la clé par défaut ci-dessous est utilisée.
_DEFAULT_VENDOR_KEY = "repod-vendor-license-key-dev-only-change-in-prod-00000000000000"

_LICENSE_PREFIX = "repod_lic_"

# ── Limites Community ─────────────────────────────────────────────────────────
COMMUNITY_LIMITS: dict[str, Any] = {
    "edition":           "community",
    "max_packages":      50,
    "max_users":         5,
    "max_distributions": 1,
    "features":          [],
    "issued_to":         "Community Edition",
    "license_id":        "community",
    "issued_at":         None,
    "expires_at":        None,
    "valid":             True,
    "active":            True,
    "days_remaining":    None,
}

# Fonctionnalités disponibles uniquement avec une licence Enterprise
ENTERPRISE_FEATURES = frozenset({
    "ldap",
    "oidc",
    "cve_policy",          # politique CVE avancée (review/warn/allow)
    "sbom",                # SBOM CycloneDX / SPDX
    "api_tokens",          # tokens CI/CD
    "snapshots",           # snapshots historiques multi-versions
    "inventory",           # inventaire SSH des clients
    "webhook",             # webhooks GitHub Advisory / CISA KEV
    "email_notifications", # notifications email SMTP
    "sla_alerts",          # alertes SLA automatiques
})


# ── Clé vendeur ───────────────────────────────────────────────────────────────

def _vendor_key() -> bytes:
    return os.getenv("REPOD_LICENSE_VENDOR_KEY", _DEFAULT_VENDOR_KEY).encode("utf-8")


# ── Génération (usage vendeur) ────────────────────────────────────────────────

def generate_license_key(
    edition: str,
    issued_to: str,
    max_packages: int = 0,
    max_users: int = 0,
    max_distributions: int = 0,
    features: list[str] | None = None,
    expires_days: int | None = 365,
    license_id: str | None = None,
) -> str:
    """
    Génère une clé de licence signée (usage vendeur / tests).

    Paramètres
    ----------
    edition            : "enterprise"
    issued_to          : nom de l'organisation
    max_packages       : 0 = illimité
    max_users          : 0 = illimité
    max_distributions  : 0 = illimité
    features           : liste de fonctionnalités activées (None = toutes)
    expires_days       : validité en jours depuis maintenant (None = pas d'expiration)
    license_id         : identifiant unique (généré automatiquement si None)

    Retourne
    --------
    str : clé de licence au format repod_lic_<payload_b64>.<hmac_hex>
    """
    now = datetime.now(timezone.utc)
    payload = {
        "edition":           edition,
        "license_id":        license_id or secrets.token_hex(8),
        "issued_to":         issued_to,
        "issued_at":         now.isoformat(),
        "expires_at":        None,
        "max_packages":      max_packages,
        "max_users":         max_users,
        "max_distributions": max_distributions,
        "features":          features if features is not None else list(ENTERPRISE_FEATURES),
    }
    if expires_days is not None:
        from datetime import timedelta
        payload["expires_at"] = (now + timedelta(days=expires_days)).isoformat()

    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig = _hmac_mod.new(_vendor_key(), payload_b64.encode("ascii"), digestmod=hashlib.sha256).hexdigest()
    return f"{_LICENSE_PREFIX}{payload_b64}.{sig}"


# ── Validation ────────────────────────────────────────────────────────────────

class LicenseError(Exception):
    """Erreur de validation de licence."""


def _decode_license_key(key: str) -> dict:
    """
    Décode et valide une clé de licence.
    Lève LicenseError si la clé est invalide.
    Retourne le payload décodé + champs calculés (valid, active, days_remaining).
    """
    if not key or not key.startswith(_LICENSE_PREFIX):
        raise LicenseError("Format de clé invalide (préfixe 'repod_lic_' manquant)")

    body = key[len(_LICENSE_PREFIX):]
    if "." not in body:
        raise LicenseError("Format de clé invalide (signature manquante)")

    payload_b64, sig_received = body.rsplit(".", 1)

    # Vérification HMAC (timing-safe)
    sig_expected = _hmac_mod.new(
        _vendor_key(), payload_b64.encode("ascii"), digestmod=hashlib.sha256
    ).hexdigest()
    if not _hmac_mod.compare_digest(sig_received, sig_expected):
        raise LicenseError("Signature de licence invalide — clé corrompue ou contrefaite")

    # Décodage du payload
    try:
        padding = 4 - len(payload_b64) % 4
        padded = payload_b64 + ("=" * (padding % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception as exc:
        raise LicenseError(f"Payload de licence illisible : {exc}") from exc

    # Vérification expiration
    now = datetime.now(timezone.utc)
    expires_at = payload.get("expires_at")
    days_remaining = None
    expired = False

    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            delta = (exp_dt - now).days
            days_remaining = max(0, delta)
            expired = now > exp_dt
        except Exception:
            pass

    return {
        **payload,
        "valid":          True,
        "active":         not expired,
        "expired":        expired,
        "days_remaining": days_remaining,
    }


# ── Stockage ─────────────────────────────────────────────────────────────────

def _load_stored_key() -> str | None:
    """Lit la clé de licence depuis settings.json."""
    try:
        from services.settings import get_settings
        return get_settings().get("license", {}).get("key") or None
    except Exception:
        return None


def activate_license(key: str) -> dict:
    """
    Active une clé de licence après validation.
    Stocke la clé dans settings.json.
    Retourne le statut de licence après activation.
    Lève LicenseError si la clé est invalide ou expirée.
    """
    decoded = _decode_license_key(key)
    if decoded.get("expired"):
        raise LicenseError(
            f"Licence expirée depuis {decoded.get('expires_at')}. "
            "Contactez support@repod.io pour un renouvellement."
        )

    from services.settings import update_settings
    update_settings({"license": {"key": key}})
    logger.info(
        f"[license] Licence activée : {decoded['edition']} "
        f"→ {decoded.get('issued_to')} (id={decoded.get('license_id')})"
    )
    return decoded


def deactivate_license() -> None:
    """Supprime la clé de licence (retour en Community Edition)."""
    from services.settings import update_settings
    update_settings({"license": {"key": ""}})
    logger.info("[license] Licence supprimée — retour en Community Edition")


# ── API publique ──────────────────────────────────────────────────────────────

def get_license_status() -> dict:
    """
    Retourne le statut de licence complet.
    Si aucune clé n'est configurée ou si la clé est invalide → Community Edition.
    """
    key = _load_stored_key()
    if not key:
        return {**COMMUNITY_LIMITS}

    try:
        decoded = _decode_license_key(key)
    except LicenseError as exc:
        logger.warning(f"[license] Clé de licence invalide : {exc}")
        return {
            **COMMUNITY_LIMITS,
            "valid":   False,
            "active":  False,
            "error":   str(exc),
        }

    return decoded


def get_edition() -> str:
    """Retourne 'community' ou 'enterprise'."""
    status = get_license_status()
    if status.get("valid") and status.get("active") and status.get("edition") == "enterprise":
        return "enterprise"
    return "community"


def is_enterprise() -> bool:
    return get_edition() == "enterprise"


def check_feature(feature: str) -> bool:
    """
    Vérifie si une fonctionnalité est activée.
    En Community Edition, toutes les fonctionnalités Enterprise sont désactivées.
    """
    status = get_license_status()
    if not (status.get("valid") and status.get("active")):
        return False
    if status.get("edition") == "community":
        return False
    return feature in status.get("features", [])


def check_quota(quota_key: str, current: int) -> dict:
    """
    Vérifie si un quota est respecté.

    Paramètres
    ----------
    quota_key : "max_packages" | "max_users" | "max_distributions"
    current   : valeur actuelle

    Retourne
    --------
    {
      "allowed": bool,
      "current": int,
      "limit": int,   # 0 = illimité
      "edition": str,
    }
    """
    status = get_license_status()
    limit = int(status.get(quota_key, 0) or 0)
    allowed = (limit == 0) or (current < limit)
    return {
        "allowed":  allowed,
        "current":  current,
        "limit":    limit,
        "edition":  status.get("edition", "community"),
    }


def get_license_summary() -> dict:
    """Version publique (sans la clé en clair) pour l'API."""
    status = get_license_status()
    # Ne jamais exposer la clé brute dans la réponse API
    return {k: v for k, v in status.items() if k != "key"}
