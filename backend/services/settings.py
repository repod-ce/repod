"""
Service de persistance des paramètres de l'application.
Stockage : /repos/settings.json (volume Docker partagé → survit aux restarts).

Structure complète avec valeurs par défaut :
{
  "sync": { "enabled": true, "hour": 3, "minute": 0 },
  "sources": { "ubuntu-jammy": true, ... },        # APT mode
           ou { "almalinux8-baseos": true, ... },  # RPM mode
  "retention": { "audit_days": 90, "import_cleanup_days": 30 },
  "validation": { "sha256_check": true, "clamav_scan": true, "max_upload_size_mb": 500 }
}

Les sources par défaut dépendent de REPO_FORMAT :
  - REPO_FORMAT=apt (défaut) → sources Ubuntu/Debian
  - REPO_FORMAT=rpm          → sources AlmaLinux/Rocky/Fedora/EPEL/openSUSE

Chiffrement des secrets au repos :
  Les champs listés dans _ENCRYPTED_KEYS (smtp_password, bind_password, client_secret)
  sont chiffrés avec Fernet (AES-128-CBC + HMAC-SHA256) avant écriture sur disque.
  La clé Fernet est dérivée de SETTINGS_ENCRYPTION_KEY via HKDF-SHA256 — une clé
  dédiée, indépendante de JWT_SECRET_KEY, pour qu'une rotation de JWT_SECRET_KEY
  ne casse pas le déchiffrement des secrets stockés (mots de passe SMTP/LDAP, etc.).
  Si SETTINGS_ENCRYPTION_KEY n'est pas défini, JWT_SECRET_KEY est utilisé comme
  repli (rétrocompatibilité avec les installations existantes).
  Les valeurs chiffrées sont préfixées par "enc:" dans le JSON.
  Au déchiffrement, si la clé courante échoue, une clé legacy dérivée de
  JWT_SECRET_KEY est essayée (cas : passage d'une installation existante à
  SETTINGS_ENCRYPTION_KEY) ; la valeur est alors re-chiffrée avec la clé
  courante à la prochaine écriture.
  Les valeurs en clair existantes restent lisibles et sont chiffrées lors de la prochaine
  écriture (rétrocompatibilité sans migration forcée).
"""

import base64
import copy
import json
import logging
import os
from pathlib import Path
from threading import RLock

logger = logging.getLogger("settings")

SETTINGS_PATH = Path(os.getenv("SETTINGS_PATH", "/repos/settings.json"))

_lock = RLock()

# ── Sources par format ────────────────────────────────────────────────────────
# Définies ici comme constantes publiques pour que les tests puissent les vérifier
# indépendamment de REPO_FORMAT courant.

_APT_SOURCES: dict = {
    # Ubuntu 22.04 Jammy
    "ubuntu-jammy":                    True,
    "ubuntu-jammy-universe":           True,
    "ubuntu-jammy-updates":            True,
    "ubuntu-jammy-updates-universe":   True,
    # Ubuntu 24.04 Noble
    "ubuntu-noble":                    True,
    "ubuntu-noble-universe":           True,
    # Ubuntu 20.04 Focal
    "ubuntu-focal":                    True,
    "ubuntu-focal-universe":           True,
    # Debian 12 Bookworm
    "debian-bookworm":                 True,
    "debian-bookworm-contrib":         True,
    "debian-bookworm-non-free":        False,   # désactivé par défaut (non-free)
    # Sources de sécurité
    "ubuntu-jammy-security":           True,
    "ubuntu-jammy-security-universe":  True,
    "ubuntu-noble-security":           True,
    "ubuntu-noble-security-universe":  True,
    "ubuntu-focal-security":           True,
    "debian-bookworm-security":        True,
}

_RPM_SOURCES: dict = {
    # ── AlmaLinux ──────────────────────────────────────────────────────────────
    "almalinux8-baseos":          True,
    "almalinux8-appstream":       True,
    "almalinux8-extras":          True,
    "almalinux9-baseos":          True,
    "almalinux9-appstream":       True,
    # ── Rocky Linux ────────────────────────────────────────────────────────────
    "rocky8-baseos":              True,
    "rocky8-appstream":           True,
    "rocky9-baseos":              True,
    "rocky9-appstream":           True,
    # ── CentOS Stream ──────────────────────────────────────────────────────────
    "centos-stream9-baseos":      True,
    "centos-stream9-appstream":   True,
    # ── Oracle Linux ───────────────────────────────────────────────────────────
    "oraclelinux8-baseos":        True,
    "oraclelinux8-appstream":     True,
    "oraclelinux9-baseos":        True,
    # ── Fedora ─────────────────────────────────────────────────────────────────
    "fedora42":                   True,
    "fedora42-updates":           True,
    # ── EPEL (désactivé par défaut — volumineuse) ──────────────────────────────
    "epel8":                      False,
    "epel9":                      False,
    # ── openSUSE ───────────────────────────────────────────────────────────────
    "opensuse-leap-15.6-oss":     True,
    "opensuse-leap-15.6-updates": True,
    "opensuse-tumbleweed-oss":    True,
}


_APK_SOURCES: dict = {
    # ── Alpine 3.21 ────────────────────────────────────────────────────────────
    "alpine3.21-main":      True,
    "alpine3.21-community": True,
    # ── Alpine 3.20 ────────────────────────────────────────────────────────────
    "alpine3.20-main":      True,
    "alpine3.20-community": True,
    # ── Alpine 3.19 ────────────────────────────────────────────────────────────
    "alpine3.19-main":      True,
    "alpine3.19-community": True,
    # ── Alpine 3.18 ────────────────────────────────────────────────────────────
    "alpine3.18-main":      True,
    "alpine3.18-community": True,
}


def _get_default_sources() -> dict:
    """
    Retourne les sources par défaut selon REPO_FORMAT.
    Évalué une seule fois à l'import du module — cohérent avec la durée de vie
    du processus en production (REPO_FORMAT est fixé avant tout import).
    """
    if os.getenv("REPO_FORMAT", "apt").lower().strip() == "rpm":
        return dict(_RPM_SOURCES)
    return dict(_APT_SOURCES)


def _get_default_mirror_sources() -> dict:
    """
    Retourne les sources mirroirables par défaut selon REPO_FORMAT, toutes
    désactivées (le mirroir est opt-in : impact disque/bande passante).
    Couvre apt, rpm, apk et les modes combinés both/all.
    """
    fmt = os.getenv("REPO_FORMAT", "apt").lower().strip()
    sources: dict = {}
    if fmt in ("apt", "both", "all"):
        sources.update(dict.fromkeys(_APT_SOURCES, False))
    if fmt in ("rpm", "both", "all"):
        sources.update(dict.fromkeys(_RPM_SOURCES, False))
    if fmt in ("apk", "all"):
        sources.update(dict.fromkeys(_APK_SOURCES, False))
    return sources


# ── Chiffrement des secrets ───────────────────────────────────────────────────

# Champs chiffrés au repos dans settings.json (quelque soit leur niveau d'imbrication)
_ENCRYPTED_KEYS: frozenset[str] = frozenset({
    "smtp_password",
    "bind_password",
    "client_secret",
})

_ENC_PREFIX = "enc:"
_fernet_instance = None  # cache module-level, recréé si la clé source change
_fernet_key_used = None  # clé source ayant produit l'instance courante
_legacy_fernet_instance = None  # cache pour le repli JWT_SECRET_KEY
_legacy_fernet_key_used = None


def _derive_fernet(secret: str):
    """
    Dérive un objet Fernet à partir de `secret` via HKDF-SHA256.

    HKDF est préféré à PBKDF2 ici car les clés sources sont déjà à haute
    entropie — il n'y a pas besoin d'étirement de mot de passe.
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"repod-settings-v1",  # sel fixe et public — sécurité via le secret source
        info=b"settings-encryption",
    )
    raw_key = hkdf.derive(secret.encode("utf-8"))
    fernet_key = base64.urlsafe_b64encode(raw_key)   # Fernet exige du base64url 32 octets
    return Fernet(fernet_key)


def _get_fernet():
    """
    Retourne l'objet Fernet courant, dérivé de SETTINGS_ENCRYPTION_KEY.

    Si SETTINGS_ENCRYPTION_KEY n'est pas défini, JWT_SECRET_KEY est utilisé
    comme repli (rétrocompatibilité). La clé est mise en cache tant que la
    valeur source ne change pas.
    """
    global _fernet_instance, _fernet_key_used

    secret = os.getenv("SETTINGS_ENCRYPTION_KEY") or os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    if _fernet_instance is not None and _fernet_key_used == secret:
        return _fernet_instance

    _fernet_instance = _derive_fernet(secret)
    _fernet_key_used = secret
    return _fernet_instance


def _get_legacy_fernet():
    """
    Retourne l'objet Fernet dérivé de JWT_SECRET_KEY (ancien schéma, avant
    l'introduction de SETTINGS_ENCRYPTION_KEY), ou None si SETTINGS_ENCRYPTION_KEY
    n'est pas défini (auquel cas _get_fernet() utilise déjà JWT_SECRET_KEY).
    """
    global _legacy_fernet_instance, _legacy_fernet_key_used

    if not os.getenv("SETTINGS_ENCRYPTION_KEY"):
        return None

    jwt_secret = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    if _legacy_fernet_instance is not None and _legacy_fernet_key_used == jwt_secret:
        return _legacy_fernet_instance

    _legacy_fernet_instance = _derive_fernet(jwt_secret)
    _legacy_fernet_key_used = jwt_secret
    return _legacy_fernet_instance


def _encrypt_value(plaintext: str) -> str:
    """Chiffre une valeur et la préfixe avec 'enc:'."""
    if not plaintext:
        return plaintext  # ne pas chiffrer les chaînes vides
    token = _get_fernet().encrypt(plaintext.encode("utf-8"))
    return _ENC_PREFIX + token.decode("ascii")


def _decrypt_value(ciphertext: str) -> str:
    """Déchiffre une valeur préfixée 'enc:'. Retourne '' si aucune clé ne fonctionne."""
    if not ciphertext.startswith(_ENC_PREFIX):
        return ciphertext  # valeur en clair → rétrocompatibilité
    token = ciphertext[len(_ENC_PREFIX):].encode("ascii")
    try:
        return _get_fernet().decrypt(token).decode("utf-8")
    except Exception:
        legacy = _get_legacy_fernet()
        if legacy is not None:
            try:
                value = legacy.decrypt(token).decode("utf-8")
                logger.info(
                    "[settings] Secret déchiffré avec la clé legacy (JWT_SECRET_KEY) — "
                    "il sera re-chiffré avec SETTINGS_ENCRYPTION_KEY à la prochaine écriture."
                )
                return value
            except Exception:
                pass
        logger.warning(
            "[settings] Impossible de déchiffrer un secret — SETTINGS_ENCRYPTION_KEY ou "
            "JWT_SECRET_KEY a changé ? La valeur est retournée vide. "
            "Re-saisir le secret dans les paramètres."
        )
        return ""


def _walk_secrets(d: dict, transform) -> dict:
    """
    Parcourt récursivement le dict et applique `transform(value)` sur les
    champs dont la clé est dans _ENCRYPTED_KEYS.
    """
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _walk_secrets(v, transform)
        elif k in _ENCRYPTED_KEYS and isinstance(v, str):
            result[k] = transform(v)
        else:
            result[k] = v
    return result


def _encrypt_secrets(d: dict) -> dict:
    """Chiffre tous les champs secrets avant écriture sur disque."""
    return _walk_secrets(d, _encrypt_value)


def _decrypt_secrets(d: dict) -> dict:
    """Déchiffre tous les champs secrets après lecture depuis le disque."""
    return _walk_secrets(d, _decrypt_value)

DEFAULT_SETTINGS: dict = {
    "app_url": "http://localhost:3003",
    # URL du dépôt APT repod accessible par les machines clientes.
    # Exemple : "http://192.168.1.10" (port 80, sans chemin ni slash final).
    # Si vide, le backend tente de dériver l'hôte depuis app_url.
    "repo_url": "",
    "sync": {
        "enabled":  True,
        "hour":     3,
        "minute":   0,
        "timezone": "UTC",   # ex: "Europe/Paris", "America/New_York"
    },
    # Re-matching CVE rétroactif via SBOM stocké (Grype seul, APT/RPM/APK) —
    # voir services/cve_rematch.py. Activé par défaut. Programmé après "sync"
    # (03h00, rafraîchit la base Grype) — base garantie fraîche au moment du
    # re-matching.
    "cve_rematch": {
        "enabled":               True,
        "hour":                  3,
        "minute":                45,
        "max_artifacts_per_run": 50,
        "max_runtime_minutes":   30,
    },
    "mirror": {
        "enabled":              False,
        "hour":                 4,
        "minute":               30,
        "timezone":             "UTC",
        "max_packages_per_run": 300,
        "max_runtime_minutes":  90,
        "min_free_disk_gb":     5,
        # Sources mirroirables, toutes désactivées par défaut (opt-in).
        "sources": _get_default_mirror_sources(),
    },
    # Sources détectées selon REPO_FORMAT à l'import du module.
    # APT mode : ubuntu-jammy, debian-bookworm et leurs variantes.
    # RPM mode : almalinux8/9, rocky8/9, centos-stream9, fedora42, epel8/9, opensuse…
    "sources": _get_default_sources(),
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "from_address": "",
        "to_addresses": "",
        "use_tls": True,
    },
    "retention": {
        "audit_days": 90,
        "import_cleanup_days": 30,
    },
    "validation": {
        "sha256_check": True,
        "clamav_scan": True,
        "grype_scan": True,
        "grype_fail_on": "critical",  # conservé pour compat — remplacé par cve_policy
        "gpg_required": False,  # si True, un .deb/.rpm sans signature .sig/.asc valide est rejeté
        "max_upload_size_mb": 500,
    },
    "versioning": {
        # Nombre maximum de versions conservées par paquet (0 = illimité).
        # Les versions excédentaires (les plus anciennes) sont supprimées
        # lors de la prochaine exécution de run_version_gc() ou de la rétention.
        "max_versions_per_package": 10,
        # Nombre minimum de jours avant qu'une version ancienne soit éligible
        # à la suppression par le GC (même si elle dépasse max_versions).
        # 0 = suppression immédiate dès que le compte dépasse max_versions.
        "min_version_age_days": 0,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Fusion profonde : override écrase base, les clés absentes de override restent intactes."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_settings() -> dict:
    """
    Charge les paramètres depuis settings.json.
    Si le fichier est absent ou corrompu, retourne les valeurs par défaut.
    Fusionne toujours avec DEFAULT_SETTINGS pour garantir les nouvelles clés.
    Les secrets chiffrés (préfixe 'enc:') sont déchiffrés de manière transparente.
    """
    with _lock:
        if not SETTINGS_PATH.exists():
            return copy.deepcopy(DEFAULT_SETTINGS)
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                stored = json.load(f)
            # Déchiffrer les secrets avant la fusion avec les defaults
            decrypted = _decrypt_secrets(stored)
            return _deep_merge(DEFAULT_SETTINGS, decrypted)
        except Exception:
            return copy.deepcopy(DEFAULT_SETTINGS)


def update_settings(partial: dict) -> dict:
    """
    Met à jour les paramètres en fusionnant avec les valeurs existantes.
    Les secrets sont chiffrés avant écriture sur disque.
    Retourne les paramètres complets mis à jour (secrets déchiffrés — usage interne).
    """
    with _lock:
        current = get_settings()
        merged = _deep_merge(current, partial)
        # Chiffrer les secrets avant de persister
        to_write = _encrypt_secrets(merged)
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(to_write, f, indent=2, ensure_ascii=False)
        return merged  # retourner la version déchiffrée (pas le JSON sur disque)


def is_source_enabled(source_id: str) -> bool:
    """Retourne True si la source APT est activée dans les paramètres."""
    settings = get_settings()
    return settings["sources"].get(source_id, True)


def is_mirror_source_enabled(source_id: str) -> bool:
    """Retourne True si le mirroir planifié est activé pour cette source (opt-in)."""
    settings = get_settings()
    return settings.get("mirror", {}).get("sources", {}).get(source_id, False)


def get_repo_url() -> str:
    """
    Retourne l'URL de base du dépôt APT repod (sans slash final).

    Priorité :
      1. settings["repo_url"] si défini explicitement par l'admin
      2. Dérivé depuis settings["app_url"] : même hôte, port 80

    Exemples :
      repo_url = "http://192.168.1.10"   → "http://192.168.1.10"
      app_url  = "http://192.168.1.10:3003" → "http://192.168.1.10"
    """
    from urllib.parse import urlparse
    cfg = get_settings()
    repo_url = cfg.get("repo_url", "").strip().rstrip("/")
    if repo_url:
        return repo_url
    app_url = cfg.get("app_url", "").strip()
    if app_url:
        parsed = urlparse(app_url)
        scheme = parsed.scheme or "http"
        host   = parsed.hostname or ""
        if host and host not in ("localhost", "127.0.0.1", "::1"):
            return f"{scheme}://{host}"
    return ""
