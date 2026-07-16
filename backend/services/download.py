"""
services/download.py — Téléchargement d'un paquet via SSH (paramiko).

Sécurité :
  - Le nom du paquet est validé par regex stricte avant toute exécution distante.
  - Connexion via clé Ed25519 uniquement (pas de mot de passe).
  - StrictHostKeyChecking équivalent : RejectPolicy (hôte inconnu = refus).
  - Aucun subprocess, aucune interpolation shell non contrôlée.
"""

import logging
import os
import re

logger = logging.getLogger("download")

# Chemin du script sur la machine distante (fixe, non interpolé)
SCRIPT_PATH = "~/repodata/download-package-dep.sh"

# IP ou FQDN de l'hôte cible — doit être configuré explicitement
SSH_HOST = os.getenv("SSH_HOST", "")

# Utilisateur SSH sur la machine hôte — doit être configuré explicitement
SSH_USER = os.getenv("SSH_USER", "")

# Regex stricte : lettres, chiffres, tiret, underscore, point, plus — longueur 1-200
# Couvre les noms de paquets Debian, RPM et APK valides.
_SAFE_PKG_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._+\-]{0,199}$')


def download_package(package_name: str) -> dict:
    """
    Télécharge un paquet et ses dépendances sur la machine hôte via SSH.

    Le nom du paquet est validé par regex avant toute exécution distante.
    La connexion utilise une clé Ed25519 ; les hôtes inconnus sont rejetés.

    Retourne un dict avec "message"+"output" (succès) ou "error"+"details" (échec).
    """
    # ── Validation stricte du nom de paquet ──────────────────────────────────
    if not package_name or not _SAFE_PKG_RE.match(package_name):
        logger.warning("[download] Nom de paquet invalide refusé : %r", package_name)
        return {
            "error":   "Nom de paquet invalide",
            "details": "Seuls les caractères alphanumériques, '.', '_', '+', '-' sont autorisés.",
        }

    if not SSH_HOST:
        logger.error("[download] SSH_HOST non configuré — opération impossible")
        return {
            "error":   "SSH_HOST non configuré",
            "details": "Définir la variable d'environnement SSH_HOST.",
        }

    if not SSH_USER:
        logger.error("[download] SSH_USER non configuré — opération impossible")
        return {
            "error":   "SSH_USER non configuré",
            "details": "Définir la variable d'environnement SSH_USER.",
        }

    # ── Connexion SSH via paramiko ────────────────────────────────────────────
    ssh_key_path = os.getenv("SSH_KEY_PATH", "/home/appuser/.ssh/id_ed25519")
    ssh_user     = SSH_USER
    ssh_port     = int(os.getenv("SSH_PORT", "22"))

    try:
        import paramiko

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        # Refuser explicitement les hôtes inconnus (équivalent StrictHostKeyChecking=yes)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        pkey = paramiko.Ed25519Key.from_private_key_file(ssh_key_path)
        client.connect(
            hostname=SSH_HOST,
            port=ssh_port,
            username=ssh_user,
            pkey=pkey,
            timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )

        # Commande : chemin de script fixe + nom de paquet validé par regex
        cmd = f"bash {SCRIPT_PATH} {package_name}"
        _, stdout, stderr = client.exec_command(cmd, timeout=120)

        out       = stdout.read().decode("utf-8", errors="replace")
        err       = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()

    except FileNotFoundError:
        logger.error("[download] Clé SSH introuvable : %s", ssh_key_path)
        return {"error": "Clé SSH introuvable", "details": ssh_key_path}
    except paramiko.ssh_exception.NoValidConnectionsError as exc:
        logger.error("[download] Connexion SSH refusée vers %s : %s", SSH_HOST, exc)
        return {"error": "Connexion SSH refusée", "details": str(exc)}
    except paramiko.ssh_exception.AuthenticationException as exc:
        logger.error("[download] Authentification SSH échouée : %s", exc)
        return {"error": "Authentification SSH échouée", "details": str(exc)}
    except Exception as exc:
        logger.error("[download] Erreur SSH inattendue pour %r : %s", package_name, exc)
        return {"error": "Erreur SSH", "details": str(exc)}

    if exit_code == 0:
        logger.info("[download] %s téléchargé avec succès (exit 0)", package_name)
        return {"message": f"{package_name} téléchargé avec succès", "output": out}

    logger.warning("[download] Échec téléchargement %s (exit %d)", package_name, exit_code)
    return {"error": f"Échec du téléchargement de {package_name}", "details": err}
