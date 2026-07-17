# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : grype_db.py
Rôle   : Mise à jour non-interactive de la base de vulnérabilités Grype
         (appelée par le cron quotidien security_sync_daily et par
         POST /security/grype/update).
Expose : update_grype_db
"""
import os
import subprocess

GRYPE_DB_DIR = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")


def update_grype_db(timeout: int = 600) -> dict:
    """
    Lance `grype db update` et retourne :
        {"ok": bool, "output": str}
    """
    try:
        r = subprocess.run(
            ["grype", "db", "update"],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "GRYPE_DB_CACHE_DIR": GRYPE_DB_DIR},
        )
        return {"ok": r.returncode == 0, "output": (r.stdout + r.stderr).strip()}
    except FileNotFoundError:
        return {"ok": False, "output": "grype introuvable dans le PATH"}
    except Exception as e:
        return {"ok": False, "output": f"Erreur inattendue : {e}"}
