"""
Module : health_checks.py
Rôle   : Vérifications de santé des services système (ClamAV, …).
         Centralise les fonctions qui étaient définies dans les routers,
         permettant leur réutilisation sans imports inter-routers.
Expose : get_clamav_status
Dépend : subprocess, pathlib, datetime
"""
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

CLAMAV_DB_DIR = Path(os.getenv("CLAMAV_DB_DIR", "/var/lib/clamav"))


def get_clamav_status() -> dict:
    """
    Retourne le statut actuel de ClamAV et de sa base de signatures.

    Retourne un dict avec les clés :
        available      : bool  — clamscan accessible dans le PATH
        version        : str|None  — version ClamAV (ex: "1.4.3")
        db_version     : str|None  — numéro de build de la DB (ex: "27969")
        db_date        : str|None  — date de la DB (ex: "Sun Apr 12 …")
        db_files       : list[dict] — fichiers présents dans CLAMAV_DB_DIR
        daemon_running : bool  — freshclam daemon actif
        cooldown_until : str|None  — ISO8601 fin de cooldown freshclam (si présent)
    """
    status: dict = {
        "available":      False,
        "version":        None,
        "db_version":     None,
        "db_date":        None,
        "db_files":       [],
        "daemon_running": False,
        "cooldown_until": None,
    }

    # ── Version de clamscan ───────────────────────────────────────────────────
    try:
        r = subprocess.run(
            ["clamscan", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            status["available"] = True
            # Format : "ClamAV 1.4.3/27969/Sun Apr 12 06:24:30 2026"
            parts = r.stdout.strip().split("/")
            if len(parts) >= 3:
                status["version"]    = parts[0].replace("ClamAV ", "").strip()
                status["db_version"] = parts[1].strip()
                status["db_date"]    = parts[2].strip()
    except Exception:
        pass

    # ── Fichiers de la DB sur le volume ───────────────────────────────────────
    if CLAMAV_DB_DIR.exists():
        db_files = []
        for f in sorted(CLAMAV_DB_DIR.glob("*.cv*")):
            stat = f.stat()
            db_files.append({
                "name":        f.name,
                "size_bytes":  stat.st_size,
                "modified_at": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            })
        status["db_files"] = db_files

    # ── Daemon freshclam ──────────────────────────────────────────────────────
    try:
        r = subprocess.run(
            ["pgrep", "-x", "freshclam"],
            capture_output=True, text=True, timeout=3,
        )
        status["daemon_running"] = (r.returncode == 0)
    except Exception:
        pass

    # ── Cooldown freshclam.dat ────────────────────────────────────────────────
    freshclam_dat = CLAMAV_DB_DIR / "freshclam.dat"
    if freshclam_dat.exists():
        try:
            content = freshclam_dat.read_text()
            for line in content.splitlines():
                if "cool" in line.lower() or line.strip().isdigit():
                    ts = int(line.strip())
                    if ts > 0:
                        status["cooldown_until"] = datetime.fromtimestamp(
                            ts, tz=timezone.utc
                        ).isoformat()
                        break
        except Exception:
            pass

    return status
