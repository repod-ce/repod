"""
Health checks Repod — compatibles Kubernetes.

Endpoints :
  GET /health        → bilan complet (toujours 200 ; status=healthy|degraded|unhealthy)
  GET /health/live   → liveness probe  (200 si le process tourne, 503 si KO)
  GET /health/ready  → readiness probe (200 si prêt à recevoir du trafic, 503 sinon)

Sondes critiques (échec → unhealthy / ready=False) :
  • manifests   — répertoire /repos/manifests accessible
  • pool        — répertoire /repos/pool accessible
  • auth_db     — table users interrogeable dans PostgreSQL
  • manifest_db — table manifests interrogeable dans PostgreSQL

Sondes non-critiques (échec → degraded uniquement) :
  • audit       — répertoire /repos/audit accessible
  • clamav      — daemon ClamAV disponible
  • reprepro    — binaire reprepro dans PATH
  • gpg         — clé GPG privée présente dans le keyring
  • scheduler   — jobs APScheduler actifs

Infos complémentaires (ne font pas varier le statut) :
  • packages    — compteurs de paquets et taille du pool
  • license     — édition de licence active
  • setup       — configuration initiale effectuée

Status sémantiques :
  healthy   → toutes les sondes critiques et non-critiques sont OK
  degraded  → sondes critiques OK, au moins une sonde non-critique en échec
  unhealthy → au moins une sonde critique en échec (→ 503 sur /health/ready)

Aucun endpoint ne requiert d'authentification (nécessaire pour les probes infra).
"""

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Response

router = APIRouter(tags=["Health"])

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))
POOL_DIR     = Path(os.getenv("POOL_DIR",     "/repos/pool"))
AUDIT_DIR    = Path(os.getenv("AUDIT_DIR",    "/repos/audit"))


# ── Sondes atomiques ──────────────────────────────────────────────────────────

def _check_dir(p: Path) -> dict:
    """Vérifie qu'un répertoire existe et calcule l'utilisation disque."""
    ok = p.exists() and p.is_dir()
    try:
        usage    = shutil.disk_usage(str(p)) if ok else None
        free_gb  = round(usage.free  / 1_073_741_824, 2) if usage else None
        total_gb = round(usage.total / 1_073_741_824, 2) if usage else None
        used_pct = round((usage.used / usage.total) * 100, 1) if usage else None
    except Exception:
        free_gb = total_gb = used_pct = None
    return {
        "ok":       ok,
        "path":     str(p),
        "free_gb":  free_gb,
        "total_gb": total_gb,
        "used_pct": used_pct,
    }


def _check_postgres() -> dict:
    """Vérifie que la connexion PostgreSQL est opérationnelle."""
    from db.engine import check_connection
    return check_connection()


def _check_auth_db() -> dict:
    """Sonde la table users dans PostgreSQL."""
    try:
        from sqlalchemy import text
        from db.engine import db_conn
        with db_conn() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
        return {"ok": True, "count": count}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_manifest_db() -> dict:
    """Sonde la table manifests dans PostgreSQL."""
    try:
        from sqlalchemy import text
        from db.engine import db_conn
        with db_conn() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM manifests")).scalar()
        return {"ok": True, "count": count}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_clamav() -> dict:
    """Vérifie la disponibilité du binaire ClamAV."""
    try:
        r = subprocess.run(
            ["clamscan", "--version"], capture_output=True, timeout=3
        )
        if r.returncode == 0:
            ver = r.stdout.decode().strip()
            return {
                "ok":      True,
                "version": ver.split()[1] if len(ver.split()) > 1 else ver,
            }
        return {"ok": False, "version": None, "error": f"returncode={r.returncode}"}
    except FileNotFoundError:
        return {"ok": False, "version": None, "error": "clamscan introuvable dans PATH"}
    except Exception as exc:
        return {"ok": False, "version": None, "error": str(exc)}


def _check_reprepro() -> dict:
    """Vérifie que le binaire reprepro est accessible dans PATH."""
    try:
        r = subprocess.run(
            ["reprepro", "--version"], capture_output=True, timeout=3
        )
        # reprepro --version retourne 0 ou 1 selon la version
        out = (r.stdout or r.stderr or b"").decode().strip()
        ver_line = out.splitlines()[0] if out else ""
        return {"ok": True, "version": ver_line or None}
    except FileNotFoundError:
        return {"ok": False, "version": None, "error": "reprepro introuvable dans PATH"}
    except Exception as exc:
        return {"ok": False, "version": None, "error": str(exc)}


def _check_gpg() -> dict:
    """
    Vérifie qu'au moins une clé GPG privée est présente dans le keyring.
    Utilisé pour signer les Release files APT.
    Respecte GNUPG_HOME (variable utilisée par toutes les autres routes).
    """
    gnupg_home = os.getenv("GNUPG_HOME", "/repos/gnupg")
    env = {**os.environ, "GNUPGHOME": gnupg_home}
    try:
        r = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True, timeout=5, env=env,
        )
        lines = r.stdout.decode(errors="replace")
        # Une ligne commençant par 'sec' indique une clé privée
        has_key = any(line.startswith("sec") for line in lines.splitlines())
        if has_key:
            # Extraire le fingerprint de la première clé
            fp_lines = [l for l in lines.splitlines() if l.startswith("fpr")]
            fp = fp_lines[0].split(":")[9] if fp_lines else None
            return {"ok": True, "fingerprint": fp}
        return {"ok": False, "error": "Aucune clé GPG privée dans le keyring"}
    except FileNotFoundError:
        return {"ok": False, "error": "gpg introuvable dans PATH"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_scheduler() -> dict:
    """Vérifie que le scheduler APScheduler est actif et liste ses jobs."""
    from services import leader_election, scheduler_state
    sched = scheduler_state.scheduler
    if sched is None:
        if not leader_election.is_leader():
            # Réplique passive (HA actif-passif) — absence de scheduler attendue.
            return {"ok": True, "jobs": [], "note": "réplique passive — scheduler sur l'instance leader"}
        return {"ok": False, "jobs": [], "error": "scheduler non démarré"}
    jobs = []
    for job in sched.get_jobs():
        jobs.append({
            "id":       job.id,
            "name":     job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
            "paused":   job.next_run_time is None,
        })
    return {"ok": True, "jobs": jobs}


def _check_packages() -> dict:
    """Statistiques du pool (compteurs + taille). Ne fait pas varier le statut."""
    try:
        manifests = list(MANIFEST_DIR.glob("*.manifest.json"))
        deb_files = list(POOL_DIR.glob("*.deb"))
        rpm_files = list(POOL_DIR.glob("*.rpm"))
        apk_files = list(POOL_DIR.glob("*.apk"))
        all_files = deb_files + rpm_files + apk_files
        pool_bytes = sum(f.stat().st_size for f in all_files)
        return {
            "ok":              True,
            "total_manifests": len(manifests),
            "pool_files":      len(all_files),
            "pool_size_mb":    round(pool_bytes / 1_048_576, 1),
            "by_format": {
                "deb": len(deb_files),
                "rpm": len(rpm_files),
                "apk": len(apk_files),
            },
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _dir_mb(path: Path) -> float | None:
    """Taille d'un répertoire en Mo via du -sk (non-récursif sur le pool)."""
    try:
        r = subprocess.run(
            ["du", "-sk", "--", str(path)],
            capture_output=True, text=True, timeout=6,
        )
        if r.returncode == 0 and r.stdout:
            kb = int(r.stdout.split()[0])
            return round(kb / 1024, 1)
    except Exception:
        pass
    return None


def _check_storage() -> dict:
    """
    Agrégat stockage : stats système de fichiers + taille par répertoire clé.
    Remplace les 3 checks redondants (manifests/pool/audit partagent le même FS).
    """
    try:
        base = Path("/repos")
        usage    = shutil.disk_usage(str(base))
        free_gb  = round(usage.free  / 1_073_741_824, 2)
        total_gb = round(usage.total / 1_073_741_824, 2)
        used_pct = round((usage.used / usage.total) * 100, 1)

        dirs = {}
        for name, path in [
            ("pool",      POOL_DIR),
            ("manifests", MANIFEST_DIR),
            ("audit",     AUDIT_DIR),
            ("grype_db",  Path(os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db"))),
            ("clamav_db", Path(os.getenv("CLAMAV_DB_DIR", "/var/lib/clamav"))),
        ]:
            mb = _dir_mb(path) if path.exists() else None
            dirs[name] = {"path": str(path), "size_mb": mb}

        return {
            "ok":       True,
            "free_gb":  free_gb,
            "total_gb": total_gb,
            "used_pct": used_pct,
            "dirs":     dirs,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_license() -> dict:
    """Retourne l'édition de licence active. Ne fait pas varier le statut."""
    try:
        from services.license import get_license_summary
        lic = get_license_summary()
        return {
            "ok":      True,
            "edition": lic.get("edition", "community"),
            "active":  lic.get("active", True),
            "issued_to": lic.get("issued_to"),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_setup() -> dict:
    """Vérifie si le wizard de première installation a été effectué."""
    try:
        from services.setup import is_setup_done
        done = is_setup_done()
        return {"ok": done, "setup_done": done}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _check_ha() -> dict:
    """
    Statut HA actif-passif : identifie l'instance et indique si elle est
    leader (scheduler + jobs leader-only actifs) ou réplique passive.
    """
    try:
        from services import leader_election, scheduler_state
        return {
            "ok": True,
            "is_leader": leader_election.is_leader(),
            "instance_id": leader_election.INSTANCE_ID,
            "scheduler_active": scheduler_state.scheduler is not None,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ── Agrégation ────────────────────────────────────────────────────────────────

def _run_all_checks() -> dict:
    """
    Exécute toutes les sondes et retourne leur résultat groupé.

    Retourne :
    {
      "critical":      {check_name: result, ...},  # échec → unhealthy
      "non_critical":  {check_name: result, ...},  # échec → degraded seulement
      "info":          {check_name: result, ...},  # lecture seule, pas d'impact status
    }
    """
    critical = {
        "manifests":   _check_dir(MANIFEST_DIR),
        "pool":        _check_dir(POOL_DIR),
        "auth_db":     _check_auth_db(),
        "manifest_db": _check_manifest_db(),
    }
    non_critical = {
        "audit":     _check_dir(AUDIT_DIR),
        "clamav":    _check_clamav(),
        "reprepro":  _check_reprepro(),
        "gpg":       _check_gpg(),
        "scheduler": _check_scheduler(),
    }
    info = {
        "packages": _check_packages(),
        "storage":  _check_storage(),
        "license":  _check_license(),
        "setup":    _check_setup(),
        "ha":       _check_ha(),
    }
    return {"critical": critical, "non_critical": non_critical, "info": info}


def _compute_status(checks: dict) -> str:
    """
    Calcule le statut global à partir des résultats des sondes.

    unhealthy  → au moins une sonde critique en échec
    degraded   → sondes critiques OK, au moins une non-critique en échec
    healthy    → tout est OK
    """
    if any(not v.get("ok") for v in checks["critical"].values()):
        return "unhealthy"
    if any(not v.get("ok") for v in checks["non_critical"].values()):
        return "degraded"
    return "healthy"


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/health")
def health_check(response: Response):
    """
    Bilan de santé complet.

    Toujours accessible (200 ou 503 selon le statut).
    Statuts :
      healthy   → 200
      degraded  → 200  (non-critique, mais service opérationnel)
      unhealthy → 503  (au moins une sonde critique KO)

    Utilisé par les dashboards de supervision (Grafana, Zabbix…).
    Ne requiert pas d'authentification.
    """
    checks  = _run_all_checks()
    status  = _compute_status(checks)

    http_status = 503 if status == "unhealthy" else 200
    response.status_code = http_status

    return {
        "status":    status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   os.getenv("APP_VERSION", "dev"),
        "checks":    checks,
    }


@router.get("/health/live")
def liveness():
    """
    Liveness probe Kubernetes.

    Répond 200 si le process FastAPI tourne.
    Le kubelet redémarre le pod si cette sonde échoue.
    Sonde intentionnellement minimaliste (pas de I/O ni de lock).
    """
    return {
        "alive":     True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/health/ready")
def readiness(response: Response):
    """
    Readiness probe Kubernetes.

    Répond 200 si le service est prêt à recevoir du trafic.
    Répond 503 si une sonde critique est en échec.
    Le kubelet retire le pod du load-balancer si cette sonde échoue.

    Sondes critiques vérifiées :
      • Répertoire manifests accessible
      • Répertoire pool accessible
      • Table users interrogeable dans PostgreSQL
      • Table manifests interrogeable dans PostgreSQL
    """
    critical = {
        "manifests":   _check_dir(MANIFEST_DIR),
        "pool":        _check_dir(POOL_DIR),
        "auth_db":     _check_auth_db(),
        "manifest_db": _check_manifest_db(),
    }

    failing = {k: v for k, v in critical.items() if not v.get("ok")}
    ready   = len(failing) == 0

    http_status = 200 if ready else 503
    response.status_code = http_status

    return {
        "ready":     ready,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks":    critical,
        **({"failing": list(failing.keys())} if failing else {}),
    }
