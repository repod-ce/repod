# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Routes de scan / mise à jour des bases de sécurité :
- POST /security/packages/{name}/{version}/rescan → rescan Grype d'un paquet déjà importé
- GET  /security/clamav/status                    → version DB ClamAV, date, statut
- POST /security/clamav/update                    → mise à jour manuelle ClamAV (SSE)
- GET  /security/grype/status                     → statut de la base Grype
- POST /security/grype/update                     → mise à jour manuelle Grype (SSE)
- GET  /security/feeds/status                     → statut des flux KEV / EPSS
- POST /security/feeds/refresh                    → refresh KEV / EPSS (SSE)
"""
import os
import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from auth.dependencies import get_current_user, get_admin_user, get_maintainer_user
from services.audit import log as audit_log
from services.manifest import load_manifest, save_manifest
from services.health_checks import get_clamav_status, CLAMAV_DB_DIR
from services.path_safety import safe_path_join_http
from services.format_router import (
    is_apt as _is_apt, ACCEPTED_EXTENSIONS as _ACCEPTED_EXTS,
    DEFAULT_DISTRIBUTION as _DEFAULT_DISTRIBUTION,
)
from routers.security_common import POOL_DIR

router = APIRouter(prefix="/security", tags=["Security"])


@router.post("/packages/{name}/{version}/rescan")
def rescan_package(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_maintainer_user),
):
    """
    Force un nouveau scan CVE Grype pour un paquet déjà importé.
    Met à jour cve_results dans le manifest.
    """
    manifest = load_manifest(name, version, arch)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")

    filename = manifest.get("filename")
    _pkg_ext    = next(iter(_ACCEPTED_EXTS))   # ".deb" ou ".rpm"
    _name_sep   = "_" if _is_apt() else "-"    # séparateur APT vs RPM
    pkg_path = safe_path_join_http(POOL_DIR, filename) if filename else None

    if not pkg_path or not pkg_path.exists():
        # Chercher dans le pool
        candidates = list(POOL_DIR.glob(f"{name}{_name_sep}*{_pkg_ext}"))
        pkg_path = candidates[0] if candidates else None

    if not pkg_path or not pkg_path.exists():
        raise HTTPException(status_code=404,
                            detail=f"Fichier {_pkg_ext} introuvable dans le pool")

    import json as _json
    import subprocess as _sp

    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
    distribution = manifest.get("distribution", _DEFAULT_DISTRIBUTION)
    # Carte distribution → identifiant Grype (APT + RPM)
    _DISTRO_MAP = {
        # APT
        "jammy":    "ubuntu:22.04",
        "noble":    "ubuntu:24.04",
        "focal":    "ubuntu:20.04",
        "bookworm": "debian:12",
        # RPM
        "almalinux8":     "almalinux:8",
        "almalinux9":     "almalinux:9",
        "rocky8":         "rockylinux:8",
        "rocky9":         "rockylinux:9",
        "centos-stream9": "centos:9",
        "oraclelinux8":   "oraclelinux:8",
        "oraclelinux9":   "oraclelinux:9",
        "fedora42":       "fedora:42",
    }
    grype_distro = _DISTRO_MAP.get(distribution, distribution)

    cmd = ["grype", str(pkg_path), "-o", "json", "--add-cpes-if-none"]
    if grype_distro:
        cmd += ["--distro", grype_distro]

    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=300,
                    env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir})
    except _sp.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Grype timeout (> 5 min)")

    if r.returncode not in (0, 1):
        raise HTTPException(status_code=500, detail=f"Grype erreur : {r.stderr[:300]}")

    try:
        data = _json.loads(r.stdout)
    except Exception:
        raise HTTPException(status_code=500, detail="Grype réponse illisible")

    raw_matches = data.get("matches", [])
    from services.cve_enrichment import enrich_cve_list

    cve_list = []
    for m in raw_matches:
        vuln = m.get("vulnerability", {})
        cve_list.append({
            "id": vuln.get("id", ""),
            "severity": m.get("vulnerability", {}).get("severity", "Unknown"),
            "description": vuln.get("description", ""),
            "fix_state": m.get("vulnerability", {}).get("fix", {}).get("state", "unknown"),
            "fix_versions": m.get("vulnerability", {}).get("fix", {}).get("versions", []),
            "cvss": next((c.get("metrics", {}).get("baseScore") for c in vuln.get("cvss", []) if c.get("version", "").startswith("3")), None),
            "package_name": m.get("artifact", {}).get("name", ""),
            "package_version": m.get("artifact", {}).get("version", ""),
            "urls": vuln.get("urls", []),
        })

    enriched = enrich_cve_list(cve_list)
    manifest["cve_results"] = enriched
    manifest["last_scan"] = datetime.now(timezone.utc).isoformat()
    save_manifest(manifest)

    counts = {}
    for c in enriched:
        sev = c.get("severity", "Unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    audit_log("RESCAN", current_user, "SUCCESS", package=name, version=version,
              detail=f"Grype rescan — {len(enriched)} CVE trouvée(s)")

    return {
        "status": "ok",
        "package": name,
        "version": version,
        "cve_count": len(enriched),
        "cve_counts": counts,
    }


@router.get("/clamav/status")
def clamav_status(current_user: str = Depends(get_current_user)):
    """Retourne le statut de ClamAV et de sa base de signatures."""
    return get_clamav_status()


@router.post("/clamav/update")
def clamav_update(current_user: str = Depends(get_admin_user)):
    """
    Lance une mise à jour manuelle de la base ClamAV.
    Stream SSE en temps réel.
    """
    def event_stream():
        def emit(msg: str, level: str = "info") -> str:
            return f"data: {level}|{msg}\n\n"

        yield emit("Lancement de la mise à jour ClamAV...")
        yield emit(f"Répertoire DB : {CLAMAV_DB_DIR}")

        try:
            process = subprocess.Popen(
                ["freshclam",
                 "--datadir", str(CLAMAV_DB_DIR),
                 "--log=/dev/null",   # évite "Permission denied" sur /var/log/clamav/freshclam.log
                 "--stdout"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                line_lower = line.lower()
                # Coloriser selon le contenu
                if "up to date" in line_lower or "already up" in line_lower:
                    yield emit(line, "success")
                elif "updated" in line_lower or "downloading" in line_lower:
                    yield emit(line, "info")
                elif "rate limit" in line_lower or "cool-down" in line_lower or "429" in line or "403" in line:
                    yield emit(line, "warning")
                elif "error" in line_lower or "failed" in line_lower:
                    yield emit(line, "error")
                elif "warning" in line_lower:
                    yield emit(line, "warning")
                else:
                    yield emit(line, "info")

            process.wait()

            if process.returncode == 0:
                status = get_clamav_status()
                yield emit(
                    f"Mise à jour terminée — DB version {status.get('db_version', '?')} "
                    f"({status.get('db_date', '?')})",
                    "success"
                )
                audit_log("CLAMAV_UPDATE", current_user, "SUCCESS",
                          detail=f"DB mise à jour : version {status.get('db_version')}")
            else:
                yield emit("Mise à jour terminée avec des avertissements", "warning")
                audit_log("CLAMAV_UPDATE", current_user, "WARNING",
                          detail="freshclam terminé avec code non-zéro")

        except FileNotFoundError:
            yield emit("freshclam introuvable — ClamAV n'est pas installé", "error")
        except Exception as e:
            yield emit(f"Erreur inattendue : {e}", "error")

        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Grype DB ────────────────────────────────────────────────────────────────

@router.get("/grype/status")
def grype_db_status(current_user: str = Depends(get_current_user)):
    """Retourne le statut de la base de vulnérabilités Grype."""
    import subprocess, re
    from datetime import datetime, timezone

    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
    result = {
        "available":   False,
        "version":     None,
        "built_at":    None,
        "schema":      None,
        "status":      None,
        "age_hours":   None,
        "stale":       False,
        "stale_threshold_hours": 48,
    }
    try:
        r = subprocess.run(
            ["grype", "db", "status"],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir},
        )
        out = r.stdout + r.stderr
        result["available"] = True

        # Parser la sortie : "Built:     2026-06-09T07:40:05Z"
        for line in out.splitlines():
            if line.startswith("Built:"):
                built_str = line.split(":", 1)[1].strip()
                result["built_at"] = built_str
                try:
                    built_dt = datetime.fromisoformat(built_str.rstrip("Z")).replace(tzinfo=timezone.utc)
                    age = datetime.now(timezone.utc) - built_dt
                    result["age_hours"] = round(age.total_seconds() / 3600, 1)
                    result["stale"] = result["age_hours"] > result["stale_threshold_hours"]
                except Exception:
                    pass
            elif line.startswith("Schema:"):
                result["schema"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                result["status"] = line.split(":", 1)[1].strip()
    except FileNotFoundError:
        result["status"] = "grype non installé"
    except Exception as e:
        result["status"] = f"erreur : {e}"
    return result


@router.post("/grype/update")
def grype_db_update(current_user: str = Depends(get_admin_user)):
    """Met à jour la base Grype. Stream SSE en temps réel."""
    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")

    def event_stream():
        def emit(msg: str, level: str = "info") -> str:
            return f"data: {level}|{msg}\n\n"

        yield emit("Mise à jour de la base Grype en cours...")
        yield emit(f"Répertoire DB : {grype_db_dir}")

        try:
            proc = subprocess.Popen(
                ["grype", "db", "update"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir},
            )
            for line in iter(proc.stdout.readline, ""):
                line = line.strip()
                if not line:
                    continue
                ll = line.lower()
                if "up to date" in ll or "already" in ll:
                    yield emit(line, "success")
                elif "updating" in ll or "downloading" in ll or "loading" in ll:
                    yield emit(line, "info")
                elif "error" in ll or "failed" in ll:
                    yield emit(line, "error")
                elif "warn" in ll:
                    yield emit(line, "warning")
                else:
                    yield emit(line, "info")

            proc.wait()
            if proc.returncode == 0:
                # Relire le statut après mise à jour
                r2 = subprocess.run(
                    ["grype", "db", "status"],
                    capture_output=True, text=True, timeout=15,
                    env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir},
                )
                for line in r2.stdout.splitlines():
                    if line.startswith("Built:"):
                        built = line.split(":", 1)[1].strip()
                        yield emit(f"Base mise a jour — construite le {built}", "success")
                        break
                else:
                    yield emit("Base mise a jour avec succes", "success")
                audit_log("GRYPE_DB_UPDATE", current_user, "SUCCESS")
            else:
                yield emit("Mise a jour terminee avec des avertissements", "warning")
        except FileNotFoundError:
            yield emit("grype introuvable dans le PATH", "error")
        except Exception as e:
            yield emit(f"Erreur inattendue : {e}", "error")

        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── KEV + EPSS feeds ────────────────────────────────────────────────────────

@router.get("/feeds/status")
def feeds_status(current_user: str = Depends(get_current_user)):
    """Retourne le statut des flux de sécurité KEV et EPSS."""
    from services.cve_enrichment import (
        KEV_CACHE_PATH, EPSS_CACHE_PATH, CACHE_TTL_HOURS, _cache_fresh, _load_json
    )
    from datetime import datetime, timezone

    def _age_hours(path):
        try:
            mtime = path.stat().st_mtime
            age = datetime.now(timezone.utc).timestamp() - mtime
            return round(age / 3600, 1)
        except Exception:
            return None

    kev_data  = _load_json(KEV_CACHE_PATH)
    epss_data = _load_json(EPSS_CACHE_PATH)

    return {
        "ttl_hours": CACHE_TTL_HOURS,
        "kev": {
            "available":       KEV_CACHE_PATH.exists(),
            "fetched_at":      kev_data.get("fetched_at"),
            "total":           kev_data.get("total", 0),
            "catalog_version": kev_data.get("catalog_version", ""),
            "age_hours":       _age_hours(KEV_CACHE_PATH),
            "fresh":           _cache_fresh(KEV_CACHE_PATH),
        },
        "epss": {
            "available":  EPSS_CACHE_PATH.exists(),
            "updated_at": epss_data.get("updated_at"),
            "count":      len(epss_data.get("scores", {})),
            "age_hours":  _age_hours(EPSS_CACHE_PATH),
            "fresh":      _cache_fresh(EPSS_CACHE_PATH),
        },
    }


@router.post("/feeds/refresh")
def feeds_refresh(current_user: str = Depends(get_admin_user)):
    """Force le refresh des flux KEV et EPSS. Stream SSE."""

    def event_stream():
        def emit(msg: str, level: str = "info") -> str:
            return f"data: {level}|{msg}\n\n"

        from services.cve_enrichment import refresh_kev, get_kev_meta, _load_epss_cache, _save_epss_cache
        import urllib.request, json
        from services.cve_enrichment import EPSS_URL, EPSS_CACHE_PATH

        # 1. KEV
        yield emit("Rafraichissement du catalogue KEV (CISA)...")
        try:
            ok = refresh_kev()
            if ok:
                meta = get_kev_meta()
                yield emit(
                    f"[OK] KEV mis a jour — {meta['total']} entrees"
                    f" (version {meta.get('catalog_version', '?')})",
                    "success"
                )
            else:
                yield emit("[WARN] KEV — impossible de joindre l'API CISA (cache conserve)", "warning")
        except Exception as e:
            yield emit(f"[FAIL] KEV — {e}", "error")

        # 2. EPSS
        yield emit("Rafraichissement des scores EPSS (FIRST.org)...")
        try:
            req = urllib.request.Request(
                f"{EPSS_URL}?days=30&limit=10000",
                headers={"User-Agent": "repod-security/1.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = json.loads(resp.read())
            data = raw.get("data", [])
            scores = {
                item["cve"]: {
                    "score":      round(float(item.get("epss", 0)), 6),
                    "percentile": round(float(item.get("percentile", 0)), 4),
                }
                for item in data if "cve" in item
            }
            _save_epss_cache(scores)
            yield emit(f"[OK] EPSS mis a jour — {len(scores)} scores charges", "success")
            audit_log("FEEDS_REFRESH", current_user, "SUCCESS",
                      detail=f"KEV + EPSS ({len(scores)} scores)")
        except Exception as e:
            yield emit(f"[WARN] EPSS — {e} (cache conserve)", "warning")

        yield emit("Flux de securite rafraichis", "success")
        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
