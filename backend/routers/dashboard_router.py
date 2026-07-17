"""
Route dashboard :
- GET /dashboard/stats               → toutes les métriques en une requête
- GET /dashboard/stats/enriched      → métriques enrichies (tendances CVE, SLA, top paquets)
- GET /dashboard/events              → flux SSE temps réel (audit, notifications, imports…)
- GET /dashboard/events/subscribers  → nombre d'abonnés SSE actifs (admin)
"""
import asyncio
import json
import os
import queue
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from auth.dependencies import get_current_user, get_admin_user
from services.indexer import list_packages_from_index
from services.manifest import list_manifests
from services.audit import get_recent_logs
from services.security_decisions import list_all_decisions, get_sla_status
from services.health_checks import get_clamav_status
from services.dashboard import get_dashboard
from services.sse_bus import get_bus, sse_format

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


# ─── SSE helpers ─────────────────────────────────────────────────────────────

_SSE_HEARTBEAT_INTERVAL: float = 25.0   # secondes entre deux heartbeats
_SSE_POLL_INTERVAL:      float = 0.2    # secondes entre deux polls de queue


async def _sse_stream(
    q: queue.Queue,
    heartbeat_interval: float = _SSE_HEARTBEAT_INTERVAL,
    poll_interval:      float = _SSE_POLL_INTERVAL,
) -> AsyncGenerator[str, None]:
    """
    Générateur asynchrone pour le flux SSE d'un abonné.

    - Heartbeat (commentaire SSE `: heartbeat`) toutes les `heartbeat_interval` s
      pour maintenir la connexion vivante à travers les proxies.
    - Événements diffusés dès disponibles (polling toutes les `poll_interval` s).
    - Appelle unsubscribe() à la déconnexion du client (finally).
    """
    bus        = get_bus()
    last_hb    = time.monotonic()

    try:
        while True:
            now = time.monotonic()

            # Heartbeat périodique (commentaire SSE — ignoré par les navigateurs)
            if now - last_hb >= heartbeat_interval:
                yield ": heartbeat\n\n"
                last_hb = now

            # Lire les événements en attente
            try:
                event = q.get_nowait()
                yield sse_format(event)
            except queue.Empty:
                await asyncio.sleep(poll_interval)

    except asyncio.CancelledError:
        pass  # déconnexion normale
    finally:
        bus.unsubscribe(q)


@router.get("/stats")
def get_dashboard_stats(current_user: str = Depends(get_current_user)):
    packages = list_packages_from_index()

    # ── Stats paquets ──────────────────────────────────────────────────────────
    total_packages = len(packages)
    deps_missing = [p for p in packages if p.get("deps_missing")]
    total_size = sum(p.get("size_bytes", 0) for p in packages)

    # ── Activité audit (7 derniers jours) ─────────────────────────────────────
    logs = get_recent_logs(limit=500)
    today = datetime.now(timezone.utc).date()

    # Imports d'aujourd'hui
    imports_today = sum(
        1 for e in logs
        if e.get("action") in ("UPLOAD", "IMPORT")
        and e.get("result") == "SUCCESS"
        and e.get("timestamp", "")[:10] == str(today)
    )

    # Activité par jour sur 7 jours
    activity = {}
    for i in range(6, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        activity[day] = {"imports": 0, "failures": 0}

    for entry in logs:
        ts = entry.get("timestamp", "")[:10]
        if ts in activity:
            action = entry.get("action", "")
            result = entry.get("result", "")
            if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
                activity[ts]["imports"] += 1
            elif result == "FAILURE":
                activity[ts]["failures"] += 1

    activity_list = [
        {"date": day, **vals}
        for day, vals in activity.items()
    ]

    # ── Imports récents ────────────────────────────────────────────────────────
    recent_imports = [
        e for e in logs
        if e.get("action") in ("UPLOAD", "IMPORT") and e.get("result") == "SUCCESS"
    ][:8]

    # ── Alertes ───────────────────────────────────────────────────────────────
    alerts = []
    for p in deps_missing:
        alerts.append({
            "type": "deps_missing",
            "package": p["name"],
            "message": f"{len(p['deps_missing'])} dépendance(s) manquante(s)",
            "deps": p["deps_missing"],
        })

    # Alertes sécurité (rejets ClamAV ou provenance)
    security_failures = [
        e for e in logs
        if e.get("result") == "FAILURE"
        and e.get("action") in ("UPLOAD", "IMPORT", "VALIDATE")
    ][:3]
    for e in security_failures:
        alerts.append({
            "type": "security",
            "package": e.get("package", "inconnu"),
            "message": e.get("detail", "Validation échouée"),
            "timestamp": e.get("timestamp"),
        })

    # ── Posture CVE (agrégat depuis l'index) ──────────────────────────────────
    _sevs = ["critical", "high", "medium", "low", "negligible"]
    cve_scanned = [p for p in packages if p.get("cve_summary")]
    cve_totals = {s: 0 for s in _sevs}
    for p in cve_scanned:
        s = p["cve_summary"]
        for sev in _sevs:
            cve_totals[sev] += s.get(sev, 0)

    security_posture = {
        "scanned": len(cve_scanned),
        "total": total_packages,
        **cve_totals,
    }

    # ── Métriques de révision RSSI (depuis manifests = source de vérité) ──────
    status_counts: dict[str, int] = {}
    for m in list_manifests():
        st = m.get("status", "validated")
        status_counts[st] = status_counts.get(st, 0) + 1

    # Décisions actives et expirantes
    decisions = list_all_decisions()
    expiring_soon = []
    for dec in decisions:
        if dec.get("action") in ("accept_risk", "exception", "upgrade_required"):
            sla = get_sla_status(dec)
            if sla.get("warning") or sla.get("expired"):
                expiring_soon.append({
                    "package":        dec["package"],
                    "version":        dec["version"],
                    "action":         dec["action"],
                    "expires_at":     sla.get("expires_at"),
                    "remaining_days": sla.get("remaining_days"),
                    "expired":        sla.get("expired", False),
                    "decided_by":     dec.get("decided_by"),
                })

    security_review = {
        "pending_review":    status_counts.get("pending_review", 0),
        "blocked":           status_counts.get("blocked", 0),
        "quarantined":       status_counts.get("quarantined", 0),
        "accepted_risk":     status_counts.get("accepted_risk", 0),
        "exception":         status_counts.get("exception", 0),
        "upgrade_required":  status_counts.get("upgrade_required", 0),
        "expiring_soon":     sorted(expiring_soon, key=lambda d: d.get("remaining_days", 9999)),
        "total_decisions":   len(decisions),
    }

    # ── Alertes CVE expirantes → injecter dans les alertes dashboard ──────────
    for item in expiring_soon:
        days = item["remaining_days"]
        if item["expired"]:
            msg = "Décision CVE expirée — repassé en révision"
            atype = "sla_expired"
        else:
            msg = f"Décision CVE expire dans {days}j"
            atype = "sla_warning"
        alerts.append({
            "type":    atype,
            "package": item["package"],
            "message": msg,
            "action":  item["action"],
            "expires_at": item["expires_at"],
        })

    # ── ClamAV statut (léger) ─────────────────────────────────────────────────
    try:
        clamav = get_clamav_status()
        clamav_summary = {
            "available": clamav["available"],
            "db_version": clamav.get("db_version"),
            "db_date": clamav.get("db_date"),
            "daemon_running": clamav.get("daemon_running"),
        }
    except Exception:
        clamav_summary = {"available": False}

    return {
        "packages": {
            "total": total_packages,
            "total_size_bytes": total_size,
            "deps_missing_count": len(deps_missing),
            "imports_today": imports_today,
        },
        "activity": activity_list,
        "recent_imports": recent_imports,
        "alerts": alerts[:10],
        "clamav": clamav_summary,
        "security_posture": security_posture,
        "security_review": security_review,
    }


@router.get("/history")
def get_dashboard_history(days: int = 30, current_user: str = Depends(get_current_user)):
    """
    Retourne les données historiques sur N jours pour les graphiques :
    - Imports / jour
    - CVE détectées / jour
    - Décisions RSSI / jour
    - Failures / jour
    """
    from datetime import date
    logs = get_recent_logs(limit=2000)
    today = datetime.now(timezone.utc).date()

    # Initialiser les buckets
    buckets = {}
    for i in range(days - 1, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        buckets[day] = {"date": day, "imports": 0, "failures": 0, "decisions": 0, "cve_scans": 0}

    for entry in logs:
        ts = entry.get("timestamp", "")[:10]
        if ts not in buckets:
            continue
        action = entry.get("action", "").upper()
        result = entry.get("result", "").upper()

        if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
            buckets[ts]["imports"] += 1
        if result == "FAILURE":
            buckets[ts]["failures"] += 1
        if action == "DECISION":
            buckets[ts]["decisions"] += 1
        if action in ("UPLOAD", "IMPORT") and result == "SUCCESS":
            buckets[ts]["cve_scans"] += 1

    return {"history": list(buckets.values()), "days": days}


@router.get("/stats/enriched")
def get_enriched_dashboard(
    trend_windows: str = Query(
        "30,60,90",
        description="Fenêtres de tendance CVE en jours, séparées par virgule (ex. '30,60,90')",
    ),
    top_limit: int = Query(10, ge=1, le=50, description="Nombre de paquets dans les tops"),
    sla_max_age_days: int = Query(
        None, ge=0,
        description="Âge SLA max (jours) — défaut : valeur settings.json",
    ),
    current_user: str = Depends(get_current_user),
):
    """
    Tableau de bord enrichi — agrège les métriques avancées :

    • **cve_trends**    — évolution du volume CVE sur des fenêtres glissantes
    • **top_packages**  — top paquets par nombre de versions / taille / import récent
    • **sla_overdue**   — paquets en pending_review dépassant le SLA de review
    • **distributions** — statistiques CVE et volumes par distribution
    • **summary**       — compteurs globaux synthétiques
    """
    try:
        windows = [int(w.strip()) for w in trend_windows.split(",") if w.strip()]
    except ValueError:
        windows = [30, 60, 90]

    return get_dashboard(
        trend_windows=windows or [30, 60, 90],
        top_limit=top_limit,
        sla_max_age_days=sla_max_age_days,
    )


# ─── SSE endpoints ────────────────────────────────────────────────────────────

@router.get(
    "/events",
    summary="Flux SSE temps réel du dashboard",
    responses={
        200: {"description": "Flux Server-Sent Events — audit, imports, notifications…"},
        403: {"description": "Authentification requise"},
    },
)
async def sse_dashboard_events(
    current_user: str = Depends(get_current_user),
):
    """
    Ouvre un flux SSE (Server-Sent Events) recevant les événements temps réel :

    | type            | Émis par                                   |
    |-----------------|--------------------------------------------|
    | `audit_log`     | Chaque entrée écrite dans le journal       |
    | `notification`  | Après livraison d'une notification         |
    | `package_upload`| Import d'un nouveau paquet                 |
    | `heartbeat`     | Commentaire keepalive (toutes les 25 s)    |

    Le client doit implémenter l'API `EventSource` et gérer les reconnexions.

    Exemple JS :
    ```js
    const es = new EventSource('/api/v1/dashboard/events');
    es.onmessage = (e) => console.log(JSON.parse(e.data));
    ```
    """
    bus = get_bus()
    q   = bus.subscribe()

    return StreamingResponse(
        _sse_stream(q),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@router.get(
    "/events/subscribers",
    summary="Nombre d'abonnés SSE actifs (admin)",
    responses={
        200: {"description": "Nombre d'abonnés SSE connectés en ce moment"},
        403: {"description": "Droits insuffisants (rôle admin requis)"},
    },
)
def sse_subscriber_count(
    current_user: str = Depends(get_admin_user),
):
    """
    Retourne le nombre de clients SSE actuellement connectés.
    Utile pour le monitoring et le debugging de la charge.
    Rôle **admin** requis.
    """
    bus = get_bus()
    return {
        "subscribers": bus.subscriber_count,
        "checked_at":  datetime.now(timezone.utc).isoformat(),
    }
