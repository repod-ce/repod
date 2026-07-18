"""
Logs router — expose les logs de la stack repod en lecture.

Endpoints :
  GET /logs          → historique paginé (backend + apt-repo nginx)
  GET /logs/stream   → flux SSE temps réel (backend live + tail nginx)
  GET /logs/services → liste des services disponibles

Accès : admin uniquement (logs = données sensibles).
"""
import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from auth.dependencies import get_admin_user
from services.logging_config import get_log_buffer, subscribe_logs, unsubscribe_logs

router = APIRouter(prefix="/logs", tags=["Logs"])

NGINX_LOGS_DIR = os.getenv("NGINX_LOGS_DIR", "/repos/logs")

# Fichiers nginx disponibles et leur "type"
_NGINX_FILES: dict[str, str] = {
    "access":    "access.log",
    "downloads": "downloads.log",
    "error":     "error.log",
}

# ── Parsing nginx ─────────────────────────────────────────────────────────────

# Combined log : IP - - [04/Jun/2026:11:15:31 +0000] "GET /path HTTP/1.1" 200 1234 "-" "UA" "-"
_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
)
# Error log : 2026/06/04 11:24:58 [error] 22#22: *9 open() ... failed
_ERROR_RE = re.compile(
    r'^(?P<dt>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<lvl>\w+)\]'
)
# Mapping niveau nginx → niveau applicatif
_NGINX_LEVEL = {
    "debug":  "DEBUG",
    "info":   "INFO",
    "notice": "INFO",
    "warn":   "WARNING",
    "error":  "ERROR",
    "crit":   "ERROR",
    "alert":  "ERROR",
    "emerg":  "ERROR",
}


def _parse_nginx_ts(dt_str: str, fmt: str) -> float | None:
    """Convertit une chaîne date nginx en timestamp Unix."""
    try:
        return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


# Mois abrégés nginx : Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec
_NGINX_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _nginx_entry(line: str, log_type: str) -> dict:
    """Transforme une ligne nginx brute en entrée structurée avec timestamp parsé."""
    line = line.rstrip("\n")
    level = "INFO"
    ts    = None

    if log_type in ("access", "downloads"):
        # Format : 04/Jun/2026:11:15:31 +0000
        m = _ACCESS_RE.match(line)
        if m:
            status = int(m.group("status"))
            if status >= 500:
                level = "ERROR"
            elif status >= 400:
                level = "WARNING"
            dt_raw = m.group("dt")  # "04/Jun/2026:11:15:31 +0000"
            try:
                day, mon_abbr, rest = dt_raw.split("/", 2)
                year_time, tz_part = rest.rsplit(" ", 1)
                mon = _NGINX_MONTHS.get(mon_abbr, "01")
                dt_str = f"{year_time} {tz_part}"   # "2026:11:15:31 +0000"
                # Reconstruit en format ISO-like pour strptime
                year, hms = year_time.split(":", 1)
                iso = f"{year}-{mon}-{day} {hms}"
                ts = datetime.strptime(iso, "%Y-%m-%d %H:%M:%S") \
                              .replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                ts = None

    elif log_type == "error":
        # Format : 2026/06/04 11:24:58
        m = _ERROR_RE.match(line)
        if m:
            level = _NGINX_LEVEL.get(m.group("lvl"), "ERROR")
            ts = _parse_nginx_ts(m.group("dt"), "%Y/%m/%d %H:%M:%S")

    return {
        "ts":       ts,
        "level":    level,
        "name":     f"nginx/{log_type}",
        "message":  line,
        "service":  "apt-repo",
        "log_type": log_type,
    }


def _tail_file(path: str, n: int) -> list[str]:
    """Lit les n dernières lignes d'un fichier de manière efficace."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            buf = min(size, max(n * 250, 65536))
            f.seek(max(0, size - buf))
            raw = f.read()
        lines = raw.decode("utf-8", errors="replace").splitlines()
        return [l for l in lines[-n:] if l.strip()]
    except OSError:
        return []


# ── GET /api/v1/logs/services ─────────────────────────────────────────────────

@router.get("/services", summary="Liste des services disponibles")
def list_services(_user: str = Depends(get_admin_user)):
    services = [{"id": "backend", "label": "Backend (API)", "available": True}]
    for key, filename in _NGINX_FILES.items():
        path = os.path.join(NGINX_LOGS_DIR, filename)
        services.append({
            "id":        f"apt-repo/{key}",
            "label":     f"APT-Repo nginx ({key})",
            "available": os.path.isfile(path),
        })
    return {"services": services}


# ── GET /api/v1/logs ──────────────────────────────────────────────────────────

@router.get("", summary="Historique des logs")
def get_logs(
    service: Optional[str] = Query(None, description="backend | apt-repo | all"),
    level:   Optional[str] = Query(None, description="DEBUG | INFO | WARNING | ERROR"),
    lines:   int           = Query(300, ge=20, le=2000, description="Nombre de lignes par source"),
    _user:   str           = Depends(get_admin_user),
):
    """
    Retourne les logs récents de la stack repod.

    - **service** : `backend` (API Python), `apt-repo` (nginx), `all` (défaut)
    - **level**   : filtre par niveau (`INFO`, `WARNING`, `ERROR`)
    - **lines**   : nombre maximum de lignes par source (défaut 300, max 2000)
    """
    result: list[dict] = []

    want_backend  = service in (None, "all", "backend")
    want_apt_repo = service in (None, "all", "apt-repo")

    # ── Backend ──────────────────────────────────────────────────────────────
    if want_backend:
        buf = get_log_buffer()
        for e in buf[-lines:]:
            if level and e.get("level") != level:
                continue
            result.append(e)

    # ── APT-Repo (nginx) ─────────────────────────────────────────────────────
    if want_apt_repo:
        for log_type, filename in _NGINX_FILES.items():
            path = os.path.join(NGINX_LOGS_DIR, filename)
            for raw in _tail_file(path, lines):
                entry = _nginx_entry(raw, log_type)
                if level and entry["level"] != level:
                    continue
                result.append(entry)

    return {"entries": result, "total": len(result)}


# ── GET /api/v1/logs/stream (SSE) ─────────────────────────────────────────────

@router.get("/stream", summary="Flux SSE temps réel des logs")
async def stream_logs(
    service: Optional[str] = Query(None, description="backend | apt-repo | all"),
    level:   Optional[str] = Query(None, description="DEBUG | INFO | WARNING | ERROR"),
    _user:   str           = Depends(get_admin_user),
):
    """
    Ouvre un flux Server-Sent Events pour les logs en temps réel.

    - **backend**  : émis par le ring-buffer Python dès qu'un log est produit
    - **apt-repo** : tail des fichiers nginx (polling toutes les 2 s)

    Le flux s'interrompt proprement à la déconnexion du client.
    """
    want_backend  = service in (None, "all", "backend")
    want_apt_repo = service in (None, "all", "apt-repo")

    async def generator() -> AsyncIterator[str]:
        # ── 1. Dump du ring buffer existant (50 dernières entrées) ───────────
        if want_backend:
            recent = get_log_buffer()[-50:]
            for e in recent:
                if not level or e.get("level") == level:
                    yield f"data: {json.dumps(e)}\n\n"

        # ── 2. Positions actuelles nginx (pour tail uniquement le nouveau) ───
        file_pos: dict[str, int] = {}
        if want_apt_repo:
            for log_type, filename in _NGINX_FILES.items():
                path = os.path.join(NGINX_LOGS_DIR, filename)
                try:
                    file_pos[log_type] = os.path.getsize(path)
                except OSError:
                    file_pos[log_type] = 0

        # Heartbeat initial — confirme l'établissement du flux au client
        yield ": connected\n\n"

        # ── 3. Abonnement aux nouveaux logs backend ──────────────────────────
        q = subscribe_logs() if want_backend else None

        try:
            while True:
                # Attente du prochain log backend (timeout = 2s pour vérifier nginx aussi)
                if q is not None:
                    try:
                        entry = await asyncio.wait_for(q.get(), timeout=2.0)
                        if not level or entry.get("level") == level:
                            yield f"data: {json.dumps(entry)}\n\n"
                    except asyncio.TimeoutError:
                        pass  # timeout normal — on vérifie nginx ci-dessous

                # ── APT-Repo : tail fichiers nginx ────────────────────────
                if want_apt_repo:
                    for log_type, filename in _NGINX_FILES.items():
                        path = os.path.join(NGINX_LOGS_DIR, filename)
                        try:
                            cur_size = os.path.getsize(path)
                            pos      = file_pos.get(log_type, 0)
                            if cur_size > pos:
                                with open(path, "r", errors="replace") as f:
                                    f.seek(pos)
                                    new_lines = f.readlines()
                                file_pos[log_type] = cur_size
                                for raw in new_lines:
                                    if not raw.strip():
                                        continue
                                    e = _nginx_entry(raw, log_type)
                                    if not level or e["level"] == level:
                                        yield f"data: {json.dumps(e)}\n\n"
                        except OSError:
                            pass

                # Heartbeat si pas de backend queue (apt-repo only mode)
                if q is None:
                    await asyncio.sleep(2.0)
                    yield ": heartbeat\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            if q is not None:
                unsubscribe_logs(q)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )
