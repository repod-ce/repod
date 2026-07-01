"""
Statistiques de téléchargements — format-agnostique (DEB, RPM, APK).

Source : /repos/logs/downloads.log (nginx access log format "main")
  $remote_addr - $remote_user [$time_local] "$request" $status
  $body_bytes_sent "$http_referer" "$http_user_agent"

Cache mémoire de 2 min (invalidé si le fichier a grossi).
"""

import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

NGINX_LOGS_DIR = Path(os.getenv("NGINX_LOGS_DIR", "/repos/logs"))
DOWNLOADS_LOG  = NGINX_LOGS_DIR / "downloads.log"

_LOG_RE = re.compile(
    r'(?P<ip>\S+) - \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+) '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)

_cache: dict      = {}
_cache_mtime: float = 0.0
_cache_size: int    = 0


# ── Parsers de nom de paquet par format ───────────────────────────────────────

def _parse_deb(filename: str) -> tuple[str, str, str]:
    """name_version_arch.deb → (name, version, arch)"""
    stem = filename[:-4]
    parts = stem.rsplit("_", 2)
    name    = parts[0] if parts else stem
    version = parts[1] if len(parts) > 1 else "unknown"
    arch    = parts[2] if len(parts) > 2 else "unknown"
    return name, version, arch


def _parse_rpm(filename: str) -> tuple[str, str, str]:
    """name-version-release.arch.rpm → (name, version, arch)"""
    stem = filename[:-4]  # enlever .rpm
    # arch = dernier segment après le dernier '.'
    if "." in stem:
        arch = stem.rsplit(".", 1)[1]
        stem = stem.rsplit(".", 1)[0]  # enlever l'arch
    else:
        arch = "unknown"
    # stem = name-version-release
    parts = stem.rsplit("-", 2)
    name    = parts[0] if parts else stem
    version = f"{parts[1]}-{parts[2]}" if len(parts) == 3 else (parts[1] if len(parts) > 1 else "unknown")
    return name, version, arch


def _parse_apk(filename: str) -> tuple[str, str, str]:
    """name-version-r0.apk → (name, version, 'noarch')"""
    stem = filename[:-4]
    parts = stem.rsplit("-", 2)
    name    = parts[0] if parts else stem
    version = parts[1] if len(parts) > 1 else "unknown"
    return name, version, "noarch"


def _detect_client_type(ua: str) -> str:
    ul = ua.lower()
    if "apt" in ul or "debian" in ul:
        return "apt"
    if "dnf" in ul or "yum" in ul or "libdnf" in ul or "urlgrabber" in ul:
        return "dnf"
    if "apk" in ul or "alpine" in ul:
        return "apk"
    if "curl" in ul:
        return "curl"
    if "wget" in ul:
        return "wget"
    return "other"


# ── Parsing du log ─────────────────────────────────────────────────────────────

def _parse_log() -> list[dict]:
    entries = []
    if not DOWNLOADS_LOG.exists():
        return entries

    with open(DOWNLOADS_LOG, "r", errors="replace") as f:
        for line in f:
            m = _LOG_RE.match(line.strip())
            if not m:
                continue
            if int(m.group("status")) not in (200, 206):
                continue

            path     = m.group("path")
            filename = path.rstrip("/").split("/")[-1]

            if filename.endswith(".deb"):
                pkg_format = "deb"
                name, version, arch = _parse_deb(filename)
            elif filename.endswith(".rpm"):
                pkg_format = "rpm"
                name, version, arch = _parse_rpm(filename)
            elif filename.endswith(".apk"):
                pkg_format = "apk"
                name, version, arch = _parse_apk(filename)
            else:
                continue  # on ignore les autres fichiers (.gz, .xz, InRelease…)

            try:
                dt       = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
                date_str = dt.strftime("%Y-%m-%d")
                hour     = dt.hour
            except (ValueError, AttributeError):
                date_str = "unknown"
                hour     = 0

            ua          = m.group("ua")
            client_type = _detect_client_type(ua)

            entries.append({
                "ip":          m.group("ip"),
                "date":        date_str,
                "hour":        hour,
                "filename":    filename,
                "name":        name,
                "version":     version,
                "arch":        arch,
                "pkg_format":  pkg_format,
                "client_type": client_type,
                "bytes":       int(m.group("bytes")),
                "user_agent":  ua,
                "status":      int(m.group("status")),
                "path":        path,
            })

    return entries


def _get_entries() -> list[dict]:
    global _cache, _cache_mtime, _cache_size
    if not DOWNLOADS_LOG.exists():
        return []
    stat = DOWNLOADS_LOG.stat()
    now  = time.time()
    if stat.st_size != _cache_size or (now - _cache_mtime) > 120:
        _cache       = {"entries": _parse_log()}
        _cache_mtime = now
        _cache_size  = stat.st_size
    return _cache["entries"]


# ── API principale ─────────────────────────────────────────────────────────────

def get_download_stats(days: int = 30) -> dict:
    entries = _get_entries()

    cutoff  = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    entries = [e for e in entries if e["date"] >= cutoff]

    log_available = DOWNLOADS_LOG.exists()

    if not entries:
        return {
            "summary": {
                "total_downloads": 0,
                "unique_packages":  0,
                "unique_clients":   0,
                "total_bytes":      0,
                "per_format":       {"deb": 0, "rpm": 0, "apk": 0},
                "per_client_type":  {},
                "avg_per_day":      0,
                "peak_day":         None,
                "log_available":    log_available,
            },
            "per_package": [],
            "per_day":     [],
            "recent":      [],
        }

    # ── Summary ────────────────────────────────────────────────────────────────
    total_downloads = len(entries)
    unique_packages  = len({e["name"] for e in entries})
    unique_clients   = len({e["ip"] for e in entries})
    total_bytes      = sum(e["bytes"] for e in entries)

    fmt_counts: dict[str, int] = defaultdict(int)
    client_type_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        fmt_counts[e["pkg_format"]]    += 1
        client_type_counts[e["client_type"]] += 1

    # ── Par jour ───────────────────────────────────────────────────────────────
    day_data: dict[str, dict] = defaultdict(lambda: {"downloads": 0, "bytes": 0})
    for e in entries:
        day_data[e["date"]]["downloads"] += 1
        day_data[e["date"]]["bytes"]     += e["bytes"]

    per_day = sorted(
        [{"date": d, **v} for d, v in day_data.items()],
        key=lambda x: x["date"],
    )

    avg_per_day = round(total_downloads / len(per_day)) if per_day else 0
    peak_day    = max(per_day, key=lambda x: x["downloads"]) if per_day else None

    # ── Par paquet ─────────────────────────────────────────────────────────────
    pkg_data: dict[str, dict] = defaultdict(lambda: {
        "downloads": 0, "bytes": 0, "versions": set(),
        "clients": set(), "formats": set(),
    })
    for e in entries:
        d = pkg_data[e["name"]]
        d["downloads"]        += 1
        d["bytes"]            += e["bytes"]
        d["versions"].add(e["version"])
        d["clients"].add(e["ip"])
        d["formats"].add(e["pkg_format"])

    per_package = sorted(
        [
            {
                "name":      name,
                "downloads": d["downloads"],
                "bytes":     d["bytes"],
                "versions":  sorted(d["versions"]),
                "clients":   len(d["clients"]),
                "format":    next(iter(d["formats"])) if len(d["formats"]) == 1
                             else "mixed",
            }
            for name, d in pkg_data.items()
        ],
        key=lambda x: x["downloads"],
        reverse=True,
    )[:50]

    # ── Récents ────────────────────────────────────────────────────────────────
    recent = entries[-50:][::-1]

    return {
        "summary": {
            "total_downloads": total_downloads,
            "unique_packages":  unique_packages,
            "unique_clients":   unique_clients,
            "total_bytes":      total_bytes,
            "per_format":       {
                "deb": fmt_counts.get("deb", 0),
                "rpm": fmt_counts.get("rpm", 0),
                "apk": fmt_counts.get("apk", 0),
            },
            "per_client_type":  dict(client_type_counts),
            "avg_per_day":      avg_per_day,
            "peak_day":         peak_day,
            "log_available":    True,
        },
        "per_package": per_package,
        "per_day":     per_day,
        "recent":      recent,
    }
