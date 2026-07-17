"""
services/dashboard.py — Tableau de bord enrichi.

Métriques disponibles :
  • get_cve_trends(windows)      → évolution des CVEs sur N jours glissants
  • get_top_packages(limit)      → top paquets par imports et par téléchargements
  • get_sla_overdue(max_age)     → paquets en attente de review dépassant le SLA
  • get_distribution_stats()     → statistiques par distribution
  • get_dashboard()              → toutes les métriques regroupées

Structure CVE trend (par fenêtre temporelle) :
  {
    "window_days": int,
    "period_start": str,   # ISO-8601
    "packages_imported": int,
    "cve_totals": {
      "critical": int, "high": int, "medium": int, "low": int, "negligible": int
    },
    "packages_with_critical": int,
    "packages_with_high": int,
  }

Structure SLA overdue :
  {
    "name": str, "version": str, "arch": str,
    "imported_at": str,
    "age_days": float,
    "cve_summary": dict,
    "status": str,
  }

Structure distribution stats :
  {
    "distribution": str,
    "package_count": int,
    "latest_import": str | None,
    "cve_totals": dict,
    "packages_with_issues": int,   # au moins 1 CVE critical ou high
  }
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger("dashboard")

_SEVERITIES = ("critical", "high", "medium", "low", "negligible")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _age_days(dt: datetime | None) -> float:
    if dt is None:
        return float("inf")
    return (_now() - dt).total_seconds() / 86_400.0


def _zero_cve() -> dict:
    return {s: 0 for s in _SEVERITIES}


def _sum_cve(acc: dict, cve: dict | None) -> None:
    """Ajoute les compteurs d'un cve_summary à acc, en place."""
    if not cve:
        return
    for sev in _SEVERITIES:
        acc[sev] = acc.get(sev, 0) + int(cve.get(sev, 0) or 0)


def _iter_all_versions(index: dict):
    """Yield (name, version, ver_meta) for every version in the index."""
    for name, pkg in index.get("packages", {}).items():
        for ver, meta in pkg.get("versions", {}).items():
            yield name, ver, meta


# ── CVE trends ────────────────────────────────────────────────────────────────

def get_cve_trends(windows: list[int] | None = None) -> list[dict]:
    """
    Calcule les tendances CVE sur des fenêtres glissantes.

    Paramètre
    ---------
    windows : liste de durées en jours (défaut : [30, 60, 90])

    Pour chaque fenêtre, compte les versions importées dans la période
    et agrège leurs CVEs.
    """
    from services.indexer import get_index

    if windows is None:
        windows = [30, 60, 90]

    index  = get_index()
    now    = _now()
    result = []

    for w in windows:
        cutoff       = now - timedelta(days=w)
        cve_totals   = _zero_cve()
        pkg_imported = 0
        crit_count   = 0
        high_count   = 0

        for _name, _ver, meta in _iter_all_versions(index):
            dt = _parse_dt(meta.get("imported_at"))
            if dt is None or dt < cutoff:
                continue
            pkg_imported += 1
            cve = meta.get("cve_summary")
            _sum_cve(cve_totals, cve)
            if cve:
                if int(cve.get("critical", 0) or 0) > 0:
                    crit_count += 1
                if int(cve.get("high", 0) or 0) > 0:
                    high_count += 1

        result.append({
            "window_days":             w,
            "period_start":            cutoff.isoformat(),
            "packages_imported":       pkg_imported,
            "cve_totals":              cve_totals,
            "packages_with_critical":  crit_count,
            "packages_with_high":      high_count,
        })

    return result


# ── Top paquets ───────────────────────────────────────────────────────────────

def get_top_packages(limit: int = 10) -> dict:
    """
    Retourne les top paquets selon deux critères :
      • by_versions     : paquets avec le plus de versions importées
      • by_size         : paquets les plus volumineux (somme de toutes versions)
      • recently_added  : derniers paquets importés (latest import)

    Paramètre
    ---------
    limit : nombre de paquets à retourner par catégorie (défaut 10)
    """
    from services.indexer import get_index

    index = get_index()

    by_versions: list[dict[str, Any]] = []
    by_size:     list[dict[str, Any]] = []
    by_recent:   list[dict[str, Any]] = []

    for name, pkg in index.get("packages", {}).items():
        versions = pkg.get("versions", {})
        if not versions:
            continue

        version_count = len(versions)
        total_size    = sum(int(m.get("size_bytes", 0) or 0) for m in versions.values())

        # Date d'import la plus récente (toutes versions confondues)
        latest_dt = None
        for meta in versions.values():
            dt = _parse_dt(meta.get("imported_at"))
            if dt and (latest_dt is None or dt > latest_dt):
                latest_dt = dt

        entry = {
            "name":          name,
            "version_count": version_count,
            "total_size_mb": round(total_size / (1024 * 1024), 3),
            "latest_import": latest_dt.isoformat() if latest_dt else None,
        }
        by_versions.append(entry)
        by_size.append(entry)
        by_recent.append(entry)

    by_versions.sort(key=lambda e: e["version_count"], reverse=True)
    by_size.sort(key=lambda e: e["total_size_mb"], reverse=True)
    by_recent.sort(
        key=lambda e: e["latest_import"] or "",
        reverse=True,
    )

    return {
        "by_versions":    by_versions[:limit],
        "by_size":        by_size[:limit],
        "recently_added": by_recent[:limit],
    }


# ── SLA overdue ───────────────────────────────────────────────────────────────

def get_sla_overdue(max_age_days: int | None = None) -> list[dict]:
    """
    Retourne les versions en statut "pending_review" dont l'âge dépasse le SLA.

    Paramètre
    ---------
    max_age_days : âge maximum autorisé sans décision de review (défaut : 7 jours).
                   0 → désactivé (retourne []).
                   Peut être lu depuis settings.json (sla.review_max_age_days).

    Tri : les plus anciens en premier (urgence décroissante).
    """
    from services.indexer import get_index

    if max_age_days is None:
        try:
            from services.settings import get_settings
            settings = get_settings()
            max_age_days = int(settings.get("sla", {}).get("review_max_age_days", 7))
        except Exception:
            max_age_days = 7

    if max_age_days <= 0:
        return []

    index    = get_index()
    overdue  = []

    for name, ver, meta in _iter_all_versions(index):
        status = meta.get("status", "validated")
        if status != "pending_review":
            continue

        dt  = _parse_dt(meta.get("imported_at"))
        age = _age_days(dt)

        if age > max_age_days:
            overdue.append({
                "name":        name,
                "version":     ver,
                "arch":        meta.get("arch", "amd64"),
                "imported_at": meta.get("imported_at", ""),
                "age_days":    round(age, 2),
                "cve_summary": meta.get("cve_summary"),
                "status":      status,
            })

    overdue.sort(key=lambda e: e["age_days"], reverse=True)
    return overdue


# ── Métriques par distribution ────────────────────────────────────────────────

def get_distribution_stats() -> list[dict]:
    """
    Calcule les statistiques par distribution (jammy, noble, focal…).

    Retourne une liste triée par nombre de paquets décroissant :
      [
        {
          "distribution":       str,
          "package_count":      int,    # paquets uniques dans cette distribution
          "version_count":      int,    # total des versions dans cette distribution
          "latest_import":      str | None,
          "cve_totals":         dict,
          "packages_with_critical": int,
          "packages_with_high":     int,
        }
      ]
    """
    from services.indexer import get_index

    index = get_index()
    stats: dict[str, dict] = {}

    def _get_or_create(dist: str) -> dict:
        if dist not in stats:
            stats[dist] = {
                "distribution":           dist,
                "package_names":          set(),
                "version_count":          0,
                "latest_import":          None,
                "cve_totals":             _zero_cve(),
                "packages_with_critical": 0,
                "packages_with_high":     0,
            }
        return stats[dist]

    for name, _ver, meta in _iter_all_versions(index):
        # Distribution principale de la version
        from services.format_router import DEFAULT_DISTRIBUTION as _DEF_DIST
        primary_dist = meta.get("distribution") or _DEF_DIST
        _process_version(stats, name, meta, primary_dist)

        # Distributions promues
        for promoted in (meta.get("promoted_distributions") or []):
            _process_version(stats, name, meta, promoted)

    # Sérialisation (retire le set interne)
    result = []
    for entry in stats.values():
        cve_totals = entry["cve_totals"]
        result.append({
            "distribution":           entry["distribution"],
            "package_count":          len(entry["package_names"]),
            "version_count":          entry["version_count"],
            "latest_import":          entry["latest_import"],
            "cve_totals":             cve_totals,
            "packages_with_critical": entry["packages_with_critical"],
            "packages_with_high":     entry["packages_with_high"],
        })

    result.sort(key=lambda e: e["package_count"], reverse=True)
    return result


def _process_version(stats: dict, name: str, meta: dict, dist: str) -> None:
    """Met à jour le bucket de stats pour une (version, distribution) donnée."""
    entry = _get_stats_entry(stats, dist)
    entry["package_names"].add(name)
    entry["version_count"] += 1

    dt = _parse_dt(meta.get("imported_at"))
    if dt:
        if entry["latest_import"] is None or dt.isoformat() > entry["latest_import"]:
            entry["latest_import"] = dt.isoformat()

    cve = meta.get("cve_summary")
    _sum_cve(entry["cve_totals"], cve)
    if cve:
        if int(cve.get("critical", 0) or 0) > 0:
            entry["packages_with_critical"] += 1
        if int(cve.get("high", 0) or 0) > 0:
            entry["packages_with_high"] += 1


def _get_stats_entry(stats: dict, dist: str) -> dict:
    if dist not in stats:
        stats[dist] = {
            "distribution":           dist,
            "package_names":          set(),
            "version_count":          0,
            "latest_import":          None,
            "cve_totals":             _zero_cve(),
            "packages_with_critical": 0,
            "packages_with_high":     0,
        }
    return stats[dist]


# ── Dashboard principal ───────────────────────────────────────────────────────

def get_dashboard(
    trend_windows: list[int] | None = None,
    top_limit: int = 10,
    sla_max_age_days: int | None = None,
) -> dict:
    """
    Agrège toutes les métriques du tableau de bord.

    Retourne
    --------
    {
      "generated_at":   str,              # ISO-8601
      "cve_trends":     list[dict],
      "top_packages":   dict,
      "sla_overdue":    list[dict],
      "distributions":  list[dict],
      "summary": {
        "total_packages":  int,
        "total_versions":  int,
        "sla_overdue_count": int,
        "critical_packages": int,   # au moins 1 CVE critique dans toutes versions
      }
    }
    """
    from services.indexer import get_index

    cve_trends = get_cve_trends(trend_windows)
    top_pkgs   = get_top_packages(top_limit)
    sla        = get_sla_overdue(sla_max_age_days)
    dists      = get_distribution_stats()

    index = get_index()
    packages = index.get("packages", {})
    total_versions = sum(
        len(pkg.get("versions", {})) for pkg in packages.values()
    )

    # Paquets avec au moins une CVE critique (toutes versions)
    critical_pkgs = 0
    for pkg in packages.values():
        for meta in pkg.get("versions", {}).values():
            cve = meta.get("cve_summary") or {}
            if int(cve.get("critical", 0) or 0) > 0:
                critical_pkgs += 1
                break

    return {
        "generated_at":  _now().isoformat(),
        "cve_trends":    cve_trends,
        "top_packages":  top_pkgs,
        "sla_overdue":   sla,
        "distributions": dists,
        "summary": {
            "total_packages":    len(packages),
            "total_versions":    total_versions,
            "sla_overdue_count": len(sla),
            "critical_packages": critical_pkgs,
        },
    }
