# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Routes de visibilité CVE :
- GET  /security/vulnerabilities                 → vue consolidée des CVE cross-paquets
- GET  /security/packages-posture                → posture CVE par paquet (avec fallback validation_steps)
- GET  /security/packages/{name}/{version}/cve   → CVE détaillées d'un paquet
- GET  /security/review-queue                    → file de révision RSSI
- POST /security/check-sla                       → vérification manuelle des SLA CVE
- GET  /security/report                          → rapport d'audit complet (PDF/ISO27001/NIS2)
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from auth.dependencies import get_current_user, get_admin_user
from services.manifest import list_manifests, load_manifest
from services.security_decisions import (
    load_decision, list_all_decisions, get_sla_status,
)
from services.pagination import paginate
from services.format_router import DEFAULT_DISTRIBUTION as _DEFAULT_DISTRIBUTION
from routers.security_common import (
    _cve_message_is_inconclusive,
    _parse_cve_message,
    has_conclusive_cve_scan,
)

router = APIRouter(prefix="/security", tags=["Security"])


@router.get("/vulnerabilities")
def get_vulnerabilities(
    severity: str = Query(None, description="Filtrer par sévérité: critical, high, medium, low"),
    fix_state: str = Query(None, description="Filtrer par état du fix: fixed, not-fixed, unknown"),
    distribution: str = Query(None, description="Filtrer par distribution APT"),
    page: int = Query(1, ge=1, description="Numéro de page (1-indexé)"),
    per_page: int = Query(50, ge=1, le=500, description="Éléments par page"),
    current_user: str = Depends(get_current_user),
):
    """
    Vue consolidée des CVE sur tous les paquets du dépôt.
    Agrège les résultats Grype depuis les manifests — une ligne par CVE,
    avec la liste des paquets affectés.
    """
    manifests = list_manifests()

    # Index CVE → paquets affectés
    cve_index: dict[str, dict] = {}
    packages_scanned: list[dict] = []
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

    for m in manifests:
        cve_results = m.get("cve_results", [])
        distrib = m.get("distribution", _DEFAULT_DISTRIBUTION)

        if distribution and distrib != distribution:
            continue

        if not cve_results:
            continue

        pkg_ref = {
            "name": m["name"],
            "version": m["version"],
            "distribution": distrib,
        }

        counts: dict[str, int] = {s.lower(): 0 for s in _sev_order}
        for cve in cve_results:
            sev = cve.get("severity", "Unknown")
            counts[sev.lower()] = counts.get(sev.lower(), 0) + 1

            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            if cve_id not in cve_index:
                cve_index[cve_id] = {
                    "id": cve_id,
                    "severity": sev,
                    "cvss": cve.get("cvss"),
                    "description": cve.get("description", ""),
                    "fix_state": cve.get("fix_state", "unknown"),
                    "fix_versions": cve.get("fix_versions", []),
                    "urls": cve.get("urls", []),
                    "affected_packages": [],
                }

            # Ajouter ce paquet à la liste des affectés (éviter les doublons)
            pkg_entry = {
                **pkg_ref,
                "package_name": cve.get("package_name", m["name"]),
                "package_version": cve.get("package_version", m["version"]),
                "fix_state": cve.get("fix_state", "unknown"),
                "fix_versions": cve.get("fix_versions", []),
            }
            existing_ids = {
                (p["name"], p["package_version"], p["package_name"])
                for p in cve_index[cve_id]["affected_packages"]
            }
            key = (pkg_ref["name"], pkg_entry["package_version"], pkg_entry["package_name"])
            if key not in existing_ids:
                cve_index[cve_id]["affected_packages"].append(pkg_entry)

        packages_scanned.append({**pkg_ref, **counts})

    # Convertir en liste + filtres
    vulns = list(cve_index.values())

    if severity:
        vulns = [v for v in vulns if v["severity"].lower() == severity.lower()]
    if fix_state:
        vulns = [v for v in vulns if v["fix_state"].lower() == fix_state.lower()]

    # Trier par sévérité puis CVSS desc
    def _sort_key(v):
        sev_idx = _sev_order.index(v["severity"]) if v["severity"] in _sev_order else 99
        return (sev_idx, -(v["cvss"] or 0))

    vulns.sort(key=_sort_key)

    # Résumé global
    summary: dict[str, int] = {s.lower(): 0 for s in _sev_order}
    for v in cve_index.values():
        sev = v["severity"].lower()
        summary[sev] = summary.get(sev, 0) + 1

    return {
        "summary": summary,
        "packages_scanned": len(packages_scanned),
        "vulnerabilities": paginate(vulns, page=page, per_page=per_page),
        "packages": packages_scanned,
    }


@router.get("/packages-posture")
def get_packages_posture(
    distribution: str = Query(None, description="Filtrer par distribution APT"),
    current_user: str = Depends(get_current_user),
):
    """
    Vue posture CVE par paquet :
    - CVE counts par sévérité (depuis cve_results ou fallback validation_steps)
    - Statut hash, date d'import, pire sévérité
    - Actions disponibles selon la sévérité
    """
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

    manifests = list_manifests()
    packages = []

    for m in manifests:
        if distribution and m.get("distribution") != distribution:
            continue

        cve_results = m.get("cve_results", [])
        counts = {s.lower(): 0 for s in _sev_order}
        scanned = False
        scan_source = None

        if cve_results:
            # Données structurées depuis Grype
            scanned = True
            scan_source = "grype"
            for cve in cve_results:
                sev = cve.get("severity", "Unknown").lower()
                if sev in counts:
                    counts[sev] += 1
                else:
                    counts["unknown"] += 1
        else:
            # Fallback : parser le message dans validation_steps[cve]
            for step in m.get("validation_steps", []):
                if step.get("name") == "cve":
                    msg = step.get("message", "")
                    if not _cve_message_is_inconclusive(msg):
                        scanned = True
                        scan_source = "grype-legacy"
                        parsed = _parse_cve_message(msg)
                        counts.update(parsed)
                    break

        # Sévérité la plus grave présente
        worst = None
        for sev in _sev_order:
            if counts.get(sev.lower(), 0) > 0:
                worst = sev
                break

        # Actions recommandées selon la posture
        actions = ["view_cve"]
        if counts.get("critical", 0) > 0:
            actions.append("quarantine")
        if scanned and counts.get("critical", 0) == 0:
            actions.append("accept")

        integrity = m.get("integrity", {})

        # ── Décision RSSI enrichie ───────────────────────────────────────────
        decision = load_decision(m["name"], m.get("version", ""), m.get("arch", "amd64"))
        sla      = get_sla_status(decision) if decision else None

        # KEV & EPSS synthèse
        def _epss_float(c):
            v = c.get("epss_percent") or c.get("epss") or 0
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0

        kev_count    = sum(1 for c in cve_results if c.get("in_kev") or c.get("kev"))
        high_epss    = [c for c in cve_results if _epss_float(c) >= 10.0]

        packages.append({
            "name": m["name"],
            "version": m.get("version", ""),
            "arch": m.get("arch", "amd64"),
            "distribution": m.get("distribution", ""),
            "imported_at": m.get("source", {}).get("imported_at"),
            "imported_by": m.get("source", {}).get("imported_by"),
            "scanned": scanned,
            "scan_source": scan_source,
            "cve_counts": counts,
            "worst_severity": worst,
            "total_cve": sum(counts.values()),
            "kev_count": kev_count,
            "high_epss_count": len(high_epss),
            "hash_verified": bool(integrity.get("sha256")),
            "status": m.get("status", "validated"),
            "actions": actions,
            # Décision RSSI résumée
            "decision_action":  decision.get("action")  if decision else None,
            "decision_expires": decision.get("expires_at") if decision else None,
            "sla_days":         sla.get("days_remaining") if sla else None,
            "sla_status":       sla.get("status") if sla else None,
        })

    # Tri : pire sévérité d'abord, puis par total CVE décroissant, puis par nom
    _rank = {s.lower(): i for i, s in enumerate(_sev_order)}
    packages.sort(key=lambda p: (
        _rank.get((p["worst_severity"] or "").lower(), 99),
        -p["total_cve"],
        p["name"],
    ))

    # Résumé global
    summary = {s.lower(): 0 for s in _sev_order}
    for p in packages:
        for sev, cnt in p["cve_counts"].items():
            summary[sev] = summary.get(sev, 0) + cnt

    return {
        "summary": summary,
        "total_packages": len(packages),
        "scanned_packages": sum(1 for p in packages if p["scanned"]),
        "unscanned_packages": sum(1 for p in packages if not p["scanned"]),
        "packages": packages,
    }


@router.get("/packages/{name}/{version}/cve")
def get_package_cve(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_current_user),
):
    """
    Retourne la liste structurée des CVE d'un paquet spécifique,
    avec fallback sur validation_steps si cve_results est vide.
    """
    manifest = load_manifest(name, version, arch)
    if not manifest:
        # Chercher parmi tous les manifests (arch variable)
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                break
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Manifest introuvable pour {name} {version}")

    cve_results = manifest.get("cve_results", [])
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts = {s.lower(): 0 for s in _sev_order}

    if cve_results:
        for cve in cve_results:
            sev = cve.get("severity", "Unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
    else:
        # Extraire le résumé depuis validation_steps pour l'affichage
        for step in manifest.get("validation_steps", []):
            if step.get("name") == "cve":
                counts = _parse_cve_message(step.get("message", ""))
                break

    # Trier les CVE par sévérité
    def _sev_sort(c):
        s = c.get("severity", "Unknown")
        return _sev_order.index(s) if s in _sev_order else 99

    return {
        "package": name,
        "version": version,
        "arch": arch,
        "distribution": manifest.get("distribution", ""),
        "cve_counts": counts,
        "total": len(cve_results),
        "cve_results": sorted(cve_results, key=_sev_sort),
        # len(cve_results) > 0 confondait "jamais scanné" et "scanné,
        # confirmé sain" (cve_results est vide dans les deux cas) — un
        # paquet réellement propre affichait donc à tort l'avertissement
        # "importé avant la collecte structurée". has_conclusive_cve_scan()
        # regarde aussi le message de l'étape de validation "cve" pour
        # distinguer un scan concluant (même sans CVE trouvée) d'un scan
        # jamais exécuté ou inexploitable.
        "has_structured_data": has_conclusive_cve_scan(manifest),
        # Absent (None) sur un paquet jamais re-matché (créé avant cette
        # fonctionnalité) — voir services/cve_rematch.py.
        "last_rematch_at": manifest.get("last_rematch_at"),
    }


@router.get("/review-queue")
def get_review_queue(
    page: int = Query(1, ge=1, description="Numéro de page (1-indexé)"),
    per_page: int = Query(50, ge=1, le=200, description="Éléments par page"),
    current_user: str = Depends(get_current_user),
):
    """
    File de révision RSSI : paquets en attente de décision.
    Inclut les paquets bloqués (CRITICAL) et en révision (HIGH avec policy=review).
    Pour chaque paquet, affiche les CVE enrichies (EPSS, KEV).
    """
    _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    manifests = list_manifests()
    queue = []

    for m in manifests:
        status = m.get("status", "validated")
        if status not in ("pending_review", "blocked"):
            continue

        cve_results = m.get("cve_results", [])
        counts = {s.lower(): 0 for s in _sev_order}
        for cve in cve_results:
            sev = cve.get("severity", "Unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1

        worst = next((s for s in _sev_order if counts.get(s.lower(), 0) > 0), None)

        # CVE bloquantes / en révision
        kev_cves  = [c for c in cve_results if c.get("in_kev")]
        def _epss_float(c):
            v = c.get("epss_percent", "0%")
            try:
                return float(str(v).rstrip("%"))
            except (ValueError, TypeError):
                return 0.0
        high_epss = [c for c in cve_results if _epss_float(c) >= 10.0]

        # Décision existante éventuelle
        decision = load_decision(m["name"], m.get("version", ""), m.get("arch", "amd64"))
        sla      = get_sla_status(decision) if decision else {"has_sla": False}

        # Déduire le format depuis le nom de fichier (extension)
        filename = m.get("filename", "")
        if filename.endswith(".rpm"):
            pkg_format = "rpm"
        elif filename.endswith(".apk"):
            pkg_format = "apk"
        else:
            pkg_format = "deb"  # défaut pour .deb et cas inconnu

        queue.append({
            "name":         m["name"],
            "version":      m.get("version", ""),
            "arch":         m.get("arch", "amd64"),
            "distribution": m.get("distribution", ""),
            "pkg_format":   pkg_format,
            "imported_at":  m.get("source", {}).get("imported_at"),
            "imported_by":  m.get("source", {}).get("imported_by"),
            "status":       status,
            "worst_severity": worst,
            "cve_counts":   counts,
            "total_cve":    sum(counts.values()),
            "kev_count":    len(kev_cves),
            "high_epss_count": len(high_epss),
            "cve_results":  cve_results,
            "decision":     decision,
            "sla":          sla,
        })

    # Tri : bloqués d'abord, puis par worst severity, puis date
    _rank = {s.lower(): i for i, s in enumerate(_sev_order)}
    queue.sort(key=lambda p: (
        0 if p["status"] == "blocked" else 1,
        _rank.get((p["worst_severity"] or "").lower(), 99),
        p["imported_at"] or "",
    ))

    return {
        "total":           len(queue),
        "blocked_count":   sum(1 for p in queue if p["status"] == "blocked"),
        "review_count":    sum(1 for p in queue if p["status"] == "pending_review"),
        "packages":        paginate(queue, page=page, per_page=per_page),
    }


@router.post("/check-sla")
def trigger_sla_check(current_user: str = Depends(get_admin_user)):
    """Déclenche manuellement la vérification des SLA CVE."""
    from services.sla_alerts import run_sla_check
    result = run_sla_check()
    return result


@router.get("/report")
def get_security_report(current_user: str = Depends(get_current_user)):
    """
    Rapport d'audit complet pour export PDF / ISO 27001 / NIS2.
    Retourne toutes les métriques, décisions, posture CVE consolidée.
    """
    from services.settings import get_settings

    now = datetime.now(timezone.utc)
    settings = get_settings()
    cve_policy = settings.get("cve_policy", {})

    # ── Tous les manifests ────────────────────────────────────────────────────
    manifests = list_manifests()

    # Posture CVE agrégée
    _sevs = ["critical", "high", "medium", "low", "negligible"]
    cve_totals = {s: 0 for s in _sevs}
    packages_with_cve = []
    status_counts: dict[str, int] = {}

    for m in manifests:
        st = m.get("status", "validated")
        status_counts[st] = status_counts.get(st, 0) + 1

        cves = m.get("cve_results", [])
        if cves:
            pkg_counts = {s: 0 for s in _sevs}
            kev = 0
            for cve in cves:
                sev = cve.get("severity", "Unknown").lower()
                if sev in pkg_counts:
                    pkg_counts[sev] += 1
                    cve_totals[sev] += 1
                if cve.get("in_kev"):
                    kev += 1
            worst = next((s for s in _sevs if pkg_counts[s] > 0), None)
            packages_with_cve.append({
                "name":         m["name"],
                "version":      m.get("version", ""),
                "distribution": m.get("distribution", ""),
                "status":       st,
                "cve_counts":   pkg_counts,
                "kev_count":    kev,
                "worst":        worst,
                "total_cve":    sum(pkg_counts.values()),
            })

    packages_with_cve.sort(key=lambda p: (
        _sevs.index(p["worst"]) if p["worst"] in _sevs else 99,
    ))

    # ── Toutes les décisions ──────────────────────────────────────────────────
    all_decisions = list_all_decisions()
    decisions_enriched = []
    for dec in all_decisions:
        sla = get_sla_status(dec)
        decisions_enriched.append({**dec, "sla": sla})

    decisions_enriched.sort(key=lambda d: d.get("decided_at", ""), reverse=True)

    # ── Queue de révision actuelle ────────────────────────────────────────────
    pending = [m for m in manifests if m.get("status") in ("pending_review", "blocked")]

    # ── Résumé ───────────────────────────────────────────────────────────────
    summary = {
        "total_packages":    len(manifests),
        "packages_scanned":  len(packages_with_cve),
        "status_counts":     status_counts,
        "cve_totals":        cve_totals,
        "total_cve":         sum(cve_totals.values()),
        "decisions_count":   len(all_decisions),
        "pending_count":     len(pending),
        "expiring_soon":     sum(
            1 for d in decisions_enriched
            if d["sla"].get("warning") or d["sla"].get("expired")
        ),
    }

    return {
        "generated_at":     now.isoformat(),
        "generated_by":     current_user,
        "period":           "Toutes les décisions enregistrées",
        "cve_policy":       cve_policy,
        "summary":          summary,
        "packages_with_cve": packages_with_cve,
        "decisions":        decisions_enriched,
        "pending_review":   [
            {
                "name":        m["name"],
                "version":     m.get("version", ""),
                "arch":        m.get("arch", "amd64"),
                "distribution": m.get("distribution", ""),
                "status":      m.get("status"),
                "imported_at": m.get("source", {}).get("imported_at"),
                "cve_counts":  {
                    s: sum(1 for c in m.get("cve_results", [])
                           if c.get("severity", "").lower() == s)
                    for s in _sevs
                },
            }
            for m in pending
        ],
    }
