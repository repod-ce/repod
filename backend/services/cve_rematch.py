# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Re-matching CVE périodique via SBOM stocké (Grype seul, APT/RPM/APK).

Un paquet n'est aujourd'hui scanné par Grype qu'UNE SEULE FOIS, à l'upload/
import. Ce module rejoue périodiquement le MÊME moteur contre sa base de
vulnérabilités *actuelle* (rafraîchie quotidiennement par
security_sync_daily), sans jamais rouvrir le fichier `.deb`/`.rpm`/`.apk`
d'origine dans pool/ : `grype sbom:<fichier>` relit le SBOM CycloneDX
capturé à l'upload/import (voir services/component_sbom.py et
services/validator_apt.py:_run_grype_and_capture_sbom()) — une opération
locale, nettement moins coûteuse qu'un scan complet (pas de ré-extraction
du binaire).

cve_results est simplement rafraîchi avec le résultat du nouveau matching ;
seules les CVE VRAIMENT NOUVELLES (absentes du set précédent) sont évaluées
contre cve_policy — une CVE déjà connue qui disparaîtrait du nouveau
matching (base Grype corrigée depuis) ne redéclenche jamais de décision,
elle est simplement retirée de la liste affichée.

Portée V1 : APT/RPM/APK uniquement.
"""
import json
import logging
import os
import subprocess
import tempfile
import time
from datetime import datetime, timezone

logger = logging.getLogger("cve_rematch")

_ELIGIBLE_PKG_TYPES = ("deb", "rpm", "apk")


def _distro_map_for(pkg_type: str) -> dict:
    """Chaque format a sa propre table de correspondance codename → chaîne
    distro Grype (services/validator_{apt,rpm,apk}.py:_DISTRO_MAP) — import
    différé pour éviter d'alourdir l'import de ce module au démarrage."""
    if pkg_type == "deb":
        from services.validator_apt import _DISTRO_MAP
        return _DISTRO_MAP
    if pkg_type == "rpm":
        from services.validator_rpm import _DISTRO_MAP
        return _DISTRO_MAP
    if pkg_type == "apk":
        from services.validator_apk import _DISTRO_MAP
        return _DISTRO_MAP
    return {}


def _fetch_eligible_manifests(limit: int) -> list[dict]:
    from sqlalchemy import text

    from db.engine import db_conn
    from services.manifest import _row_to_manifest

    placeholders = ", ".join(f":t{i}" for i in range(len(_ELIGIBLE_PKG_TYPES)))
    params = {f"t{i}": t for i, t in enumerate(_ELIGIBLE_PKG_TYPES)}
    params["limit"] = limit

    with db_conn() as conn:
        rows = conn.execute(
            text(
                f"SELECT * FROM manifests WHERE pkg_type IN ({placeholders}) AND status = 'validated' "
                f"ORDER BY updated_at ASC NULLS FIRST LIMIT :limit"
            ),
            params,
        ).mappings().fetchall()
    return [_row_to_manifest(row) for row in rows]


def rematch_one(manifest: dict) -> dict:
    """
    Rejoue le matching Grype pour UN manifest via son SBOM stocké.

    Retourne {"status": "validated"|"pending_review"|"skipped"|"error",
              "name", "version", "pkg_type", "message"}.
    """
    from services.component_sbom import load_component_sbom
    from services.cve_enrichment import enrich_cve_list
    from services.manifest import save_manifest
    from services.settings import get_settings
    from services.validator_apt import parse_grype_matches

    name     = manifest["name"]
    version  = manifest["version"]
    arch     = manifest.get("arch", "amd64")
    pkg_type = manifest.get("type", "deb")

    sbom = load_component_sbom(name, version, arch)
    if not sbom:
        return {
            "status": "skipped", "name": name, "version": version, "pkg_type": pkg_type,
            "message": "aucun SBOM stocké — jamais capturé, ou paquet antérieur à cette fonctionnalité",
        }

    fd, tmp_path = tempfile.mkstemp(suffix=".cdx.json", prefix="grype-rematch-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sbom, f)

        grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
        grype_distro = _distro_map_for(pkg_type).get(manifest.get("distribution") or "", "")

        cmd = ["grype", f"sbom:{tmp_path}", "-o", "json", "--add-cpes-if-none"]
        if grype_distro:
            cmd += ["--distro", grype_distro]

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir, "GRYPE_DB_AUTO_UPDATE": "false"},
            )
        except subprocess.TimeoutExpired:
            return {"status": "error", "name": name, "version": version, "pkg_type": pkg_type,
                    "message": "grype sbom: — timeout"}

        if r.returncode not in (0, 1):
            return {"status": "error", "name": name, "version": version, "pkg_type": pkg_type,
                    "message": (r.stderr or r.stdout)[:300]}

        try:
            data = json.loads(r.stdout)
        except (json.JSONDecodeError, ValueError):
            return {"status": "error", "name": name, "version": version, "pkg_type": pkg_type,
                    "message": "réponse grype illisible"}
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    new_cve_list = parse_grype_matches(data)
    old_ids = {c["id"] for c in (manifest.get("cve_results") or []) if c.get("id")}
    new_ids = {c["id"] for c in new_cve_list if c.get("id")}
    newly_appeared = new_ids - old_ids

    try:
        enrich_cve_list(new_cve_list)
    except Exception as exc:
        logger.warning("[cve_rematch] Enrichissement EPSS/KEV ignoré pour %s %s : %s", name, version, exc)

    cve_policy = get_settings().get("cve_policy", {}) or {}
    worst_action = "allow"
    for cid in newly_appeared:
        cve = next((c for c in new_cve_list if c["id"] == cid), None)
        if not cve:
            continue
        action = cve_policy.get(cve.get("severity", "Unknown").lower(), "allow")
        if action == "block":
            worst_action = "block"
        elif action == "review" and worst_action != "block":
            worst_action = "review"

    manifest["cve_results"]     = new_cve_list
    manifest["last_rematch_at"] = datetime.now(timezone.utc).isoformat()

    needs_decision = worst_action in ("block", "review") and manifest.get("status") == "validated"
    if needs_decision:
        manifest["status"] = "pending_review"
        manifest.setdefault("validation_steps", []).append({
            "name": "cve_rematch", "passed": False, "warning": True,
            "message": f"Re-scan CVE — {len(newly_appeared)} CVE nouvelle(s) depuis le dernier scan",
            "detail": ", ".join(sorted(newly_appeared))[:500],
        })

    save_manifest(manifest)

    if needs_decision:
        from services.audit import log as audit_log
        audit_log("CVE_REMATCH", "system", "PENDING_REVIEW",
                  package=name, version=version,
                  detail=f"{len(newly_appeared)} CVE nouvelle(s) détectée(s) par re-matching",
                  extra={"new_cve_ids": sorted(newly_appeared)})
        return {"status": "pending_review", "name": name, "version": version, "pkg_type": pkg_type,
                "message": f"{len(newly_appeared)} CVE nouvelle(s) — décision RSSI requise"}

    return {"status": "validated", "name": name, "version": version, "pkg_type": pkg_type,
            "message": f"aucune CVE nouvelle significative ({len(newly_appeared)} sous le seuil de politique)"}


def run_cve_rematch(
    max_artifacts: int | None = None,
    max_runtime_minutes: int | None = None,
    progress_cb=None,
) -> dict:
    """
    Balaie les paquets APT/RPM/APK `validated` les plus anciennement
    (re-)scannés, jusqu'à max_artifacts ou max_runtime_minutes.
    """
    started = time.monotonic()
    deadline = started + (max_runtime_minutes * 60) if max_runtime_minutes else None

    summary = {"scanned": 0, "flagged": 0, "errors": 0, "skipped": 0}
    manifests = _fetch_eligible_manifests(max_artifacts or 50)
    total = len(manifests)
    for manifest in manifests:
        if deadline is not None and time.monotonic() >= deadline:
            break
        result = rematch_one(manifest)
        if result["status"] == "skipped":
            summary["skipped"] += 1
        else:
            summary["scanned"] += 1
            if result["status"] == "pending_review":
                summary["flagged"] += 1
            elif result["status"] == "error":
                summary["errors"] += 1
        if progress_cb:
            progress_cb(summary["scanned"] + summary["skipped"], total)

    return summary


def run_cve_rematch_daily() -> dict:
    """Point d'entrée du cron `cve_rematch_daily` — lit ses propres limites
    depuis settings.json à chaque exécution (même convention que les autres
    jobs planifiés)."""
    from services.settings import get_settings

    cfg = get_settings().get("cve_rematch", {})
    return run_cve_rematch(
        max_artifacts=cfg.get("max_artifacts_per_run", 50),
        max_runtime_minutes=cfg.get("max_runtime_minutes", 30),
    )
