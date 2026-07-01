# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Pipeline de validation d'artefacts.
Vérifie l'intégrité, les dépendances et le format avant d'accepter un artefact.
"""
import json
import logging
import os
import subprocess
import hashlib
from pathlib import Path

logger = logging.getLogger("validator")
from services.manifest import parse_deb_fields, parse_dependencies, compute_sha256

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


def _extract_cvss(vuln: dict) -> float | None:
    """Extrait le score CVSS le plus pertinent depuis un objet vulnérabilité Grype."""
    for metric in vuln.get("cvss", []):
        score = metric.get("metrics", {}).get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    return None


# Correspondance codename APT → chaîne distro Grype
_DISTRO_MAP: dict[str, str] = {
    "focal":    "ubuntu:20.04",
    "jammy":    "ubuntu:22.04",
    "noble":    "ubuntu:24.04",
    "buster":   "debian:10",
    "bullseye": "debian:11",
    "bookworm": "debian:12",
}


class ValidationResult:
    def __init__(self):
        self.steps: list[dict] = []
        self.passed = True
        self.deps: list[dict] = []        # dépendances avec available_internally renseigné
        self.cve_results: list[dict] = []  # liste complète et structurée des CVE (Grype)
        # Statut issu de la politique CVE :
        #   "approved"       → aucun CVE bloquant/en révision
        #   "pending_review" → des CVE déclenchent une révision RSSI
        #   "blocked"        → des CVE déclenchent un blocage immédiat
        self.cve_status: str = "approved"

    def add_step(self, name: str, passed: bool, message: str, detail: str = "", warning: bool = False):
        entry = {
            "name": name,
            "passed": passed,
            "message": message,
            "detail": detail,
        }
        if warning:
            entry["warning"] = True
        self.steps.append(entry)
        if not passed and not warning:
            self.passed = False

    def to_dict(self) -> dict:
        missing = [d["name"] for d in self.deps if not d.get("available_internally", True)]
        return {
            "passed":      self.passed,
            "cve_status":  self.cve_status,
            "steps":       self.steps,
            "deps_missing": missing,   # liste des dépendances absentes du dépôt
        }


def validate_format(deb_path: str, result: ValidationResult):
    """Vérifie que le fichier est un .deb valide."""
    if not deb_path.endswith(".deb"):
        result.add_step("format", False, "Extension invalide — seuls les .deb sont acceptés")
        return

    r = subprocess.run(
        ["dpkg-deb", "--info", deb_path],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        result.add_step("format", False, "Fichier .deb corrompu ou invalide", r.stderr)
    else:
        result.add_step("format", True, "Format .deb valide")


def validate_checksum(deb_path: str, expected_sha256: str | None, result: ValidationResult):
    """Calcule et vérifie le SHA-256."""
    actual = compute_sha256(deb_path)
    if expected_sha256 and expected_sha256 != actual:
        result.add_step(
            "checksum", False,
            "SHA-256 ne correspond pas",
            f"Attendu: {expected_sha256}\nObtenu:  {actual}"
        )
    else:
        result.add_step("checksum", True, f"SHA-256: {actual}")


def validate_gpg(deb_path: str, result: ValidationResult, required: bool = False):
    """Vérifie la signature GPG (.sig ou .asc à côté du fichier).

    Si `required` est True (politique de sécurité `validation.gpg_required`),
    l'absence de signature ou une signature invalide fait échouer la validation.
    """
    sig_path = deb_path + ".sig"
    asc_path = deb_path + ".asc"

    sig_file = None
    if os.path.exists(sig_path):
        sig_file = sig_path
    elif os.path.exists(asc_path):
        sig_file = asc_path

    if sig_file is None:
        if required:
            result.add_step("gpg", False, "Signature GPG requise mais absente", "Politique de sécurité : gpg_required=true")
        else:
            result.add_step("gpg", True, "Pas de signature GPG (non requis)", "Signature optionnelle absente")
        return

    r = subprocess.run(
        ["gpg", "--verify", sig_file, deb_path],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        result.add_step("gpg", True, "Signature GPG valide", r.stderr)
    else:
        result.add_step("gpg", False, "Signature GPG invalide", r.stderr)


def validate_provenance_sha256(deb_path: str, expected_sha256: str | None, result: ValidationResult):
    """
    Vérifie le SHA256 du fichier téléchargé contre celui stocké dans l'index Packages.gz.
    Protège contre les attaques man-in-the-middle et les corruptions de source.
    """
    if not expected_sha256:
        result.add_step(
            "provenance", True,
            "Provenance non vérifiable (import manuel)",
            "Aucun SHA256 de référence disponible dans l'index"
        )
        return

    actual = compute_sha256(deb_path)
    if actual != expected_sha256:
        result.add_step(
            "provenance", False,
            "SHA256 ne correspond pas à l'index Packages.gz — fichier suspect",
            f"Attendu (Packages.gz) : {expected_sha256}\nObtenu               : {actual}"
        )
    else:
        result.add_step(
            "provenance", True,
            "Provenance vérifiée — SHA256 conforme à Packages.gz",
            f"SHA256 : {actual}"
        )


CLAMD_SOCKET = "/var/run/clamav/clamd.ctl"


def _clamd_scan(file_path: str, timeout: int = 60) -> tuple[str, str | None]:
    """
    Envoie le fichier au daemon clamd via socket UNIX (protocole INSTREAM).
    Retourne (status, threat) où status = "OK" | "FOUND" | "ERROR".
    Utilise INSTREAM pour éviter les problèmes de permissions sur le fichier.
    """
    import socket
    import struct

    CHUNK_SIZE = 1024 * 128  # 128 Ko par chunk

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(CLAMD_SOCKET)
        sock.sendall(b"zINSTREAM\0")
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sock.sendall(struct.pack("!I", len(chunk)) + chunk)
        sock.sendall(struct.pack("!I", 0))  # fin du stream

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
    finally:
        sock.close()

    resp_str = response.decode("utf-8", errors="replace").strip().rstrip("\0")
    # Format réponse clamd : "stream: OK" ou "stream: Eicar-Test-Signature FOUND"
    if resp_str.endswith("OK"):
        return "OK", None
    elif "FOUND" in resp_str:
        threat = resp_str.replace("stream:", "").replace("FOUND", "").strip()
        return "FOUND", threat
    else:
        return "ERROR", resp_str


def validate_clamav(deb_path: str, result: ValidationResult):
    """
    Scan antivirus ClamAV du fichier .deb.
    Utilise le daemon clamd via socket UNIX (INSTREAM) — les signatures
    restent chargées en mémoire, le scan est rapide et ne cause pas d'OOM.
    Fallback sur clamscan si le daemon n'est pas disponible.
    """
    import os

    # ── Priorité : daemon clamd via socket ──────────────────────────────────
    if os.path.exists(CLAMD_SOCKET):
        try:
            status, threat = _clamd_scan(deb_path, timeout=60)
            if status == "OK":
                result.add_step("antivirus", True, "ClamAV — aucune menace détectée (clamd)")
            elif status == "FOUND":
                result.add_step(
                    "antivirus", False,
                    "ClamAV — menace détectée : fichier rejeté",
                    threat or "Menace inconnue",
                )
            else:
                result.add_step(
                    "antivirus", True,
                    "ClamAV — scan incomplet (avertissement)",
                    threat or "Erreur daemon clamd",
                )
            return
        except Exception as e:
            logger.warning(f"[clamav] Erreur clamd socket, fallback clamscan : {e}")

    # ── Fallback : clamscan (charge les signatures — plus lent) ─────────────
    check = subprocess.run(["which", "clamscan"], capture_output=True, text=True)
    if check.returncode != 0:
        result.add_step(
            "antivirus", True,
            "ClamAV non disponible — scan ignoré",
            "Installez clamav pour activer le scan antivirus",
        )
        return

    try:
        r = subprocess.run(
            ["clamscan", "--no-summary", "--infected", deb_path],
            capture_output=True, text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        result.add_step(
            "antivirus", True,
            "ClamAV — scan timeout (avertissement)",
            "Le scan a dépassé le délai imparti",
        )
        return

    if r.returncode == 0:
        result.add_step("antivirus", True, "ClamAV — aucune menace détectée (clamscan)")
    elif r.returncode == 1:
        threat = r.stdout.strip() or "Menace inconnue"
        result.add_step("antivirus", False, "ClamAV — menace détectée : fichier rejeté", threat)
    else:
        detail = r.stderr.strip() or r.stdout.strip() or "Erreur clamscan inconnue"
        result.add_step("antivirus", True, "ClamAV — scan incomplet (avertissement)", detail)


def _extract_description(match: dict) -> str:
    vuln = match.get("vulnerability", {})
    if vuln.get("description"):
        return vuln["description"]
    for related in match.get("relatedVulnerabilities", []):
        if related.get("description"):
            return related["description"]
    return ""


def validate_cve_grype(
    deb_path: str,
    result: ValidationResult,
    fail_on: str = "critical",   # conservé pour compat ascendante
    distro: str | None = None,
    cve_policy: dict | None = None,
    auto_enrich: bool = True,
):
    """
    Scan CVE avec Grype sur le fichier .deb.

    cve_policy : dict issu de settings["cve_policy"]
      { "critical": "block", "high": "review", "medium": "warn", ... }
      Prioritaire sur fail_on si fourni.

    auto_enrich : enrichir les CVE avec EPSS + KEV CISA si True.
    """
    # Vérifier que grype est disponible
    check = subprocess.run(["which", "grype"], capture_output=True, text=True)
    if check.returncode != 0:
        result.add_step(
            "cve", True,
            "Grype non disponible — scan CVE ignoré",
            "Le binaire grype est absent du conteneur"
        )
        return

    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")

    # Résoudre la chaîne distro Grype depuis le codename APT si nécessaire
    grype_distro = _DISTRO_MAP.get(distro or "", distro or "")

    cmd = ["grype", deb_path, "-o", "json", "--add-cpes-if-none"]
    if grype_distro:
        cmd += ["--distro", grype_distro]

    try:
        r = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300,
            env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir, "GRYPE_DB_AUTO_UPDATE": "false"},
        )
    except subprocess.TimeoutExpired:
        result.add_step("cve", True, "Grype — timeout (> 5 min), scan CVE ignoré")
        return

    # Grype : 0 = aucune vuln, 1 = vulns trouvées, autres = erreur
    if r.returncode not in (0, 1):
        result.add_step(
            "cve", True,
            "Grype — scan incomplet (avertissement non bloquant)",
            (r.stderr or r.stdout)[:500],
        )
        return

    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        result.add_step("cve", True, "Grype — réponse illisible (avertissement)", r.stdout[:300])
        return

    matches = data.get("matches", [])

    # Comptage par sévérité + liste complète structurée
    _order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts: dict[str, int] = {s: 0 for s in _order}
    cve_list: list[dict] = []

    for match in matches:
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        sev = vuln.get("severity", "Unknown")
        if sev not in counts:
            sev = "Unknown"
        counts[sev] += 1

        fix_info = vuln.get("fix", {})
        cve_list.append({
            "id":              vuln.get("id", ""),
            "severity":        sev,
            "cvss":            _extract_cvss(vuln),
            "description":     _extract_description(match),
            "package_name":    artifact.get("name", ""),
            "package_version": artifact.get("version", ""),
            "package_type":    artifact.get("type", ""),
            "fix_state":       fix_info.get("state", "unknown"),
            "fix_versions":    fix_info.get("versions", []),
            "urls":            vuln.get("urls", [])[:3],
            # Champs enrichis (remplis ci-dessous)
            "epss":         0.0,
            "epss_percent": 0.0,
            "epss_label":   "Faible",
            "in_kev":       False,
        })

    # ── Enrichissement EPSS + KEV ───────────────────────────────────────────
    if auto_enrich and cve_list:
        try:
            from services.cve_enrichment import enrich_cve_list
            enrich_cve_list(cve_list)
        except Exception as _enrich_err:
            pass  # non bloquant : l'enrichissement est un bonus

    # Stocker la liste complète dans le résultat (pour le manifest)
    result.cve_results = cve_list

    # Résumé compact
    summary_parts = [f"{counts[s]} {s}" for s in _order if counts[s] > 0]
    summary = " | ".join(summary_parts) if summary_parts else "0 CVE détectée"

    # ── Application de la politique CVE ────────────────────────────────────
    # cve_policy prend la priorité sur fail_on (compat ascendante)
    if cve_policy:
        # Sévérités qui déclenchent un blocage immédiat
        block_sevs   = [s for s in _order if cve_policy.get(s.lower(), "allow") == "block"]
        # Sévérités qui déclenchent une révision RSSI
        review_sevs  = [s for s in _order if cve_policy.get(s.lower(), "allow") == "review"]
        # Sévérités qui génèrent un avertissement (non bloquant)
        warn_sevs    = [s for s in _order if cve_policy.get(s.lower(), "allow") == "warn"]

        has_block   = any(counts.get(s, 0) > 0 for s in block_sevs)
        has_review  = any(counts.get(s, 0) > 0 for s in review_sevs)
        has_warn    = any(counts.get(s, 0) > 0 for s in warn_sevs)

        kev_ids = [c["id"] for c in cve_list if c.get("in_kev")]
        kev_note = f" · {len(kev_ids)} dans CISA KEV !" if kev_ids else ""
        epss_high = [c for c in cve_list if c.get("epss_percent", 0) >= 10]
        epss_note = f" · {len(epss_high)} EPSS ≥ 10%" if epss_high else ""

        detail_lines = [
            f"Politique appliquée : block={block_sevs} | review={review_sevs} | warn={warn_sevs}",
            f"Résultat  : {summary}{kev_note}{epss_note}",
        ]
        if cve_list:
            sorted_cves = sorted(
                cve_list,
                key=lambda x: (_order.index(x["severity"]) if x["severity"] in _order else 99,
                               -(x.get("epss_percent") or 0)),
            )
            detail_lines.append("\nTop CVEs :")
            for c in sorted_cves[:10]:
                fix_str  = c["fix_state"] if c["fix_state"] != "unknown" else "pas de fix"
                kev_flag = " 🔥KEV" if c.get("in_kev") else ""
                epss_str = f" EPSS:{c['epss_percent']}%" if c.get("epss_percent") else ""
                detail_lines.append(
                    f"  [{c['severity']}] {c['id']} — {c['package_name']} {c['package_version']} "
                    f"({fix_str}){kev_flag}{epss_str}"
                )
        detail = "\n".join(detail_lines)

        if has_block:
            result.cve_status = "blocked"
            result.add_step("cve", False,
                            f"Grype — CVE(s) bloquante(s) : {summary}{kev_note}",
                            detail)
        elif has_review:
            result.cve_status = "pending_review"
            # NB : passed reste True → le fichier est accepté mais pas promu dans APT
            result.add_step("cve", True,
                            f"Grype — {summary}{kev_note} · Révision RSSI requise",
                            detail)
        elif has_warn:
            result.cve_status = "approved"
            result.add_step("cve", True,
                            f"Grype — {summary} (avertissement)",
                            detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)

    else:
        # ── Mode compat : fail_on simple ──────────────────────────────────
        _threshold_map: dict[str, list[str]] = {
            "critical": ["Critical"],
            "high":     ["Critical", "High"],
            "medium":   ["Critical", "High", "Medium"],
            "low":      ["Critical", "High", "Medium", "Low"],
            "none":     [],
        }
        blocking     = _threshold_map.get(fail_on.lower(), ["Critical"])
        should_block = any(counts.get(sev, 0) > 0 for sev in blocking)

        detail_lines = [
            f"Politique : bloquer si ≥ {fail_on.upper()}",
            f"Résultat  : {summary}",
        ]
        if cve_list:
            sorted_cves = sorted(
                cve_list,
                key=lambda x: _order.index(x["severity"]) if x["severity"] in _order else 99,
            )
            detail_lines.append("\nTop CVEs :")
            for c in sorted_cves[:10]:
                fix_str = c["fix_state"] if c["fix_state"] != "unknown" else "pas de fix"
                detail_lines.append(
                    f"  [{c['severity']}] {c['id']} — {c['package_name']} {c['package_version']} ({fix_str})"
                )
        detail = "\n".join(detail_lines)

        if should_block:
            result.cve_status = "blocked"
            result.add_step("cve", False,
                            f"Grype — CVE(s) bloquante(s) : {summary}", detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)


def _resolve_deps_recursive(
    start_deb_path: str,
    max_depth: int = 6,
) -> list[dict]:
    """
    Résout récursivement l'arbre complet des dépendances d'un .deb.

    Pour chaque dépendance trouvée dans le pool, on lit son propre champ
    Depends et on descend jusqu'à max_depth niveaux.  Les paquets absents
    du pool sont signalés manquants sans récursion (aucun fichier à lire).

    Retourne une liste plate de dicts :
      {name, available_internally, depth, version_constraint?}
    """
    visited: set[str] = set()
    result_list: list[dict] = []

    def _get_depends(deb_path: str) -> str:
        """Lit uniquement le champ Depends (1 subprocess au lieu de 8)."""
        r = subprocess.run(
            ["dpkg-deb", "-f", deb_path, "Depends"],
            capture_output=True, text=True, timeout=15,
        )
        return r.stdout.strip() if r.returncode == 0 else ""

    def _walk(deb_path: str, depth: int) -> None:
        if depth > max_depth:
            return
        direct = parse_dependencies(_get_depends(deb_path))
        for dep in direct:
            dep_name = dep["name"]
            if dep_name in visited:
                continue
            visited.add(dep_name)

            matches = list(POOL_DIR.rglob(f"{dep_name}_*.deb"))
            available = bool(matches)
            entry = {
                "name":                 dep_name,
                "available_internally": available,
                "depth":                depth,
            }
            if dep.get("version_constraint"):
                entry["version_constraint"] = dep["version_constraint"]
            result_list.append(entry)

            # Récursion uniquement si le .deb est dans le pool
            if available:
                _walk(str(matches[0]), depth + 1)

    _walk(start_deb_path, depth=1)
    return result_list


def validate_dependencies(deb_path: str, result: ValidationResult) -> list[dict]:
    """
    Vérifie récursivement toutes les dépendances (directes + transitives)
    disponibles dans le repo interne.

    Retourne la liste complète des dépendances avec leur statut de disponibilité.
    Un paquet présent dans le pool mais dont une sous-dépendance est absente
    est correctement signalé comme bloquant.
    """
    # Résolution récursive de l'arbre complet
    all_deps = _resolve_deps_recursive(deb_path)

    if not all_deps:
        result.add_step("dependencies", True, "Aucune dépendance déclarée")
        return []

    missing  = [d["name"] for d in all_deps if not d["available_internally"]]
    direct   = [d["name"] for d in all_deps if d["depth"] == 1]
    n_total  = len(all_deps)

    if missing:
        result.add_step(
            "dependencies", False,
            f"{len(missing)} dépendance(s) manquante(s) sur {n_total} vérifiées",
            "Manquantes : " + ", ".join(missing),
        )
    else:
        result.add_step(
            "dependencies", True,
            f"Toutes les dépendances présentes ({n_total} vérifiées, "
            f"{len(direct)} directe(s))",
        )

    return all_deps


def run_validation_pipeline(
    deb_path: str,
    expected_sha256: str | None = None,
    strict_deps: bool = False,
    distro: str | None = None,
) -> ValidationResult:
    """
    Pipeline de validation complet :
    1. Format .deb
    2. Provenance SHA256 (vs Packages.gz index)
    3. Antivirus ClamAV
    4. Scan CVE Grype
    5. Signature GPG
    6. Dépendances

    distro : codename APT cible (ex: "jammy", "bookworm") — améliore la précision Grype
    """
    from services.settings import get_settings
    cfg = get_settings().get("validation", {})

    result = ValidationResult()

    # 1. Format
    validate_format(deb_path, result)
    if not result.passed:
        return result

    # 2. Provenance SHA256 vs index Packages.gz
    validate_provenance_sha256(deb_path, expected_sha256, result)
    if not result.passed:
        return result  # SHA256 invalide = rejet immédiat

    # 3. Antivirus ClamAV
    if cfg.get("clamav_scan", True):
        try:
            validate_clamav(deb_path, result)
        except subprocess.TimeoutExpired:
            result.add_step("antivirus", True, "ClamAV — timeout, scan ignoré")
        if not result.passed:
            return result  # Virus détecté = rejet immédiat

    # 4. Scan CVE Grype
    if cfg.get("grype_scan", True):
        fail_on      = cfg.get("grype_fail_on", "critical")
        cve_policy   = get_settings().get("cve_policy")
        auto_enrich  = cve_policy.get("auto_enrich", True) if cve_policy else True
        try:
            validate_cve_grype(
                deb_path, result,
                fail_on=fail_on,
                distro=distro,
                cve_policy=cve_policy,
                auto_enrich=auto_enrich,
            )
        except Exception as exc:
            result.add_step("cve", True, "Grype — erreur inattendue (ignorée)", str(exc)[:300])
        # Blocage uniquement si cve_status == "blocked" (policy=block déclenché)
        if result.cve_status == "blocked":
            result.passed = False
            return result

    # 5. GPG
    validate_gpg(deb_path, result, required=cfg.get("gpg_required", False))
    if not result.passed:
        return result  # Signature GPG manquante/invalide alors que requise = rejet immédiat

    # 6. Dépendances
    deps = validate_dependencies(deb_path, result)
    result.deps = deps

    if not strict_deps:
        dep_step = next((s for s in result.steps if s["name"] == "dependencies"), None)
        if dep_step and not dep_step["passed"]:
            dep_step["warning"] = True
            result.passed = True

    return result
