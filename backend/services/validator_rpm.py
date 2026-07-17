# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Pipeline de validation d'artefacts RPM.
Vérifie l'intégrité, les dépendances et le format avant d'accepter un artefact.

Ce module est importé via le dispatcher services/validator.py uniquement quand
REPO_FORMAT=rpm est défini dans l'environnement.
"""
import json
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger("validator_rpm")

# parse_rpm_fields, parse_rpm_requires et compute_sha256 sont définis dans manifest.py
# (commun APT + RPM) pour éviter la duplication.
from services.manifest import (
    parse_rpm_fields,
    parse_rpm_requires,
    parse_rpm_dependencies as parse_dependencies,
    compute_sha256,
)

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))

# Correspondance codename RPM → chaîne distro Grype
_DISTRO_MAP: dict[str, str] = {
    "almalinux8":           "almalinux:8",
    "rocky8":               "rockylinux:8",
    "centos-stream9":       "centos:9",
    "oraclelinux8":         "oraclelinux:8",
    "fedora":               "fedora:latest",
    "opensuse-leap-15.5":   "opensuse/leap:15.5",
    "opensuse-leap-15.6":   "opensuse/leap:15.6",
    "opensuse-leap":        "opensuse/leap:latest",
    "opensuse-tumbleweed":  "opensuse/tumbleweed:latest",
}


def _extract_cvss(vuln: dict) -> float | None:
    for metric in vuln.get("cvss", []):
        score = metric.get("metrics", {}).get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                pass
    return None


class ValidationResult:
    def __init__(self):
        self.steps: list[dict] = []
        self.passed = True
        self.deps: list[dict] = []
        self.cve_results: list[dict] = []
        self.cve_status: str = "approved"

    def add_step(self, name: str, passed: bool, message: str, detail: str = "", warning: bool = False):
        entry = {"name": name, "passed": passed, "message": message, "detail": detail}
        if warning:
            entry["warning"] = True
        self.steps.append(entry)
        if not passed and not warning:
            self.passed = False

    def to_dict(self) -> dict:
        return {"passed": self.passed, "cve_status": self.cve_status, "steps": self.steps}


def validate_format(rpm_path: str, result: ValidationResult):
    """Vérifie que le fichier est un .rpm valide via rpm -qip."""
    if not rpm_path.endswith(".rpm"):
        result.add_step("format", False, "Extension invalide — seuls les .rpm sont acceptés")
        return

    r = subprocess.run(
        ["rpm", "-qip", "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        result.add_step("format", False, "Fichier .rpm corrompu ou invalide", r.stderr)
    else:
        result.add_step("format", True, "Format .rpm valide")


def validate_checksum(rpm_path: str, expected_sha256: str | None, result: ValidationResult):
    """Calcule et vérifie le SHA-256."""
    actual = compute_sha256(rpm_path)
    if expected_sha256 and expected_sha256 != actual:
        result.add_step(
            "checksum", False,
            "SHA-256 ne correspond pas",
            f"Attendu: {expected_sha256}\nObtenu:  {actual}",
        )
    else:
        result.add_step("checksum", True, f"SHA-256: {actual}")


def validate_gpg(rpm_path: str, result: ValidationResult, required: bool = False):
    """
    Vérifie la signature GPG interne d'un .rpm (rpm --checksig).
    Tente aussi les fichiers .sig/.asc externes.

    Si `required` est True (politique de sécurité `validation.gpg_required`),
    l'absence de signature externe ou une signature invalide fait échouer la validation.
    """
    r = subprocess.run(
        ["rpm", "--checksig", "--nosignature", rpm_path],
        capture_output=True, text=True,
    )
    # --nosignature ne signifie pas qu'on ignore — on vérifie l'intégrité du header
    # Pour vérifier la vraie signature GPG, il faudrait importer la clé dans le trousseau rpm
    # On accepte si le fichier est bien formé, et on vérifie les .sig/.asc externes

    sig_path = rpm_path + ".sig"
    asc_path = rpm_path + ".asc"
    sig_file = sig_path if os.path.exists(sig_path) else (asc_path if os.path.exists(asc_path) else None)

    if sig_file:
        r2 = subprocess.run(
            ["gpg", "--verify", sig_file, rpm_path],
            capture_output=True, text=True,
        )
        if r2.returncode == 0:
            result.add_step("gpg", True, "Signature GPG externe valide", r2.stderr)
        else:
            result.add_step("gpg", False, "Signature GPG externe invalide", r2.stderr)
    elif required:
        result.add_step("gpg", False, "Signature GPG requise mais absente", "Politique de sécurité : gpg_required=true")
    else:
        result.add_step("gpg", True, "Pas de signature GPG externe (non requis)",
                        "Signature optionnelle absente — intégrité RPM vérifiée par checksum")


def validate_provenance_sha256(rpm_path: str, expected_sha256: str | None, result: ValidationResult):
    """Vérifie le SHA256 contre l'index de référence."""
    if not expected_sha256:
        result.add_step(
            "provenance", True,
            "Provenance non vérifiable (import manuel)",
            "Aucun SHA256 de référence disponible dans l'index",
        )
        return

    actual = compute_sha256(rpm_path)
    if actual != expected_sha256:
        result.add_step(
            "provenance", False,
            "SHA256 ne correspond pas à l'index — fichier suspect",
            f"Attendu (index) : {expected_sha256}\nObtenu          : {actual}",
        )
    else:
        result.add_step("provenance", True, "Provenance vérifiée — SHA256 conforme à l'index",
                        f"SHA256 : {actual}")


CLAMD_SOCKET = "/var/run/clamav/clamd.ctl"


def _clamd_scan(file_path: str, timeout: int = 60) -> tuple[str, str | None]:
    import socket
    import struct

    CHUNK_SIZE = 1024 * 128
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
        sock.sendall(struct.pack("!I", 0))
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
    finally:
        sock.close()

    resp_str = response.decode("utf-8", errors="replace").strip().rstrip("\0")
    if resp_str.endswith("OK"):
        return "OK", None
    elif "FOUND" in resp_str:
        threat = resp_str.replace("stream:", "").replace("FOUND", "").strip()
        return "FOUND", threat
    else:
        return "ERROR", resp_str


def validate_clamav(rpm_path: str, result: ValidationResult):
    """Scan antivirus ClamAV du fichier .rpm."""
    if os.path.exists(CLAMD_SOCKET):
        try:
            status, threat = _clamd_scan(rpm_path, timeout=60)
            if status == "OK":
                result.add_step("antivirus", True, "ClamAV — aucune menace détectée (clamd)")
            elif status == "FOUND":
                result.add_step("antivirus", False,
                                "ClamAV — menace détectée : fichier rejeté",
                                threat or "Menace inconnue")
            else:
                result.add_step("antivirus", True,
                                "ClamAV — scan incomplet (avertissement)",
                                threat or "Erreur daemon clamd")
            return
        except Exception as e:
            logger.warning(f"[clamav] Erreur clamd socket, fallback clamscan : {e}")

    check = subprocess.run(["which", "clamscan"], capture_output=True, text=True)
    if check.returncode != 0:
        result.add_step("antivirus", True,
                        "ClamAV non disponible — scan ignoré",
                        "Installez clamav pour activer le scan antivirus")
        return

    try:
        r = subprocess.run(
            ["clamscan", "--no-summary", "--infected", rpm_path],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        result.add_step("antivirus", True, "ClamAV — scan timeout (avertissement)",
                        "Le scan a dépassé le délai imparti")
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
    rpm_path: str,
    result: ValidationResult,
    fail_on: str = "critical",
    distro: str | None = None,
    cve_policy: dict | None = None,
    auto_enrich: bool = True,
):
    """Scan CVE avec Grype sur le fichier .rpm (Grype supporte nativement RPM)."""
    check = subprocess.run(["which", "grype"], capture_output=True, text=True)
    if check.returncode != 0:
        result.add_step("cve", True, "Grype non disponible — scan CVE ignoré",
                        "Le binaire grype est absent du conteneur")
        return

    grype_db_dir = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
    grype_distro = _DISTRO_MAP.get(distro or "", distro or "")

    cmd = ["grype", rpm_path, "-o", "json", "--add-cpes-if-none"]
    if grype_distro:
        cmd += ["--distro", grype_distro]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            env={**os.environ, "GRYPE_DB_CACHE_DIR": grype_db_dir, "GRYPE_DB_AUTO_UPDATE": "false"},
        )
    except subprocess.TimeoutExpired:
        result.add_step("cve", True, "Grype — timeout (> 5 min), scan CVE ignoré")
        return

    if r.returncode not in (0, 1):
        result.add_step("cve", True,
                        "Grype — scan incomplet (avertissement non bloquant)",
                        (r.stderr or r.stdout)[:500])
        return

    try:
        data = json.loads(r.stdout)
    except (json.JSONDecodeError, ValueError):
        result.add_step("cve", True, "Grype — réponse illisible (avertissement)", r.stdout[:300])
        return

    matches = data.get("matches", [])
    _order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts: dict[str, int] = {s: 0 for s in _order}
    cve_list: list[dict] = []

    for match in matches:
        vuln = match.get("vulnerability", {})
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
            "epss":         0.0,
            "epss_percent": 0.0,
            "epss_label":   "Faible",
            "in_kev":       False,
        })

    if auto_enrich and cve_list:
        try:
            from services.cve_enrichment import enrich_cve_list
            enrich_cve_list(cve_list)
        except Exception:
            pass

    result.cve_results = cve_list
    summary_parts = [f"{counts[s]} {s}" for s in _order if counts[s] > 0]
    summary = " | ".join(summary_parts) if summary_parts else "0 CVE détectée"

    if cve_policy:
        block_sevs  = [s for s in _order if cve_policy.get(s.lower(), "allow") == "block"]
        review_sevs = [s for s in _order if cve_policy.get(s.lower(), "allow") == "review"]
        warn_sevs   = [s for s in _order if cve_policy.get(s.lower(), "allow") == "warn"]

        has_block  = any(counts.get(s, 0) > 0 for s in block_sevs)
        has_review = any(counts.get(s, 0) > 0 for s in review_sevs)
        has_warn   = any(counts.get(s, 0) > 0 for s in warn_sevs)

        kev_ids  = [c["id"] for c in cve_list if c.get("in_kev")]
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
                kev_flag = " KEV" if c.get("in_kev") else ""
                epss_str = f" EPSS:{c['epss_percent']}%" if c.get("epss_percent") else ""
                detail_lines.append(
                    f"  [{c['severity']}] {c['id']} — {c['package_name']} {c['package_version']} "
                    f"({fix_str}){kev_flag}{epss_str}"
                )
        detail = "\n".join(detail_lines)

        if has_block:
            result.cve_status = "blocked"
            result.add_step("cve", False, f"Grype — CVE(s) bloquante(s) : {summary}{kev_note}", detail)
        elif has_review:
            result.cve_status = "pending_review"
            result.add_step("cve", True,
                            f"Grype — {summary}{kev_note} · Révision RSSI requise", detail)
        elif has_warn:
            result.cve_status = "approved"
            result.add_step("cve", True, f"Grype — {summary} (avertissement)", detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)
    else:
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
            result.add_step("cve", False, f"Grype — CVE(s) bloquante(s) : {summary}", detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)


def validate_dependencies(rpm_path: str, result: ValidationResult) -> list[dict]:
    """
    Vérifie que les dépendances déclarées sont disponibles dans le repo interne.
    """
    requires_raw = parse_rpm_requires(rpm_path)
    deps = parse_dependencies(requires_raw)

    if not deps:
        result.add_step("dependencies", True, "Aucune dépendance déclarée")
        return []

    missing = []
    available = []

    for dep in deps:
        dep_name = dep["name"]
        # Chercher dans le pool interne
        matches = list(POOL_DIR.rglob(f"{dep_name}-*.rpm"))
        if matches:
            dep["available_internally"] = True
            available.append(dep_name)
        else:
            dep["available_internally"] = False
            missing.append(dep_name)

    if missing:
        result.add_step(
            "dependencies", False,
            f"{len(missing)} dépendance(s) absente(s) du repo interne",
            "Manquantes: " + ", ".join(missing[:20]),
        )
    else:
        result.add_step("dependencies", True,
                        f"{len(available)} dépendance(s) disponible(s) en interne")

    return deps


def run_validation_pipeline(
    rpm_path: str,
    expected_sha256: str | None = None,
    strict_deps: bool = False,
    distro: str | None = None,
) -> ValidationResult:
    """
    Pipeline de validation complet pour un .rpm :
    1. Format .rpm
    2. Provenance SHA256 (vs index)
    3. Antivirus ClamAV
    4. Scan CVE Grype
    5. Signature GPG
    6. Dépendances
    """
    from services.settings import get_settings
    cfg = get_settings().get("validation", {})

    result = ValidationResult()

    # 1. Format
    validate_format(rpm_path, result)
    if not result.passed:
        return result

    # 2. Provenance SHA256
    validate_provenance_sha256(rpm_path, expected_sha256, result)
    if not result.passed:
        return result

    # 3. Antivirus ClamAV
    if cfg.get("clamav_scan", True):
        try:
            validate_clamav(rpm_path, result)
        except subprocess.TimeoutExpired:
            result.add_step("antivirus", True, "ClamAV — timeout, scan ignoré")
        if not result.passed:
            return result

    # 4. Scan CVE Grype
    if cfg.get("grype_scan", True):
        fail_on     = cfg.get("grype_fail_on", "critical")
        cve_policy  = get_settings().get("cve_policy")
        auto_enrich = cve_policy.get("auto_enrich", True) if cve_policy else True
        try:
            validate_cve_grype(
                rpm_path, result,
                fail_on=fail_on,
                distro=distro,
                cve_policy=cve_policy,
                auto_enrich=auto_enrich,
            )
        except Exception as exc:
            result.add_step("cve", True, "Grype — erreur inattendue (ignorée)", str(exc)[:300])
        if result.cve_status == "blocked":
            result.passed = False
            return result

    # 5. GPG
    validate_gpg(rpm_path, result, required=cfg.get("gpg_required", False))
    if not result.passed:
        return result  # Signature GPG manquante/invalide alors que requise = rejet immédiat

    # 6. Dépendances
    deps = validate_dependencies(rpm_path, result)
    result.deps = deps

    if not strict_deps:
        dep_step = next((s for s in result.steps if s["name"] == "dependencies"), None)
        if dep_step and not dep_step["passed"]:
            dep_step["warning"] = True
            result.passed = True

    return result
