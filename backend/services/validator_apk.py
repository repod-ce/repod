"""
Pipeline de validation d'artefacts APK (Alpine Linux).

Reproduit la même structure en 6 étapes que validator_apt.py :
  1. Format      — gzip tar contenant .PKGINFO
  2. Checksum    — SHA-256 de provenance (upload uniquement)
  3. Antivirus   — ClamAV (daemon clamd / fallback clamscan)
  4. CVE         — Grype --distro alpine:x.y
  5. GPG         — signature RSA intégrée (optionnelle)
  6. Dépendances — paquets manquants dans le dépôt APK local

La classe ValidationResult et les helpers ClamAV sont partagés avec
validator_apt.py via import — pas de duplication de code.
"""
import base64
import hashlib
import io
import json
import logging
import os
import struct
import subprocess
import tarfile
import zlib
from pathlib import Path

logger = logging.getLogger("validator_apk")

POOL_DIR     = Path(os.getenv("POOL_DIR",     "/repos/pool"))
APK_REPO_BASE = Path(os.getenv("APK_REPO_BASE", "/repos/apk"))

# Importation du résultat commun + helpers antivirus depuis validator_apt
from services.validator_apt import (
    ValidationResult,
    validate_clamav,
    CLAMD_SOCKET,              # noqa: F401 (re-export pour les tests)
    _extract_cvss,
)

# Correspondance codename APK → chaîne distro Grype
_DISTRO_MAP: dict[str, str] = {
    "alpine3.18": "alpine:3.18",
    "alpine3.19": "alpine:3.19",
    "alpine3.20": "alpine:3.20",
    "alpine3.21": "alpine:3.21",
    "alpine":     "alpine:3.21",
}

# ── Étape 1 : Format ──────────────────────────────────────────────────────────

def validate_format(apk_path: str, result: ValidationResult):
    """
    Vérifie qu'un fichier .apk est bien un gzip tarball contenant un fichier
    .PKGINFO.  Aucun outil externe requis — analyse binaire pure Python.
    """
    if not apk_path.endswith(".apk"):
        result.add_step("format", False, "Extension invalide — seuls les .apk sont acceptés")
        return

    from services.distributions_apk import parse_apk_metadata
    try:
        meta = parse_apk_metadata(Path(apk_path))
    except Exception as exc:
        result.add_step("format", False, f"Fichier .apk illisible : {exc}")
        return

    if not meta:
        result.add_step(
            "format", False,
            "Fichier .apk invalide — .PKGINFO absent ou illisible",
            "Le fichier ne contient pas de section de contrôle Alpine valide",
        )
        return

    name = meta.get("pkgname", "?")
    ver  = meta.get("pkgver",  "?")
    arch = meta.get("arch",    "?")
    result.add_step(
        "format", True,
        f"Format .apk valide — {name} {ver} ({arch})",
        f"pkgdesc: {meta.get('pkgdesc', '')}",
    )


# ── Étape 2 : Intégrité section contrôle (APKINDEX C:) ───────────────────────

def _gzip_stream_end(data: bytes, start: int) -> int:
    """Retourne l'offset juste après la fin du stream gzip commençant à `start`. -1 si invalide."""
    if len(data) < start + 10 or data[start:start+2] != b'\x1f\x8b':
        return -1
    if data[start+2] != 8:
        return -1
    flg = data[start+3]
    pos = start + 10
    if flg & 4:
        if pos + 2 > len(data): return -1
        pos += 2 + struct.unpack_from('<H', data, pos)[0]
    if flg & 8:
        while pos < len(data) and data[pos]: pos += 1
        pos += 1
    if flg & 16:
        while pos < len(data) and data[pos]: pos += 1
        pos += 1
    if flg & 2:
        pos += 2
    if pos >= len(data):
        return -1
    try:
        dec = zlib.decompressobj(-15)
        dec.decompress(data[pos:])
        pos += len(data[pos:]) - len(dec.unused_data)
    except zlib.error:
        return -1
    return pos + 8


def _split_gzip_streams(data: bytes) -> list[bytes]:
    """Décompose des gzip concaténés (format .apk) en liste de streams individuels."""
    streams = []
    pos = 0
    while pos < len(data) - 1:
        end = _gzip_stream_end(data, pos)
        if end <= pos:
            break
        streams.append(data[pos:end])
        pos = end
    return streams


def validate_control_checksum(apk_path: str, apk_control_checksum: str | None, result: ValidationResult):
    """
    Vérifie le champ C: de l'APKINDEX contre la section contrôle du paquet téléchargé.
    Format C: = Q1<base64(SHA1(<control_stream_bytes>))>
    Non-bloquant si le champ est absent (paquets privés).
    """
    if not apk_control_checksum:
        result.add_step("control_checksum", True, "Champ C: absent — vérification ignorée (paquet privé)")
        return

    if not apk_control_checksum.startswith("Q1"):
        result.add_step("control_checksum", True, f"Format C: inconnu ({apk_control_checksum[:8]}…) — ignoré")
        return

    try:
        expected_sha1 = base64.b64decode(apk_control_checksum[2:])
    except Exception:
        result.add_step("control_checksum", True, "Champ C: base64 invalide — ignoré")
        return

    try:
        with open(apk_path, "rb") as f:
            raw = f.read()

        streams = _split_gzip_streams(raw)
        control_bytes = None
        for stream in streams:
            try:
                with tarfile.open(fileobj=io.BytesIO(stream), mode="r:gz") as tf:
                    if ".PKGINFO" in tf.getnames():
                        control_bytes = stream
                        break
            except Exception:
                continue

        if control_bytes is None:
            result.add_step("control_checksum", True, ".PKGINFO introuvable — vérification C: ignorée")
            return

        # SHA1 mandated by the APKINDEX "C:" field format itself (Alpine apk-tools
        # spec) — a format-integrity checksum, not a security control.
        actual_sha1 = hashlib.sha1(control_bytes, usedforsecurity=False).digest()
        if actual_sha1 != expected_sha1:
            expected_b64 = base64.b64encode(expected_sha1).decode()
            actual_b64 = base64.b64encode(actual_sha1).decode()
            result.add_step(
                "control_checksum", False,
                "Intégrité section contrôle (.PKGINFO) invalide — possible corruption ou MitM",
                f"Attendu (APKINDEX C:): Q1{expected_b64}\nObtenu             : Q1{actual_b64}",
            )
        else:
            result.add_step(
                "control_checksum", True,
                f"Section contrôle vérifiée via APKINDEX C: ({apk_control_checksum[:20]}…)",
            )

    except Exception as exc:
        result.add_step("control_checksum", True, f"Vérification C: ignorée : {exc}")


# ── Étape 3 : Checksum de provenance ─────────────────────────────────────────

def validate_checksum(apk_path: str, expected_sha256: str | None, result: ValidationResult):
    """Calcule le SHA-256 du fichier et vérifie la valeur attendue si fournie."""
    from services.manifest import compute_sha256
    actual = compute_sha256(apk_path)

    if expected_sha256 and expected_sha256 != actual:
        result.add_step(
            "checksum", False,
            "SHA-256 ne correspond pas",
            f"Attendu : {expected_sha256}\nObtenu  : {actual}",
        )
    else:
        result.add_step("checksum", True, f"SHA-256 : {actual}")


# ── Étape 5 : Signature RSA intégrée ─────────────────────────────────────────

def validate_gpg(apk_path: str, result: ValidationResult):
    """
    Les fichiers .apk Alpine utilisent une signature RSA intégrée dans le
    premier flux gzip.  Ici on vérifie seulement si un stream de signature
    est présent ; la validation RSA complète requiert la clé publique
    Alpine (hors scope du dépôt privé — les paquets maison n'ont pas de
    clé Alpine officielle).

    Toujours marqué comme réussite (non-bloquant) car les paquets privés
    ne sont pas forcément signés par une clé Alpine officielle.
    """
    import io, tarfile

    try:
        with open(apk_path, "rb") as f:
            header = f.read(2)

        if header != b"\x1f\x8b":
            result.add_step("gpg", True, "Signature RSA absente (optionnel)")
            return

        # Lire le premier flux gzip — s'il contient .SIGN.RSA.* → signature présente
        with open(apk_path, "rb") as f:
            raw = f.read()

        stream = io.BytesIO(raw)
        try:
            with tarfile.open(fileobj=stream, mode="r:gz") as tf:
                names = [m.name for m in tf.getmembers()]
                has_sig = any(n.startswith(".SIGN.RSA.") or n.startswith(".SIGN.") for n in names)
        except Exception:
            has_sig = False

        if has_sig:
            result.add_step(
                "gpg", True,
                "Signature RSA présente dans le paquet",
                "Clé de signature non vérifiée (dépôt privé)",
            )
        else:
            result.add_step("gpg", True, "Pas de signature RSA (optionnel pour dépôt privé)")

    except Exception as exc:
        result.add_step("gpg", True, f"Lecture signature ignorée : {exc}")


# ── Étape 4 : CVE via Grype ───────────────────────────────────────────────────

def validate_cve_grype(
    apk_path: str,
    result: ValidationResult,
    fail_on: str = "critical",
    distro: str | None = None,
    cve_policy: dict | None = None,
    auto_enrich: bool = True,
):
    """
    Scan CVE avec Grype sur un fichier .apk.
    Utilise pkg:apk purls et --distro alpine:x.y pour une meilleure précision.
    """
    check = subprocess.run(["which", "grype"], capture_output=True, text=True)
    if check.returncode != 0:
        result.add_step("cve", True, "Grype non disponible — scan CVE ignoré")
        return

    grype_db_dir  = os.getenv("GRYPE_DB_CACHE_DIR", "/repos/grype-db")
    grype_distro  = _DISTRO_MAP.get(distro or "", distro or "")
    if not grype_distro and distro and distro.startswith("alpine"):
        grype_distro = distro.replace("alpine", "alpine:")

    cmd = ["grype", apk_path, "-o", "json", "--add-cpes-if-none"]
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
    _order  = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    counts: dict[str, int] = {s: 0 for s in _order}
    cve_list: list[dict] = []

    for match in matches:
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        sev      = vuln.get("severity", "Unknown")
        if sev not in counts:
            sev = "Unknown"
        counts[sev] += 1

        fix_info = vuln.get("fix", {})
        cve_list.append({
            "id":              vuln.get("id", ""),
            "severity":        sev,
            "cvss":            _extract_cvss(vuln),
            "description":     vuln.get("description", ""),
            "package_name":    artifact.get("name", ""),
            "package_version": artifact.get("version", ""),
            "package_type":    artifact.get("type", "apk"),
            "fix_state":       fix_info.get("state", "unknown"),
            "fix_versions":    fix_info.get("versions", []),
            "urls":            vuln.get("urls", [])[:3],
            "epss":            0.0,
            "epss_percent":    0.0,
            "epss_label":      "Faible",
            "in_kev":          False,
        })

    # Enrichissement EPSS + KEV
    if auto_enrich and cve_list:
        try:
            from services.cve_enrichment import enrich_cve_list
            enrich_cve_list(cve_list)
        except Exception:
            pass

    result.cve_results = cve_list
    summary_parts = [f"{counts[s]} {s}" for s in _order if counts[s] > 0]
    summary = " | ".join(summary_parts) if summary_parts else "0 CVE détectée"

    # Application de la politique CVE (identique à validator_apt.py)
    if cve_policy:
        block_sevs  = [s for s in _order if cve_policy.get(s.lower(), "allow") == "block"]
        review_sevs = [s for s in _order if cve_policy.get(s.lower(), "allow") == "review"]
        warn_sevs   = [s for s in _order if cve_policy.get(s.lower(), "allow") == "warn"]

        has_block  = any(counts.get(s, 0) > 0 for s in block_sevs)
        has_review = any(counts.get(s, 0) > 0 for s in review_sevs)
        has_warn   = any(counts.get(s, 0) > 0 for s in warn_sevs)

        kev_ids  = [c["id"] for c in cve_list if c.get("in_kev")]
        kev_note = f" · {len(kev_ids)} dans CISA KEV !" if kev_ids else ""
        epss_hi  = [c for c in cve_list if c.get("epss_percent", 0) >= 10]
        epss_note = f" · {len(epss_hi)} EPSS ≥ 10%" if epss_hi else ""

        detail_lines = [
            f"Politique appliquée : block={block_sevs} | review={review_sevs} | warn={warn_sevs}",
            f"Résultat  : {summary}{kev_note}{epss_note}",
        ]
        if cve_list:
            sorted_cves = sorted(
                cve_list,
                key=lambda x: (
                    _order.index(x["severity"]) if x["severity"] in _order else 99,
                    -(x.get("epss_percent") or 0),
                ),
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
            result.add_step("cve", False, f"Grype — CVE(s) bloquante(s) : {summary}{kev_note}", detail)
        elif has_review:
            result.cve_status = "pending_review"
            result.add_step("cve", True,  f"Grype — {summary}{kev_note} · Révision RSSI requise", detail)
        elif has_warn:
            result.cve_status = "approved"
            result.add_step("cve", True,  f"Grype — {summary} (avertissement)", detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)
    else:
        # Mode compat fail_on simple
        _threshold_map: dict[str, list[str]] = {
            "critical": ["Critical"],
            "high":     ["Critical", "High"],
            "medium":   ["Critical", "High", "Medium"],
            "low":      ["Critical", "High", "Medium", "Low"],
            "none":     [],
        }
        blocking     = _threshold_map.get(fail_on.lower(), ["Critical"])
        should_block = any(counts.get(sev, 0) > 0 for sev in blocking)
        detail       = f"Politique : bloquer si ≥ {fail_on.upper()}\nRésultat  : {summary}"

        if should_block:
            result.cve_status = "blocked"
            result.add_step("cve", False, f"Grype — CVE(s) bloquante(s) : {summary}", detail)
        else:
            result.cve_status = "approved"
            msg = f"Grype — {summary}" if any(counts.values()) else "Grype — aucune CVE connue"
            result.add_step("cve", True, msg, detail)


# ── Étape 6 : Dépendances ─────────────────────────────────────────────────────

def validate_dependencies(apk_path: str, result: ValidationResult) -> list[dict]:
    """
    Vérifie que les dépendances déclarées dans .PKGINFO sont disponibles
    dans le dépôt APK local ou dans le pool/.

    Les dépendances Alpine utilisent le champ `depend =` du .PKGINFO.
    Syntaxe: "name", "name>version", "name=version", "so:libfoo.so.1"
    """
    from services.distributions_apk import parse_apk_metadata, APK_REPO_BASE

    try:
        meta = parse_apk_metadata(Path(apk_path))
    except Exception:
        result.add_step("dependencies", True, "Impossible de lire les dépendances (.PKGINFO)")
        return []

    raw_deps = meta.get("depend", [])
    if isinstance(raw_deps, str):
        raw_deps = [raw_deps]
    if not raw_deps:
        result.add_step("dependencies", True, "Aucune dépendance déclarée")
        return []

    dep_list: list[dict] = []
    for raw_dep in raw_deps:
        # Normaliser : supprimer les contraintes de version (name>1.0 → name)
        # ~  est l'opérateur "compatible avec" d'APK (ex: python3~3.11 → python3)
        name = (
            raw_dep.split(">")[0].split("=")[0].split("<")[0].split("~")[0].strip()
        )
        if (
            not name
            or name.startswith("so:")    # bibliothèques partagées (so:libssl.so.3)
            or name.startswith("cmd:")   # commandes
            or name.startswith("pc:")    # pkg-config
            or name.startswith("!")      # conflicts
            or name.startswith("/")      # chemins absolus (/bin/sh, /usr/bin/env)
            or "/" in name               # sécurité : tout chemin absolu résiduel
        ):
            continue

        # Chercher dans le dépôt APK local
        found_in_apk = any(
            list(APK_REPO_BASE.rglob(f"{name}-*.apk"))
        )
        # Chercher dans le pool général
        found_in_pool = any(
            list(POOL_DIR.rglob(f"{name}*.apk"))
        ) if not found_in_apk else True

        available = found_in_apk or found_in_pool
        dep_list.append({
            "name":                 name,
            "raw":                  raw_dep,
            "available_internally": available,
            "depth":                1,
        })

    missing = [d["name"] for d in dep_list if not d["available_internally"]]
    n_total = len(dep_list)

    if missing:
        result.add_step(
            "dependencies", False,
            f"{len(missing)} dépendance(s) introuvable(s) sur {n_total} vérifiées",
            "Manquantes : " + ", ".join(missing),
        )
    else:
        result.add_step(
            "dependencies", True,
            f"Toutes les dépendances présentes ({n_total} vérifiée(s))",
        )

    return dep_list


# ── Pipeline principal ────────────────────────────────────────────────────────

def run_validation_pipeline(
    apk_path: str,
    expected_sha256: str | None = None,
    strict_deps: bool = False,
    distro: str | None = None,
    apk_control_checksum: str | None = None,
) -> ValidationResult:
    """
    Pipeline de validation APK complet :
      1. Format (.apk / .PKGINFO)
      2. Intégrité section contrôle (APKINDEX C:) — import uniquement
      3. SHA-256 de provenance — upload uniquement
      4. Antivirus ClamAV
      5. Scan CVE Grype
      6. Signature RSA (optionnelle)
      7. Dépendances

    distro : codename Alpine cible (ex: "alpine3.20") — améliore la précision Grype
    apk_control_checksum : valeur du champ C: de l'APKINDEX (Q1<base64(SHA1(...))>)
    """
    from services.settings import get_settings
    cfg = get_settings().get("validation", {})

    result = ValidationResult()

    # 1. Format
    validate_format(apk_path, result)
    if not result.passed:
        return result

    # 2. Intégrité section contrôle via champ C: de l'APKINDEX (import uniquement)
    validate_control_checksum(apk_path, apk_control_checksum, result)
    if not result.passed:
        return result

    # 3. Checksum de provenance SHA-256 (upload uniquement)
    validate_checksum(apk_path, expected_sha256, result)
    if not result.passed:
        return result

    # 3. Antivirus ClamAV (partagé avec validator_apt.py)
    if cfg.get("clamav_scan", True):
        try:
            validate_clamav(apk_path, result)
        except subprocess.TimeoutExpired:
            result.add_step("antivirus", True, "ClamAV — timeout, scan ignoré")
        if not result.passed:
            return result

    # 4. Scan CVE Grype
    if cfg.get("grype_scan", True):
        fail_on    = cfg.get("grype_fail_on", "critical")
        cve_policy = get_settings().get("cve_policy")
        auto_enrich = cve_policy.get("auto_enrich", True) if cve_policy else True
        try:
            validate_cve_grype(
                apk_path, result,
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

    # 5. Signature RSA
    validate_gpg(apk_path, result)

    # 6. Dépendances
    deps = validate_dependencies(apk_path, result)
    result.deps = deps

    if not strict_deps:
        dep_step = next((s for s in result.steps if s["name"] == "dependencies"), None)
        if dep_step and not dep_step["passed"]:
            dep_step["warning"] = True
            result.passed = True

    return result
