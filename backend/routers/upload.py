"""
Pipeline d'upload complet (APT et RPM) :
1. Réception du fichier → staging/incoming/
2. Validation (format, checksum, GPG, antivirus, CVE, dépendances)
3. Si OK → déplacement vers pool/, génération manifest, mise à jour index
4. Si KO → déplacement vers staging/quarantine/
5. Audit log dans tous les cas

Le format cible (APT ou RPM) est déterminé par REPO_FORMAT (voir format_router.py).

POST /upload/        → réponse JSON (legacy)
POST /upload/stream  → réponse SSE workflow en temps réel
"""
import asyncio
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from auth.dependencies import get_uploader_user
from limiter import limiter
from services.rate_limits import make_role_limit
from services.format_router import (
    REPO_FORMAT, is_apt, is_rpm, is_apk,
    ACCEPTED_EXTENSIONS, FORMAT_LABEL, REPO_TOOL_LABEL, DEFAULT_DISTRIBUTION,
)
from services.distributions import VALID_CODENAMES
from services.validator import run_validation_pipeline
from services.manifest import generate_manifest, save_manifest
from services.indexer import add_to_index
from services.audit import log as audit_log
from services.notifications import notify
from services.cve_utils import compute_cve_summary
from services.manifest import compute_sha256

router = APIRouter(prefix="/upload", tags=["Upload"])

STAGING_INCOMING   = Path(os.getenv("STAGING_INCOMING",   "/repos/staging/incoming"))
STAGING_QUARANTINE = Path(os.getenv("STAGING_QUARANTINE", "/repos/staging/quarantine"))
POOL_DIR           = Path(os.getenv("POOL_DIR",           "/repos/pool"))
ADD_DEB_SCRIPT     = os.getenv("ADD_DEB_SCRIPT",          "/scripts/add-deb.sh")
ADD_RPM_SCRIPT     = os.getenv("ADD_RPM_SCRIPT",          "/scripts/add-rpm.sh")

for _d in [STAGING_INCOMING, STAGING_QUARANTINE, POOL_DIR]:
    _d.mkdir(parents=True, exist_ok=True)


def _cve_summary_detail(cve_counts: dict, worst: str | None, kev_count: int) -> str:
    """Texte récapitulatif des CVE détectées, pour le contexte de notification."""
    cve_line = " | ".join(f"{k.capitalize()}: {v}" for k, v in cve_counts.items() if v > 0)
    detail = f"CVE détectées ({worst or '?'}) : {cve_line or 'aucune'}"
    if kev_count:
        detail += f" | {kev_count} CVE(s) dans le catalogue KEV CISA"
    return detail


# ─── Format/distribution compatibility ───────────────────────────────────────

# Codename prefixes → expected file extension
_APK_PREFIXES = ("alpine",)
_RPM_PREFIXES = ("almalinux", "rocky", "centos", "oraclelinux", "fedora", "opensuse")

_FORMAT_LABEL = {"deb": "APT / Debian·Ubuntu (.deb)", "rpm": "RPM / RHEL·Fedora (.rpm)", "apk": "APK / Alpine Linux (.apk)"}

def _expected_ext_for_distrib(codename: str) -> tuple[str, str]:
    """
    Retourne (extension_attendue, label_format) pour un codename de distribution.
    Ex : "alpine3.19" → (".apk", "APK / Alpine Linux (.apk)")
         "almalinux9" → (".rpm", "RPM / RHEL·Fedora (.rpm)")
         "jammy"      → (".deb", "APT / Debian·Ubuntu (.deb)")
    """
    c = codename.lower()
    if any(c.startswith(p) for p in _APK_PREFIXES):
        return ".apk", _FORMAT_LABEL["apk"]
    if any(c.startswith(p) for p in _RPM_PREFIXES):
        return ".rpm", _FORMAT_LABEL["rpm"]
    return ".deb", _FORMAT_LABEL["deb"]


def _check_duplicate(staged_path: Path, safe_filename: str) -> dict | None:
    """
    Vérifie si le paquet est déjà présent dans le pool avant de lancer le pipeline.

    Retourne :
      None                  → paquet nouveau, continuer normalement
      {"status": "already_imported", "sha256": ..., "pool_path": ...}
                            → fichier identique déjà dans le pool (même SHA256)
      {"status": "conflict", "sha256": ..., "existing_sha256": ...}
                            → même nom/version/arch mais contenu différent → alerte sécurité
    """
    pool_path = POOL_DIR / safe_filename
    if not pool_path.exists():
        return None

    incoming_sha256 = compute_sha256(str(staged_path))
    existing_sha256 = compute_sha256(str(pool_path))

    if incoming_sha256 == existing_sha256:
        return {
            "status": "already_imported",
            "sha256": incoming_sha256,
            "pool_path": str(pool_path),
        }

    # Même filename, contenu différent — possible falsification ou re-release non versionnée
    return {
        "status": "conflict",
        "sha256": incoming_sha256,
        "existing_sha256": existing_sha256,
        "pool_path": str(pool_path),
    }


def _missing_dep_names(validation) -> list[str]:
    """Noms des dépendances signalées absentes par validate_dependencies()
    (déb : arbre transitif complet ; rpm/apk : Requires/depend directs
    uniquement — asymétrie pré-existante entre formats, non modifiée ici).
    available_internally absent (donnée incomplète) est traité comme
    manquant, pas comme disponible : au pire, import_one() constatera que
    le paquet est déjà indexé et renverra "skipped" sans effet — l'inverse
    (ignorer silencieusement une dépendance réellement manquante) serait
    pire pour une fonctionnalité dont le but est justement de combler ces
    trous."""
    return [d["name"] for d in (validation.deps or []) if not d.get("available_internally", False)]


# Garde-fou contre un graphe de dépendances pathologique/circulaire — même
# convention que la limite "50 paquets" déjà appliquée ailleurs (import par
# lot, voir ImportPage.js:BatchImportTab).
_MAX_AUTO_IMPORT_DEPS = 50


def _sub_missing_deps(pkg_name: str) -> list[str]:
    """
    Après l'import d'une dépendance, ses propres dépendances manquantes
    (calculées à l'import et déjà stockées dans l'index — voir
    services/indexer.py:add_to_index()'s "deps_missing") — c'est la SEULE
    façon de les découvrir : validate_dependencies() ne peut lire le champ
    Depends que d'un fichier .deb présent localement, donc tant qu'une
    dépendance n'a pas été téléchargée, ses propres sous-dépendances sont
    invisibles depuis le paquet parent.
    """
    from services.indexer import get_package_info
    info = get_package_info(pkg_name)
    if not info:
        return []
    latest = info.get("latest")
    return (info.get("versions", {}).get(latest, {}) or {}).get("deps_missing", [])


def _is_index_miss(dep_result: dict) -> bool:
    """
    Détecte un échec dû à une dépendance absente de l'index local de
    synchronisation (pas encore récupérée depuis la source publique) — la
    seule cause d'échec qu'une resynchronisation peut réellement résoudre.

    Le message est la seule source fiable : importer_apt.py renvoie
    status="error" pour ce cas, alors qu'importer_rpm.py/importer_apk.py
    renvoient status="skipped" pour le même cas (incohérence pré-existante,
    non corrigée ici) — on ne peut donc pas se fier uniquement au champ
    status, commun aux trois formats via services/importer.py.
    """
    return "introuvable dans l'index" in (dep_result.get("message") or "")


async def _sync_index_for_distribution(distribution: str) -> None:
    """
    Resynchronise l'index de paquets (source publique → base SQLite
    interne) pour le format de la distribution cible — déclenché par le
    pipeline de dépôt manuel quand une dépendance manquante n'est pas (ou
    plus) dans l'index, plutôt que d'obliger l'utilisateur à aller cliquer
    "Sync index" sur une autre page. Best-effort : une synchronisation qui
    échoue (réseau, source indisponible) ne doit pas faire échouer le
    dépôt du paquet principal — le second essai de import_one() échouera
    simplement avec le même message qu'avant, sans régression.
    """
    ext, _ = _expected_ext_for_distrib(distribution)
    try:
        if ext == ".rpm":
            from services.package_index_rpm import sync_all as _sync_all
        elif ext == ".apk":
            from services.package_index_apk import sync_all as _sync_all
        else:
            from services.package_index_apt import sync_all as _sync_all
        await asyncio.to_thread(_sync_all)
    except Exception:
        pass


async def _import_dep_or_error(import_one, dep_name: str, distribution: str, user: str, group: str) -> dict:
    try:
        return await asyncio.to_thread(import_one, {"name": dep_name}, distribution, user, group)
    except Exception as e:
        return {"status": "error", "name": dep_name, "message": str(e)}


async def _auto_import_missing_deps(dep_names: list[str], distribution: str, user: str, group: str) -> list[dict]:
    """
    Tente d'importer automatiquement, depuis internet, chaque dépendance
    manquante détectée par validate_dependencies() lors d'un dépôt manuel —
    même pipeline complet (validation format/antivirus/CVE/politique) que
    l'import depuis internet, via services.importer.import_one() (dispatché
    par format selon la distribution cible).

    Transitif : après chaque import réussi, ses propres dépendances
    manquantes (voir _sub_missing_deps()) sont ajoutées à la file — le
    pipeline complet (Clam/Grype/SHA/politique) s'applique à CHAQUE paquet
    découvert, pas seulement au premier niveau, jusqu'à ce qu'aucun nouveau
    paquet ne soit découvert (point fixe) ou que _MAX_AUTO_IMPORT_DEPS soit
    atteint (protection contre un graphe pathologique/circulaire).

    Ne bloque jamais le paquet principal : un échec d'import d'une
    dépendance ne fait pas échouer l'upload lui-même, il est simplement
    rapporté tel quel dans le résultat.
    """
    from services.importer import import_one
    results = []
    queue = list(dict.fromkeys(dep_names))  # dé-doublonné, ordre préservé
    seen = set(queue)
    synced_once = False
    while queue and len(results) < _MAX_AUTO_IMPORT_DEPS:
        dep_name = queue.pop(0)
        r = await _import_dep_or_error(import_one, dep_name, distribution, user, group)

        if _is_index_miss(r) and not synced_once:
            synced_once = True
            await _sync_index_for_distribution(distribution)
            r = await _import_dep_or_error(import_one, dep_name, distribution, user, group)

        results.append(r)

        if r.get("status") in ("added", "pending_review"):
            for sub_name in await asyncio.to_thread(_sub_missing_deps, r.get("name", dep_name)):
                if sub_name not in seen:
                    seen.add(sub_name)
                    queue.append(sub_name)
    return results


def _accepted_ext_hint() -> str:
    """Message d'erreur lisible pour les extensions acceptées."""
    return " | ".join(sorted(ACCEPTED_EXTENSIONS))


async def _add_to_repo(pool_path: Path, distribution: str) -> bool:
    """
    Ajoute le paquet dans le dépôt physique (reprepro, createrepo_c ou APKINDEX).
    Dispatch par extension de fichier pour les modes multi-format (both, all).
    Retourne True si succès.
    """
    suffix = pool_path.suffix.lower()

    # ── APK Alpine ──────────────────────────────────────────────────────────
    if suffix == ".apk" or (is_apk() and not is_apt() and not is_rpm()):
        from services.distributions_apk import add_package as _apk_add
        ok, _msg = await asyncio.to_thread(_apk_add, pool_path, distribution)
        return ok

    # ── RPM ─────────────────────────────────────────────────────────────────
    if suffix == ".rpm" or (is_rpm() and not is_apt()):
        from services.distributions_rpm import add_rpm_to_distrib
        ok, _msg = await asyncio.to_thread(add_rpm_to_distrib, pool_path.name, distribution)
        return ok

    # ── APT (.deb) ──────────────────────────────────────────────────────────
    result = await asyncio.to_thread(
        subprocess.run,
        ["sh", ADD_DEB_SCRIPT, distribution, pool_path.name],
        capture_output=True, text=True,
        env={
            **os.environ,
            "GNUPGHOME":     os.getenv("GNUPG_HOME",    "/repos/gnupg"),
            "REPREPRO_BASE": os.getenv("REPREPRO_BASE", "/repos"),
        },
    )
    return result.returncode == 0


# ─── POST /upload/ ────────────────────────────────────────────────────────────

@router.post("/")
@limiter.limit(make_role_limit("upload"))
async def upload_package(
    request: Request,
    response: Response,
    file: UploadFile = File(...),
    distribution: str = Form(DEFAULT_DISTRIBUTION),
    current_user: str = Depends(get_uploader_user),
):
    """
    Pipeline complet d'import d'un paquet ({FORMAT_LABEL}) :
    - Validation format, checksum, GPG, antivirus, CVE, dépendances
    - Génération du manifest
    - Mise à jour de l'index
    - Ajout au dépôt ({REPO_TOOL_LABEL})
    """.format(FORMAT_LABEL=FORMAT_LABEL, REPO_TOOL_LABEL=REPO_TOOL_LABEL)

    if distribution not in VALID_CODENAMES:
        raise HTTPException(
            status_code=400,
            detail=f"Distribution invalide. Valeurs acceptées : {', '.join(sorted(VALID_CODENAMES))}"
        )

    filename = file.filename
    if not filename:
        raise HTTPException(status_code=400, detail="Nom de fichier manquant")

    # Validation de l'extension
    safe_filename = Path(filename).name
    ext = Path(safe_filename).suffix.lower()
    if ext not in ACCEPTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Extension invalide '{ext}' — seuls les {_accepted_ext_hint()} sont acceptés "
                   f"(REPO_FORMAT={REPO_FORMAT})"
        )

    # Validation compatibilité format-fichier ↔ distribution (avant staging)
    expected_ext, fmt_label = _expected_ext_for_distrib(distribution)
    if ext != expected_ext:
        actual_ext_label = _FORMAT_LABEL.get(ext.lstrip("."), ext)
        raise HTTPException(
            status_code=422,
            detail=(
                f"Format incompatible : '{safe_filename}' est un paquet {ext.upper().lstrip('.')} "
                f"mais la distribution '{distribution}' attend des paquets {fmt_label}. "
                f"Sélectionnez la bonne distribution ou utilisez un fichier {expected_ext.upper().lstrip('.')}."
            ),
        )

    # Préfixe UUID pour éviter les races conditions entre uploads concurrents
    staging_path = STAGING_INCOMING / f"{uuid.uuid4().hex}_{safe_filename}"

    # 1. Sauvegarde en staging
    try:
        with open(staging_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        audit_log("UPLOAD", current_user, "FAILURE", package=safe_filename,
                  detail=f"Erreur écriture staging: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la sauvegarde du fichier")

    # 1b. Détection de doublon (avant le pipeline — évite un scan Grype inutile)
    dup = _check_duplicate(staging_path, safe_filename)
    if dup:
        staging_path.unlink(missing_ok=True)  # nettoyage staging
        if dup["status"] == "already_imported":
            audit_log("UPLOAD", current_user, "DUPLICATE", package=safe_filename,
                      detail=f"Doublon ignoré — sha256={dup['sha256']}")
            return {
                "status":   "already_imported",
                "filename": safe_filename,
                "format":   REPO_FORMAT,
                "sha256":   dup["sha256"],
                "message":  f"{safe_filename} est déjà présent dans le dépôt (SHA256 identique) — import ignoré",
            }
        # conflict : même fichier, contenu différent
        audit_log("UPLOAD", current_user, "CONFLICT", package=safe_filename,
                  detail=f"Conflit SHA256 — entrant={dup['sha256']} existant={dup['existing_sha256']}")
        raise HTTPException(
            status_code=409,
            detail={
                "error":           "duplicate_conflict",
                "message":         f"Un paquet portant le nom '{safe_filename}' existe déjà dans le pool avec un SHA256 différent. Incrémentez la version ou vérifiez l'intégrité du fichier.",
                "incoming_sha256": dup["sha256"],
                "existing_sha256": dup["existing_sha256"],
            },
        )

    # 2. Pipeline de validation (exécuté dans le thread pool — Grype ≤ 300 s)
    validation = await asyncio.to_thread(
        run_validation_pipeline, str(staging_path), strict_deps=False, distro=distribution
    )

    # 3a. Rejet si validation échouée
    if not validation.passed:
        quarantine_path = STAGING_QUARANTINE / safe_filename
        shutil.move(str(staging_path), str(quarantine_path))
        audit_log(
            "VALIDATE", current_user, "FAILURE",
            package=safe_filename,
            detail="Validation échouée — déplacé en quarantaine",
            extra={"validation_steps": validation.steps},
        )
        return {
            "status":     "rejected",
            "filename":   safe_filename,
            "format":     REPO_FORMAT,
            "message":    "Le paquet a été rejeté et mis en quarantaine",
            "validation": validation.to_dict(),
        }

    # 3b. Déplacement vers pool/
    pool_path = POOL_DIR / safe_filename
    shutil.move(str(staging_path), str(pool_path))

    # 4. Génération du manifest
    cve_status      = validation.cve_status
    manifest_status = "pending_review" if cve_status == "pending_review" else "validated"

    manifest = generate_manifest(
        str(pool_path),
        imported_by=current_user,
        validated_deps=validation.deps if validation.deps else None,
        validation_steps=validation.steps,
        cve_results=validation.cve_results if validation.cve_results else None,
        distribution=distribution,
    )
    manifest["status"] = manifest_status
    save_manifest(manifest)

    # 5. Mise à jour de l'index
    add_to_index(manifest)

    # 6. Ajout au dépôt physique (seulement si approuvé)
    repo_ok = False
    if cve_status != "pending_review":
        repo_ok = await _add_to_repo(pool_path, distribution)

    audit_log(
        "UPLOAD", current_user,
        "PENDING_REVIEW" if cve_status == "pending_review" else "SUCCESS",
        package=manifest["name"],
        version=manifest["version"],
        detail=(
            "En attente de révision RSSI — CVE politique déclenchée"
            if cve_status == "pending_review"
            else f"sha256={manifest['integrity']['sha256']}"
        ),
        extra={
            "validation_steps": validation.steps,
            "cve_status": cve_status,
            "repo_format": REPO_FORMAT,
        },
    )

    warnings = [s for s in validation.steps if s.get("warning") and not s["passed"]]

    # Résolution automatique des dépendances manquantes détectées ci-dessus —
    # même pipeline complet que l'import depuis internet, indépendant du
    # statut CVE du paquet principal (une dépendance manquante est un
    # artefact distinct avec sa propre décision de politique).
    missing_dep_names = _missing_dep_names(validation)
    dependencies_resolved = (
        await _auto_import_missing_deps(missing_dep_names, distribution, current_user, manifest["name"])
        if missing_dep_names else []
    )

    # Notification si en attente de révision RSSI
    if cve_status == "pending_review":
        try:
            cve_counts, kev_count, worst = compute_cve_summary(validation.cve_results or [])
            notify("PENDING_REVIEW", {
                "package":   manifest["name"],
                "version":   manifest["version"],
                "from_dist": distribution,
                "to_dist":   distribution,
                "detail":    _cve_summary_detail(cve_counts, worst, kev_count),
                "user":      current_user,
            })
        except Exception:
            pass  # notifications non bloquantes

    if cve_status == "pending_review":
        return {
            "status":     "pending_review",
            "filename":   safe_filename,
            "format":     REPO_FORMAT,
            "package":    manifest["name"],
            "version":    manifest["version"],
            "arch":       manifest["arch"],
            "sha256":     manifest["integrity"]["sha256"],
            "validation": validation.to_dict(),
            "warnings":   warnings,
            "dependencies_resolved": dependencies_resolved,
            "message": (
                f"{manifest['name']} {manifest['version']} importé mais "
                "en attente de révision RSSI — non publié dans le dépôt"
            ),
        }

    return {
        "status":     "accepted",
        "filename":   safe_filename,
        "format":     REPO_FORMAT,
        "dependencies_resolved": dependencies_resolved,
        "package":    manifest["name"],
        "version":    manifest["version"],
        "arch":       manifest["arch"],
        "sha256":     manifest["integrity"]["sha256"],
        "validation": validation.to_dict(),
        "warnings":   warnings,
        "message": (
            f"{manifest['name']} {manifest['version']} ajouté au dépôt "
            f"({distribution})"
        ),
    }


# ─── Upload SSE (streaming) ───────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


async def _upload_stream_generator(
    safe_filename: str, staging_path: Path, distribution: str, current_user: str
):
    """Générateur SSE — chaque étape du pipeline émet un événement."""

    _ext = Path(safe_filename).suffix.lower().lstrip(".")

    def step(name: str, label: str, status: str, message: str = "", detail: str = "") -> str:
        return _sse("step", {
            "name": name, "label": label, "status": status,
            "message": message, "detail": detail,
        })

    try:
        yield step("reception", "Réception du fichier", "done",
                   f"{safe_filename} — {staging_path.stat().st_size // 1024} Ko")

        # Détection de doublon avant le pipeline
        dup = await asyncio.to_thread(_check_duplicate, staging_path, safe_filename)
        if dup:
            staging_path.unlink(missing_ok=True)
            if dup["status"] == "already_imported":
                audit_log("UPLOAD", current_user, "DUPLICATE", package=safe_filename,
                          detail=f"Doublon ignoré — sha256={dup['sha256']}")
                yield step("duplicate", "Détection doublon", "warn",
                           f"{safe_filename} est déjà présent dans le dépôt (SHA256 identique)",
                           "Import ignoré — aucune modification effectuée")
                yield _sse("result", {
                    "status":   "already_imported",
                    "format":   REPO_FORMAT,
                    "sha256":   dup["sha256"],
                    "message":  f"{safe_filename} déjà importé — doublon ignoré",
                })
            else:
                audit_log("UPLOAD", current_user, "CONFLICT", package=safe_filename,
                          detail=f"Conflit SHA256 — entrant={dup['sha256']} existant={dup['existing_sha256']}")
                yield step("duplicate", "Détection doublon", "error",
                           "Conflit : même nom mais SHA256 différent — vérifiez l'intégrité ou incrémentez la version",
                           f"Entrant : {dup['sha256']}\nExistant : {dup['existing_sha256']}")
                yield _sse("result", {
                    "status":           "conflict",
                    "format":           REPO_FORMAT,
                    "incoming_sha256":  dup["sha256"],
                    "existing_sha256":  dup["existing_sha256"],
                    "message":          "Conflit de doublon : SHA256 différent pour le même paquet",
                })
            yield "data: done|DONE\n\n"
            return

        yield step("validation", "Pipeline de validation", "running",
                   "Vérification format, intégrité, antivirus, CVE, dépendances…")

        validation = await asyncio.to_thread(
            run_validation_pipeline, str(staging_path), strict_deps=False, distro=distribution
        )

        _step_labels = {
            "format":       f"Format .{_ext}",
            "checksum":     "Intégrité SHA-256",
            "provenance":   "Provenance SHA-256",
            "gpg":          "Signature GPG",
            "antivirus":    "Scan antivirus ClamAV",
            "cve":          "Analyse CVE (Grype)",
            "dependencies": "Dépendances",
        }
        for vs in validation.steps:
            name    = vs.get("name", "")
            passed  = vs.get("passed", False)
            warning = vs.get("warning", False)
            status  = "done" if (passed or warning) else "error"
            yield step(f"sub_{name}", _step_labels.get(name, name), status,
                       vs.get("message", ""), vs.get("detail", ""))

        if not validation.passed:
            quarantine_path = STAGING_QUARANTINE / safe_filename
            shutil.move(str(staging_path), str(quarantine_path))
            audit_log("VALIDATE", current_user, "FAILURE", package=safe_filename,
                      detail="Validation échouée — déplacé en quarantaine",
                      extra={"validation_steps": validation.steps})
            yield step("validation", "Pipeline de validation", "error", "Paquet rejeté")
            yield _sse("result", {
                "status":     "rejected",
                "format":     REPO_FORMAT,
                "message":    "Le paquet a échoué à la validation.",
                "validation": validation.to_dict(),
            })
            yield "data: done|DONE\n\n"
            return

        yield step("validation", "Pipeline de validation", "done",
                   "Toutes les vérifications passées")

        yield step("pool", "Déplacement vers le pool", "running")
        pool_path = POOL_DIR / safe_filename
        shutil.move(str(staging_path), str(pool_path))
        yield step("pool", "Déplacement vers le pool", "done", f"pool/{safe_filename}")

        yield step("manifest", "Génération du manifest", "running")
        cve_status      = validation.cve_status
        manifest_status = "pending_review" if cve_status == "pending_review" else "validated"
        manifest = generate_manifest(
            str(pool_path), imported_by=current_user,
            validated_deps=validation.deps if validation.deps else None,
            validation_steps=validation.steps,
            cve_results=validation.cve_results if validation.cve_results else None,
            distribution=distribution,
        )
        manifest["status"] = manifest_status
        save_manifest(manifest)
        yield step("manifest", "Génération du manifest", "done",
                   f"{manifest['name']} {manifest['version']} · {manifest['arch']}")

        yield step("index", "Mise à jour de l'index", "running")
        add_to_index(manifest)
        yield step("index", "Mise à jour de l'index", "done")

        _repo_label = "Ajout au dépôt"
        repo_ok = False
        if cve_status != "pending_review":
            yield step("repo_add", _repo_label, "running",
                       f"Distribution : {distribution}")
            repo_ok = await _add_to_repo(pool_path, distribution)
            yield step("repo_add", _repo_label,
                       "done" if repo_ok else "warn",
                       "Paquet publié" if repo_ok else "Erreur lors de la publication")
        else:
            yield step("repo_add", _repo_label, "warn",
                       "En attente de révision RSSI — non publié dans le dépôt")

        # Résolution automatique des dépendances manquantes détectées par
        # l'étape "dependencies" ci-dessus — même pipeline complet que
        # l'import depuis internet, indépendant du statut CVE du paquet
        # principal (une dépendance manquante est un artefact distinct
        # avec sa propre décision de politique).
        missing_dep_names = _missing_dep_names(validation)
        dependencies_resolved: list[dict] = []
        if missing_dep_names:
            yield step("auto_deps", "Résolution des dépendances manquantes", "running",
                       f"{len(missing_dep_names)} dépendance(s) à importer depuis internet")
            from services.importer import import_one as _import_dep
            n_added, n_pending, n_failed = 0, 0, 0
            # File de traitement transitive : chaque dépendance importée
            # avec succès peut révéler ses propres dépendances manquantes
            # (voir _sub_missing_deps()) — elles sont ajoutées à la file et
            # passent par le même pipeline complet, jusqu'à épuisement
            # (point fixe) ou _MAX_AUTO_IMPORT_DEPS.
            dep_queue = list(dict.fromkeys(missing_dep_names))
            dep_seen = set(dep_queue)
            dep_synced_once = False
            while dep_queue and len(dependencies_resolved) < _MAX_AUTO_IMPORT_DEPS:
                dep_name = dep_queue.pop(0)
                dep_result = await _import_dep_or_error(_import_dep, dep_name, distribution, current_user, manifest["name"])

                if _is_index_miss(dep_result) and not dep_synced_once:
                    dep_synced_once = True
                    yield step("auto_deps", "Résolution des dépendances manquantes", "running",
                               "Synchronisation de l'index en cours…")
                    await _sync_index_for_distribution(distribution)
                    yield step("auto_deps", "Résolution des dépendances manquantes", "running",
                               "Synchronisation terminée — reprise de l'import")
                    dep_result = await _import_dep_or_error(_import_dep, dep_name, distribution, current_user, manifest["name"])

                dependencies_resolved.append(dep_result)
                dep_status = dep_result.get("status")
                if dep_status == "added":
                    n_added += 1
                    yield step(f"sub_dep_{dep_name}", dep_name, "done",
                               dep_result.get("message", "ajouté au dépôt"))
                elif dep_status == "pending_review":
                    n_pending += 1
                    yield step(f"sub_dep_{dep_name}", dep_name, "warn",
                               "en attente révision RSSI (non publié)")
                elif dep_status == "skipped":
                    yield step(f"sub_dep_{dep_name}", dep_name, "done",
                               dep_result.get("message", "déjà présent dans le dépôt"))
                else:
                    n_failed += 1
                    yield step(f"sub_dep_{dep_name}", dep_name, "error",
                               dep_result.get("message", "échec de l'import"))

                # Détail complet du pipeline de scan pour cette dépendance
                # (format/provenance/antivirus/CVE/GPG/dépendances) — même
                # niveau de détail que pour le paquet principal, jusqu'ici
                # invisible dans le frontend malgré sa présence dans
                # dependencies_resolved.
                for vs in dep_result.get("steps", []):
                    vs_name    = vs.get("name", "")
                    vs_passed  = vs.get("passed", False)
                    vs_warning = vs.get("warning", False)
                    vs_status  = "done" if (vs_passed or vs_warning) else "error"
                    vs_label   = _step_labels.get(vs_name, vs_name)
                    yield step(f"sub_dep_{dep_name}_{vs_name}", f"{dep_name} — {vs_label}", vs_status,
                               vs.get("message", ""), vs.get("detail", ""))

                if dep_status in ("added", "pending_review"):
                    for sub_name in await asyncio.to_thread(_sub_missing_deps, dep_result.get("name", dep_name)):
                        if sub_name not in dep_seen:
                            dep_seen.add(sub_name)
                            dep_queue.append(sub_name)
                            yield step("auto_deps", "Résolution des dépendances manquantes", "running",
                                       f"  ↳ sous-dépendance découverte : {sub_name}")
            summary_parts = [f"{n_added} ajoutée(s)"]
            if n_pending: summary_parts.append(f"{n_pending} en révision RSSI")
            if n_failed:  summary_parts.append(f"{n_failed} échouée(s)")
            yield step("auto_deps", "Résolution des dépendances manquantes",
                       "error" if n_failed and not n_added else "done",
                       ", ".join(summary_parts))

        if cve_status == "pending_review":
            try:
                cve_counts, kev_count, worst = compute_cve_summary(validation.cve_results or [])
                notify("PENDING_REVIEW", {
                    "package":   manifest["name"],
                    "version":   manifest["version"],
                    "from_dist": distribution,
                    "to_dist":   distribution,
                    "detail":    _cve_summary_detail(cve_counts, worst, kev_count),
                    "user":      current_user,
                })
            except Exception:
                pass

        audit_log(
            "UPLOAD", current_user,
            "PENDING_REVIEW" if cve_status == "pending_review" else "SUCCESS",
            package=manifest["name"], version=manifest["version"],
            detail=f"sha256={manifest['integrity']['sha256']}",
            extra={
                "validation_steps": validation.steps,
                "cve_status": cve_status,
                "repo_format": REPO_FORMAT,
            },
        )

        yield _sse("result", {
            "status":       "pending_review" if cve_status == "pending_review" else "accepted",
            "format":       REPO_FORMAT,
            "package":      manifest["name"],
            "version":      manifest["version"],
            "arch":         manifest["arch"],
            "sha256":       manifest["integrity"]["sha256"],
            "distribution": distribution,
            "dependencies_resolved": dependencies_resolved,
            "message": (
                f"{manifest['name']} {manifest['version']} importé — en attente de révision RSSI"
                if cve_status == "pending_review"
                else f"{manifest['name']} {manifest['version']} ajouté au dépôt {distribution}"
            ),
            "validation": validation.to_dict(),
        })

    except Exception as exc:
        yield step("error", "Erreur inattendue", "error", str(exc))
        yield _sse("result", {"status": "error", "format": REPO_FORMAT, "message": str(exc)})

    yield "data: done|DONE\n\n"


@router.post("/stream")
@limiter.limit(make_role_limit("upload"))
async def upload_package_stream(
    request: Request,
    file: UploadFile = File(...),
    distribution: str = Form(DEFAULT_DISTRIBUTION),
    current_user: str = Depends(get_uploader_user),
):
    """Upload avec workflow SSE en temps réel."""
    if distribution not in VALID_CODENAMES:
        raise HTTPException(
            status_code=400,
            detail=f"Distribution invalide : {', '.join(sorted(VALID_CODENAMES))}"
        )

    filename     = file.filename or f"unknown{next(iter(ACCEPTED_EXTENSIONS))}"
    safe_filename = Path(filename).name

    # Validation extension
    ext = Path(safe_filename).suffix.lower()
    if ext not in ACCEPTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Extension invalide '{ext}' — seuls les {_accepted_ext_hint()} sont acceptés "
                   f"(REPO_FORMAT={REPO_FORMAT})"
        )

    # Validation compatibilité format-fichier ↔ distribution (avant staging)
    expected_ext, fmt_label = _expected_ext_for_distrib(distribution)
    if ext != expected_ext:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Format incompatible : '{safe_filename}' est un paquet {ext.upper().lstrip('.')} "
                f"mais la distribution '{distribution}' attend des paquets {fmt_label}. "
                f"Sélectionnez la bonne distribution ou utilisez un fichier {expected_ext.upper().lstrip('.')}."
            ),
        )

    staging_path = STAGING_INCOMING / f"{uuid.uuid4().hex}_{safe_filename}"
    try:
        with open(staging_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur écriture staging: {e}")

    return StreamingResponse(
        _upload_stream_generator(safe_filename, staging_path, distribution, current_user),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
