"""
Service d'import depuis internet pour les paquets APK (Alpine Linux).
Télécharge un paquet et ses dépendances depuis l'index SQLite (APKINDEX),
les valide via le pipeline complet, et les ajoute au repo interne.
"""
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Generator

POOL_DIR    = Path(os.getenv("POOL_DIR",    "/repos/pool"))
IMPORTS_DIR = Path(os.getenv("IMPORTS_DIR", "/repos/imports"))


def _emit(msg: str, level: str = "info") -> str:
    """Format SSE : data: level|message\\n\\n — compatible avec LogLine.js"""
    return f"data: {level}|{msg}\n\n"


def _get_package_info_apk(pkg_name: str, distro: str | None = None):
    """
    Cherche un paquet APK dans l'index SQLite.
    Si distro est fourni (ex: 'alpine3.21'), filtre sur cette distro en priorité.
    """
    from services.package_index_apk import DEFAULT_SOURCES, get_package_info

    if distro:
        matching = [s for s in DEFAULT_SOURCES if s.get("distro") == distro]
        for source in matching:
            row = get_package_info(pkg_name, source_id=source["id"])
            if row:
                return row, source

    # Fallback sans filtre
    row = get_package_info(pkg_name)
    if not row:
        return None, None
    source = next((s for s in DEFAULT_SOURCES if s["id"] == row["source_id"]), None)
    return row, source


def _build_download_url(row: dict, source: dict) -> str:
    """
    Construit l'URL de téléchargement depuis les métadonnées du paquet.
    Ex : https://dl-cdn.alpinelinux.org/alpine/v3.21/main/x86_64/openssh-9.9_p2-r0.apk
    """
    base_url = source["apkindex_url"].rsplit("/", 1)[0]  # supprime "APKINDEX.tar.gz"
    filename = f"{row['name']}-{row['version']}.apk"
    return f"{base_url}/{filename}"


def _download_apk(pkg_name: str, tmp_dir: str, distro: str | None = None) -> tuple:
    """
    Télécharge un .apk depuis l'index SQLite local.
    Retourne (chemin_fichier, source_label) ou (None, message_erreur).
    """
    row, source = _get_package_info_apk(pkg_name, distro)
    if not row:
        return None, f"'{pkg_name}' introuvable dans l'index APK — lancez une synchronisation"
    if not source:
        return None, f"Source APK '{row.get('source_id')}' inconnue"

    download_url = _build_download_url(row, source)
    filename = f"{row['name']}-{row['version']}.apk"
    dest = Path(tmp_dir) / filename

    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": "repod/1.0 (private-repo-manager)"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(dest, "wb") as f:
                shutil.copyfileobj(resp, f)
    except urllib.error.HTTPError as e:
        return None, f"Erreur HTTP {e.code} — {download_url}"
    except Exception as e:
        return None, f"Erreur téléchargement : {e}"

    return dest, source.get("label", source["id"])


def resolve_deps_online(package_name: str, distro: str | None = None) -> dict:
    """
    Résout les dépendances directes d'un paquet APK depuis l'index.
    Retourne un dict compatible avec l'interface commune.
    """
    from services.package_index_apk import get_package_info

    row, _ = _get_package_info_apk(package_name, distro)
    if not row:
        return {"total_deps": 0, "already_in_repo": 0, "to_download": 0, "packages": []}

    raw_deps = (row.get("depends") or "").split()
    # Filtrer les dépendances système (so:..., cmd:..., pc:..., !...)
    pkg_deps = [
        d for d in raw_deps
        if d
        and not d.startswith("so:")
        and not d.startswith("cmd:")
        and not d.startswith("!")
        and not d.startswith("pc:")
        and not d.startswith("/")   # exclut les chemins absolus (/bin/sh, /usr/bin/...)
    ]

    packages = []
    for dep in pkg_deps:
        dep_name = dep.split("=")[0].split(">")[0].split("<")[0].split("~")[0].strip()
        if not dep_name or "/" in dep_name:
            continue  # sécurité supplémentaire contre les chemins
        in_repo = any(POOL_DIR.glob(f"{dep_name}-*.apk"))
        dep_row = get_package_info(dep_name)
        packages.append({
            "name":            dep_name,
            "version":         dep_row["version"] if dep_row else None,
            "already_in_repo": in_repo,
        })

    in_repo = sum(1 for p in packages if p["already_in_repo"])
    return {
        "total_deps":      len(packages),
        "already_in_repo": in_repo,
        "to_download":     len(packages) - in_repo,
        "packages":        packages,
    }


_STEP_LABELS = {
    "format":       "Format .apk",
    "checksum":     "Integrite SHA-256",
    "provenance":   "Provenance SHA-256",
    "gpg":          "Signature GPG",
    "antivirus":    "Antivirus ClamAV",
    "cve":          "Analyse CVE (Grype)",
    "dependencies": "Dependances",
}


def import_one(pkg_row: dict, distribution: str, user: str, group: str | None = None) -> dict:
    """
    Télécharge, valide et ajoute un seul paquet indexé (.apk) au dépôt Alpine.

    Retourne un dict :
      {"status": "added"|"pending_review"|"blocked"|"skipped"|"error",
       "name": str, "version": str | None, "message": str, "steps": list[dict]}
    """
    import tempfile

    from services.audit import log as audit_log
    from services.distributions_apk import add_package as apk_add_package
    from services.indexer import add_to_index
    from services.manifest import generate_manifest, save_manifest
    from services.validator import run_validation_pipeline

    pkg_name = pkg_row["name"]
    version = pkg_row.get("version")

    if any(POOL_DIR.glob(f"{pkg_name}-*.apk")):
        return {"status": "skipped", "name": pkg_name, "version": version,
                "message": "déjà présent dans le dépôt", "steps": []}

    with tempfile.TemporaryDirectory() as tmp_dir:
        apk_path, label_or_err = _download_apk(pkg_name, tmp_dir, distro=distribution)
        if apk_path is None:
            # "introuvable dans l'index" → skip (dep système/non-indexée), autre → erreur
            if "introuvable dans l'index" in label_or_err:
                return {"status": "skipped", "name": pkg_name, "version": version,
                        "message": label_or_err, "steps": []}
            return {"status": "error", "name": pkg_name, "version": version,
                    "message": label_or_err, "steps": []}

        validation = run_validation_pipeline(str(apk_path), strict_deps=False, distro=distribution)

        if not validation.passed:
            failed_steps = [
                s for s in validation.steps
                if not s.get("passed") and not s.get("warning")
            ]
            reason = (
                failed_steps[0].get("message", "validation echouee")
                if failed_steps else "validation echouee"
            )
            audit_log("IMPORT", user, "FAILURE", package=pkg_name, detail=reason)
            status = "blocked" if validation.cve_status == "blocked" else "error"
            return {"status": status, "name": pkg_name, "version": version,
                    "message": reason, "steps": validation.steps}

        pool_path = POOL_DIR / apk_path.name
        shutil.copy2(str(apk_path), str(pool_path))

        manifest = generate_manifest(
            str(pool_path),
            imported_by=user,
            validation_steps=validation.steps,
            cve_results=validation.cve_results or None,
            distribution=distribution,
        )
        save_manifest(manifest)
        add_to_index(manifest)

        ok, repo_msg = apk_add_package(pool_path, distribution)
        audit_log(
            "IMPORT", user, "SUCCESS",
            package=pkg_name,
            version=manifest.get("version"),
            detail=f"distribution={distribution}",
        )
        if ok:
            return {"status": "added", "name": manifest["name"], "version": manifest.get("version"),
                    "message": f"ajouté au dépôt APK ({distribution})", "steps": validation.steps}
        return {"status": "added", "name": manifest["name"], "version": manifest.get("version"),
                "message": f"importé mais erreur repo : {repo_msg}", "steps": validation.steps,
                "warning": True}


def import_package_stream(
    package_name: str,
    user: str,
    group: str | None = None,
    distribution: str | None = None,
) -> Generator[str, None, None]:
    """
    Importe un paquet APK et ses dépendances directes avec pipeline complet.
    Générateur SSE : format `data: level|message\\n\\n` (compatible LogLine.js).
    NE PAS émettre `done|DONE` ici — le router l'ajoute après le générateur.
    """
    from services.package_index_apk import get_package_info as index_get_info

    try:
        yield _emit(f"Démarrage de l'import APK de '{package_name}'...")
        yield _emit(f"Distribution cible : {distribution or 'auto-détection'}")

        # 1. Résolution des dépendances
        yield _emit("Résolution des dépendances depuis l'index APK...")
        deps_info = resolve_deps_online(package_name, distro=distribution)
        already   = deps_info["already_in_repo"]
        to_dl     = deps_info["to_download"]
        total     = deps_info["total_deps"]
        yield _emit(f"{total} dep(s) resolu(s) — {already} deja present(s), {to_dl} a telecharger")

        # 2. Liste à importer : principal + dépendances manquantes
        yield _emit("Téléchargement et import depuis internet...")
        to_import = [package_name] + [
            p["name"] for p in deps_info["packages"] if not p["already_in_repo"]
        ]

        added       = 0
        skipped     = 0
        failed      = 0
        not_indexed = 0

        for pkg_name in to_import:
            # Vérifier si déjà dans le pool
            if any(POOL_DIR.glob(f"{pkg_name}-*.apk")):
                yield _emit(f"  [SKIP] {pkg_name} — deja dans le depot")
                skipped += 1
                continue

            pkg_row = index_get_info(pkg_name, source_id=None)
            if not pkg_row:
                yield _emit(
                    f"  [WARN] {pkg_name} — absent de l'index prive"
                    " (fourni par le repo systeme de la cible)",
                    "warning",
                )
                not_indexed += 1
                continue
            result = import_one(pkg_row, distribution, user, group=group)

            for vs in result.get("steps", []):
                name    = vs.get("name", "")
                passed  = vs.get("passed", False)
                warning = vs.get("warning", False)
                label   = _STEP_LABELS.get(name, name)
                detail  = vs.get("message", "")
                if passed or warning:
                    lvl = "success" if passed and not warning else "warning"
                    yield _emit(f"     [OK] {label} : {detail}", lvl)
                else:
                    yield _emit(f"     [FAIL] {label} : {detail}", "error")

            status = result["status"]
            if status == "skipped":
                if "introuvable dans l'index" in result["message"]:
                    yield _emit(
                        f"  [WARN] {pkg_name} — absent de l'index prive"
                        f" (fourni par le repo systeme de la cible)",
                        "warning"
                    )
                    not_indexed += 1
                else:
                    yield _emit(f"  [SKIP] {pkg_name} — {result['message']}")
                    skipped += 1
            elif status in ("error", "blocked"):
                yield _emit(f"  [REJECT] {pkg_name} — {result['message']}", "error")
                failed += 1
            else:  # added
                if result.get("warning"):
                    yield _emit(f"  [WARN] {pkg_name} importe mais erreur repo : {result['message']}", "warning")
                else:
                    yield _emit(
                        f"  [ADD] {result['name']} {result.get('version', '')} "
                        f"{result['message']}",
                        "success",
                    )
                added += 1

        # Résumé final
        yield _emit("─" * 48)
        summary_level = "success" if not failed else "warning"

        parts = [f"{added} ajoute(s)"]
        if skipped:
            parts.append(f"{skipped} deja present(s)")
        if not_indexed:
            parts.append(f"{not_indexed} absent(s) de l'index")
        if failed:
            parts.append(f"{failed} echoue(s)")

        yield _emit(f"Import termine : {', '.join(parts)}", summary_level)

        if not_indexed:
            yield _emit(
                "Les paquets absents seront resolus par le gestionnaire de paquets"
                " de la machine cible (Alpine main/community/edge).",
                "info",
            )

    except Exception as exc:  # noqa: BLE001
        import traceback
        tb = traceback.format_exc()
        yield _emit(f"[ERR] Erreur interne : {exc}", "error")
        yield _emit(f"[ERR] Detail : {tb[:500]}", "error")
