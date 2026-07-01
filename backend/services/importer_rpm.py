"""
Service d'import depuis internet pour les paquets RPM.

Télécharge un paquet et ses dépendances depuis l'index SQLite (repomd.xml/primary.xml),
les valide et les ajoute au repo interne via createrepo_c.

Expose import_package_stream() comme générateur SSE pour la compatibilité
avec import_router.py (identique à l'interface APT).
"""
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Generator

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
IMPORTS_DIR = Path(os.getenv("IMPORTS_DIR", "/repos/imports"))
ADD_RPM_SCRIPT = os.getenv("ADD_RPM_SCRIPT", "/scripts/add-rpm.sh")


def _run(cmd: list[str]) -> tuple[int, str, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def _get_repo_base_url(repomd_url: str) -> str:
    """Extrait l'URL de base depuis une URL repomd.xml."""
    return repomd_url.rsplit("/repodata/", 1)[0]


def _download_rpm(pkg_name: str, tmp_dir: str, distribution: str = "") -> tuple[Path | None, str, str | None]:
    """
    Télécharge un .rpm depuis l'index SQLite local.
    Retourne (chemin_fichier, source_label, sha256_attendu) ou (None, message_erreur, None).

    distribution : si fourni (ex. "almalinux9"), cherche d'abord dans les sources
    correspondantes (almalinux9-baseos, almalinux9-appstream…) avant de se rabattre
    sur toutes les sources. Evite de retourner un package Tumbleweed incompatible
    quand un package natif EL9 existe.
    """
    # Importer DIRECTEMENT depuis package_index_rpm (pas le dispatcher combiné)
    # En mode REPO_FORMAT=all, le dispatcher cherche APT en premier → renvoie un résultat
    # DEB sans champ rpm_url, causant une fausse erreur "introuvable".
    from services.package_index_rpm import DEFAULT_SOURCES
    from services.package_index_rpm import get_package_info as _rpm_get_info

    # 1. Essayer d'abord la source native de la distribution cible
    row = None
    if distribution:
        row = _rpm_get_info(pkg_name, source_prefix=distribution)

    # 2. Fallback : n'importe quelle source
    if not row:
        row = _rpm_get_info(pkg_name)

    if not row or not row.get("rpm_url"):
        return None, f"'{pkg_name}' introuvable dans l'index — lancez une synchronisation", None

    source = next((s for s in DEFAULT_SOURCES if s["id"] == row["source_id"]), None)
    if not source:
        return None, f"Source '{row['source_id']}' inconnue", None

    base_url = _get_repo_base_url(source["repomd_url"])
    rpm_href = row["rpm_url"]
    if rpm_href.startswith("http"):
        download_url = rpm_href
    else:
        download_url = f"{base_url}/{rpm_href.lstrip('/')}"

    expected_sha256 = row.get("sha256")
    filename = Path(rpm_href).name
    dest = Path(tmp_dir) / filename

    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return dest, source["label"], expected_sha256
    except urllib.error.URLError as e:
        return None, f"Erreur téléchargement {pkg_name}: {e}", None


def resolve_deps_online(package_name: str, **_kwargs) -> dict:
    """Résout les dépendances d'un paquet RPM depuis l'index SQLite."""
    # Utiliser directement package_index_rpm pour éviter que le dispatcher
    # "all" retourne un résultat APT/APK en premier
    from services.indexer import get_package_info as repo_get_info
    from services.package_index_rpm import get_package_info as _rpm_get_info

    row = _rpm_get_info(package_name)
    if not row:
        return {
            "success": False,
            "error": f"Paquet '{package_name}' introuvable dans l'index RPM. "
                     "Lancez une synchronisation d'abord.",
            "packages": [],
        }

    # NE PAS inclure le paquet lui-même dans ses propres dépendances
    dep_names: set[str] = set()
    if row.get("requires"):
        for part in row["requires"].split(","):
            part = part.strip().split()[0] if part.strip() else ""
            # Garder uniquement les noms de paquets simples (pas les capabilities/libs)
            if part and part != package_name and all(c.isalnum() or c in ".-+_" for c in part):
                dep_names.add(part)

    packages = []
    for dep in sorted(dep_names):
        already_present = repo_get_info(dep) is not None
        packages.append({"name": dep, "already_in_repo": already_present})

    to_download = [p for p in packages if not p["already_in_repo"]]

    return {
        "success": True,
        "package": package_name,
        "total_deps": len(packages),
        "already_in_repo": len(packages) - len(to_download),
        "to_download": len(to_download),
        "packages": packages,
    }


def import_one(pkg_row: dict, distribution: str, user: str, group: str | None = None) -> dict:
    """
    Télécharge, valide et ajoute un seul paquet indexé (.rpm) au repo via createrepo_c.

    Retourne un dict :
      {"status": "added"|"pending_review"|"blocked"|"skipped"|"error",
       "name": str, "version": str | None, "message": str, "steps": list[dict]}
    Les entrées "added" incluent en plus : arch, sha256, source, createrepo_ok,
    filename, size_bytes (utilisés par import_package() pour record_import_group).
    """
    from services.audit import log as audit_log
    from services.indexer import add_to_index
    from services.manifest import generate_manifest, save_manifest
    from services.validator import run_validation_pipeline

    pkg_name = pkg_row["name"]
    version = pkg_row.get("version")

    # Skip si un .rpm de même nom est déjà dans les manifests (évite un rescan ClamAV/Grype).
    # Ne pas skipper si seul un .deb existe — APT et RPM sont des formats distincts.
    from services.indexer import get_package_info as repo_get_info
    existing = repo_get_info(pkg_name)
    if existing and (existing.get("filename", "").endswith(".rpm") or
                     existing.get("format") == "rpm"):
        return {"status": "skipped", "name": pkg_name, "version": version,
                "message": "Déjà dans le repo", "steps": []}

    with tempfile.TemporaryDirectory() as tmp_dir:
        rpm_path, source_label, expected_sha256 = _download_rpm(pkg_name, tmp_dir, distribution=distribution)
        if rpm_path is None:
            # Distinguer "absent de l'index" (skip) vs "erreur de téléchargement" (error)
            if "introuvable dans l'index" in source_label:
                return {"status": "skipped", "name": pkg_name, "version": version,
                        "message": source_label, "steps": []}
            return {"status": "error", "name": pkg_name, "version": version,
                    "message": source_label, "steps": []}

        validation = run_validation_pipeline(
            str(rpm_path),
            expected_sha256=expected_sha256,
            distro=distribution,
        )

        if not validation.passed:
            audit_log("IMPORT", user, "FAILURE",
                      package=pkg_name, detail="Validation échouée")
            status = "blocked" if validation.cve_status == "blocked" else "error"
            return {"status": status, "name": pkg_name, "version": version,
                    "message": "Validation échouée", "steps": validation.steps}

        pool_path = POOL_DIR / rpm_path.name
        shutil.copy2(str(rpm_path), str(pool_path))

        manifest = generate_manifest(
            str(pool_path),
            imported_by=user,
            import_method="internet",
            validated_deps=validation.deps or None,
            validation_steps=validation.steps,
            cve_results=validation.cve_results or None,
            distribution=distribution,
        )
        save_manifest(manifest)
        add_to_index(manifest)

        # Ajout au dépôt RPM via add-rpm.sh
        r = subprocess.run(
            ["sh", ADD_RPM_SCRIPT, distribution, pool_path.name],
            capture_output=True, text=True,
            env={**os.environ, "GNUPG_HOME": os.getenv("GNUPG_HOME", "/repos/gnupg"),
                 "REPO_BASE": os.getenv("REPO_BASE", "/repos")},
        )
        createrepo_ok = r.returncode == 0

        audit_log("IMPORT", user, "SUCCESS",
                  package=manifest["name"], version=manifest["version"],
                  detail=f"source={source_label}, sha256={manifest['integrity']['sha256']}")

        return {
            "status": "added",
            "name": manifest["name"],
            "version": manifest["version"],
            "message": "ajouté au repo" if createrepo_ok else f"indexé mais createrepo_c a échoué (rc={r.returncode})",
            "warning": not createrepo_ok,
            "steps": validation.steps,
            "arch": manifest["arch"],
            "sha256": manifest["integrity"]["sha256"],
            "source": source_label,
            "createrepo_ok": createrepo_ok,
            "filename": pool_path.name,
            "size_bytes": pool_path.stat().st_size if pool_path.exists() else 0,
        }


def import_package(
    package_name: str,
    distribution: str,
    current_user: str = "system",
) -> dict:
    """
    Importe un paquet RPM et ses dépendances depuis l'index.
    Retourne un dict de résultats (non-streaming).
    """
    results = []
    errors = []

    deps_info = resolve_deps_online(package_name)
    if not deps_info["success"]:
        return {"success": False, "error": deps_info["error"], "results": []}

    packages_to_get = [p["name"] for p in deps_info["packages"] if not p["already_in_repo"]]
    if not packages_to_get:
        return {
            "success": True,
            "message": "Tous les paquets sont déjà présents dans le repo",
            "results": [],
            "skipped": [p["name"] for p in deps_info["packages"]],
        }

    group_files = []
    not_indexed: list[str] = []   # absents de l'index → warning, pas erreur

    for pkg_name in packages_to_get:
        result = import_one({"name": pkg_name}, distribution, current_user)
        status = result["status"]
        if status == "skipped":
            not_indexed.append(pkg_name)
        elif status in ("error", "blocked"):
            errors.append({"name": pkg_name, "error": result["message"], "steps": result.get("steps", [])})
        else:  # added
            group_files.append({
                "filename":   result["filename"],
                "size_bytes": result["size_bytes"],
            })
            results.append({
                "name":          result["name"],
                "version":       result["version"],
                "arch":          result["arch"],
                "sha256":        result["sha256"],
                "source":        result["source"],
                "createrepo_ok": result["createrepo_ok"],
            })

    if group_files:
        import time

        from services.package_index import record_import_group
        group_name = f"{package_name}-{int(time.time())}"
        record_import_group(
            name=group_name,
            files=group_files,
            distribution=distribution,
            imported_by=current_user,
        )

    return {
        "success":      True,
        "imported":     len(results),
        "errors":       len(errors),
        "not_indexed":  len(not_indexed),
        "results":      results,
        "error_details":    errors,
        "not_indexed_details": not_indexed,
    }


def import_package_stream(
    package_name: str,
    user: str,
    group: str | None = None,
    distribution: str | None = None,
) -> Generator[str, None, None]:
    """
    Interface streaming SSE compatible avec import_router.py (identique à l'APT).
    Enveloppe import_package() et génère des messages SSE en temps réel.

    distribution est obligatoire en mode RPM (pas d'auto-détection).
    """
    from services.format_router import DEFAULT_DISTRIBUTION

    def emit(msg: str, level: str = "info") -> str:
        return f"data: {level}|{msg}\n\n"

    # Résoudre la distribution cible
    target_distrib = distribution or DEFAULT_DISTRIBUTION

    yield emit(f"Démarrage de l'import RPM de '{package_name}'...")
    yield emit(f"Distribution cible : {target_distrib}")

    # Résolution des dépendances
    yield emit("Résolution des dépendances depuis l'index RPM...")
    deps_info = resolve_deps_online(package_name)
    if not deps_info["success"]:
        yield emit(deps_info["error"], "error")
        return

    packages = deps_info["packages"]
    already_in = [p for p in packages if p["already_in_repo"]]
    to_download = [p for p in packages if not p["already_in_repo"]]

    yield emit(
        f"  {len(packages)} paquet(s) résolu(s) — "
        f"{len(already_in)} déjà présent(s), {len(to_download)} à télécharger"
    )

    if not to_download:
        yield emit("Tous les paquets sont déjà dans le repo !", "success")
        return

    for p in already_in:
        yield emit(f"  [SKIP] {p['name']} — deja dans le repo")

    # Téléchargement et import
    yield emit("Téléchargement et import depuis internet...")
    result = import_package(package_name, target_distrib, current_user=user)

    if not result["success"]:
        yield emit(f"Erreur : {result.get('error', 'Inconnue')}", "error")
        return

    for item in result.get("results", []):
        yield emit(
            f"  [ADD] {item['name']} {item['version']} — ajouté au repo",
            "success"
        )

    # Deps absentes de l'index → warning (probablement fournies par le repo système)
    for pkg_name in result.get("not_indexed_details", []):
        yield emit(
            f"  [WARN] {pkg_name} — absent de l'index prive"
            f" (fourni par le repo systeme de la cible)",
            "warning"
        )

    # Vraies erreurs (téléchargement/validation échoués)
    for err in result.get("error_details", []):
        yield emit(f"  [FAIL] {err['name']} — {err.get('error', 'Echec')}", "error")

    n_imported    = result.get("imported", 0)
    n_not_indexed = result.get("not_indexed", 0)
    n_errors      = result.get("errors", 0)
    n_skipped     = len(already_in)

    yield emit("─" * 50)

    summary_parts = [f"{n_imported} ajouté(s)"]
    if n_skipped:
        summary_parts.append(f"{n_skipped} déjà présent(s)")
    if n_not_indexed:
        summary_parts.append(f"{n_not_indexed} absent(s) de l'index")
    if n_errors:
        summary_parts.append(f"{n_errors} échoué(s)")

    summary_level = "success" if not n_errors else "warning"
    yield emit(f"Import terminé : {', '.join(summary_parts)}", summary_level)

    if n_not_indexed:
        yield emit(
            "Les paquets absents de l'index seront résolus par le gestionnaire"
            " de paquets de la machine cible (BaseOS / EPEL / repo système).",
            "info"
        )
