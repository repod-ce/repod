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
        return None, f"'{pkg_name}' introuvable dans l'index APK — lancez une synchronisation", None
    if not source:
        return None, f"Source APK '{row.get('source_id')}' inconnue", None

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
        return None, f"Erreur HTTP {e.code} — {download_url}", None
    except Exception as e:
        return None, f"Erreur téléchargement : {e}", None

    apk_checksum = row.get("apk_checksum")
    return dest, source.get("label", source["id"]), apk_checksum


def resolve_deps_online(package_name: str, distro: str | None = None, max_depth: int = 8) -> dict:
    """
    Résout l'arbre COMPLET (transitif) des dépendances d'un paquet APK,
    jusqu'à max_depth niveaux — même patron que importer_apt.py.

    Alpine exprime la quasi-totalité de ses dépendances de bibliothèques via
    des capabilities (so:libssl.so.3, cmd:bash, pc:zlib…) plutôt que des noms
    de paquets directement dans le champ Depends — auparavant ces tokens
    étaient filtrés/ignorés purement et simplement, ce qui faisait passer à
    la trappe la grande majorité des dépendances réelles. Elles sont
    maintenant résolues vers le paquet qui les fournit via
    resolve_provide_to_package() (colonne `provides`, même convention que
    RPM). Les chemins absolus (/bin/sh…) restent non résolus — généralement
    déjà fournis par l'image de base (busybox) de la machine cible.
    """
    from services.package_index_apk import get_package_info, resolve_provide_to_package

    root_row, _ = _get_package_info_apk(package_name, distro)
    if not root_row:
        return {
            "success": False,
            "error": f"Paquet '{package_name}' introuvable dans l'index APK. "
                     "Lancez une synchronisation d'abord.",
            "total_deps": 0, "already_in_repo": 0, "to_download": 0, "packages": [], "unresolved": [],
        }

    def _tokens(depends_str: str | None) -> list[str]:
        return [d for d in (depends_str or "").split() if d and not d.startswith("!")]

    def _resolve_token(token: str) -> str | None:
        if token.startswith(("so:", "cmd:", "pc:")):
            provided = resolve_provide_to_package(token)
            return provided["name"] if provided else None
        if token.startswith("/"):
            return None
        name = token.split("=")[0].split(">")[0].split("<")[0].split("~")[0].strip()
        return name or None

    resolved_names: set[str] = set()
    unresolved: set[str] = set()
    seen_tokens: set[str] = set()
    frontier_rows: list[dict] = [root_row]
    depth = 0

    while frontier_rows and depth < max_depth:
        depth += 1
        next_frontier: list[dict] = []
        for row in frontier_rows:
            for token in _tokens(row.get("depends")):
                if token in seen_tokens:
                    continue
                seen_tokens.add(token)
                real_name = _resolve_token(token)
                if not real_name:
                    unresolved.add(token)
                    continue
                if real_name == package_name or real_name in resolved_names:
                    continue
                resolved_names.add(real_name)
                dep_row, _ = _get_package_info_apk(real_name, distro)
                if dep_row:
                    next_frontier.append(dep_row)
        frontier_rows = next_frontier

    packages = []
    for dep_name in sorted(resolved_names):
        in_repo = any(POOL_DIR.glob(f"{dep_name}-*.apk"))
        dep_row = get_package_info(dep_name)
        packages.append({
            "name":            dep_name,
            "version":         dep_row["version"] if dep_row else None,
            "already_in_repo": in_repo,
        })

    in_repo = sum(1 for p in packages if p["already_in_repo"])
    return {
        "success":         True,
        "package":         package_name,
        "total_deps":      len(packages),
        "already_in_repo": in_repo,
        "to_download":     len(packages) - in_repo,
        "packages":        packages,
        "unresolved":      sorted(unresolved),
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
        apk_path, label_or_err, apk_checksum = _download_apk(pkg_name, tmp_dir, distro=distribution)
        if apk_path is None:
            # "introuvable dans l'index" → skip (dep système/non-indexée), autre → erreur
            if "introuvable dans l'index" in label_or_err:
                return {"status": "skipped", "name": pkg_name, "version": version,
                        "message": label_or_err, "steps": []}
            return {"status": "error", "name": pkg_name, "version": version,
                    "message": label_or_err, "steps": []}

        validation = run_validation_pipeline(
            str(apk_path), strict_deps=False, distro=distribution,
            apk_control_checksum=apk_checksum,
        )

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

        cve_status = validation.cve_status  # "approved" | "pending_review" | "blocked"

        manifest = generate_manifest(
            str(pool_path),
            imported_by=user,
            validation_steps=validation.steps,
            cve_results=validation.cve_results or None,
            distribution=distribution,
        )
        manifest["status"] = "pending_review" if cve_status == "pending_review" else "validated"
        save_manifest(manifest)
        add_to_index(manifest)

        if cve_status == "pending_review":
            audit_log("IMPORT", user, "PENDING_REVIEW",
                      package=manifest["name"], version=manifest.get("version"),
                      detail="En attente de révision RSSI — non publié dans APK")
            return {"status": "pending_review", "name": manifest["name"], "version": manifest.get("version"),
                    "message": "en attente révision RSSI (non publié)", "steps": validation.steps}

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

        # 1. Résolution des dépendances (transitive — voir resolve_deps_online())
        yield _emit("Résolution de l'arbre de dépendances (transitif)...")
        deps_info = resolve_deps_online(package_name, distro=distribution)
        already   = deps_info["already_in_repo"]
        to_dl     = deps_info["to_download"]
        total     = deps_info["total_deps"]
        unresolved = deps_info.get("unresolved", [])
        yield _emit(f"{total} dep(s) resolu(s) — {already} deja present(s), {to_dl} a telecharger")
        if unresolved:
            yield _emit(
                f"  [WARN] {len(unresolved)} capability(s) non resolue(s) vers un paquet reel : "
                f"{', '.join(unresolved[:10])}{'…' if len(unresolved) > 10 else ''}",
                "warning",
            )

        # 2. Liste à importer : principal + dépendances manquantes
        yield _emit("Téléchargement et import depuis internet...")
        to_import = [package_name] + [
            p["name"] for p in deps_info["packages"] if not p["already_in_repo"]
        ]

        added       = 0
        skipped     = 0
        failed      = 0
        not_indexed = 0
        pending     = 0

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
            elif status == "pending_review":
                yield _emit(
                    f"  ⏳ {result['name']} {result.get('version', '')} — "
                    "en attente révision RSSI (non publié)", "warning"
                )
                pending += 1
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
        if pending:
            parts.append(f"{pending} en attente révision RSSI")
        if skipped:
            parts.append(f"{skipped} deja present(s)")
        if not_indexed:
            parts.append(f"{not_indexed} absent(s) de l'index")
        if unresolved:
            parts.append(f"{len(unresolved)} capability(s) non resolue(s)")
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
