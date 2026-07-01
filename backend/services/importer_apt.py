"""
Service d'import depuis internet.
Télécharge un paquet et toutes ses dépendances directement depuis les URLs
de l'index SQLite (Packages.gz), les valide, et les ajoute au repo interne.
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
ADD_DEB_SCRIPT = os.getenv("ADD_DEB_SCRIPT", "/scripts/add-deb.sh")


def _run(cmd: list[str], cwd: str = None) -> tuple[int, str, str]:
    """Exécute une commande et retourne (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=cwd
    )
    return result.returncode, result.stdout, result.stderr


def _get_source_base_url(source_url: str) -> str:
    """
    Extrait l'URL de base depuis l'URL Packages.gz.
    Ex: http://archive.ubuntu.com/ubuntu/dists/jammy/.../Packages.gz
     →  http://archive.ubuntu.com/ubuntu
    """
    return source_url.split("/dists/")[0]


def _download_deb(pkg_name: str, tmp_dir: str) -> tuple[Path | None, str, str | None]:
    """
    Télécharge un .deb depuis l'index SQLite local.
    Retourne (chemin_fichier, source_label, sha256_attendu) ou (None, message_erreur, None).
    """
    from services.package_index import DEFAULT_SOURCES
    from services.package_index import get_package_info as index_get_info

    row = index_get_info(pkg_name)
    if not row or not row.get("filename"):
        return None, f"'{pkg_name}' introuvable dans l'index — lancez une synchronisation", None

    source = next((s for s in DEFAULT_SOURCES if s["id"] == row["source_id"]), None)
    if not source:
        return None, f"Source '{row['source_id']}' inconnue", None

    base_url = _get_source_base_url(source["url"])
    download_url = f"{base_url}/{row['filename']}"
    expected_sha256 = row.get("sha256")  # SHA256 depuis Packages.gz

    filename = Path(row["filename"]).name
    dest = Path(tmp_dir) / filename

    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": "APT-Repo-Manager/2.0"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            dest.write_bytes(resp.read())
        return dest, source["label"], expected_sha256
    except urllib.error.URLError as e:
        return None, f"Erreur téléchargement {pkg_name}: {e}", None


def resolve_deps_online(package_name: str) -> dict:
    """
    Résout les dépendances d'un paquet depuis l'index SQLite.
    """
    from services.indexer import get_package_info as repo_get_info
    from services.package_index import get_package_info as index_get_info

    row = index_get_info(package_name)
    if not row:
        return {
            "success": False,
            "error": f"Paquet '{package_name}' introuvable dans l'index local. "
                     "Lancez une synchronisation d'abord.",
            "packages": [],
        }

    # Résoudre les dépendances depuis le champ depends de l'index
    dep_names = {package_name}
    if row.get("depends"):
        for part in row["depends"].split(","):
            part = part.strip().split(" ")[0].split("|")[0].strip()  # "curl (>= 7.0)" → "curl"
            # Strip architecture qualifier: "perl:any" → "perl", "libc6:amd64" → "libc6"
            if ":" in part:
                part = part.split(":")[0]
            if part and all(c.isalnum() or c in ".-+_" for c in part):
                dep_names.add(part)

    packages = []
    for dep in sorted(dep_names):
        # Vérifier d'abord dans le repo interne (nom exact)
        already_present = repo_get_info(dep) is not None
        real_name = dep
        if not already_present:
            # Résoudre les paquets virtuels via Provides dans l'index APT
            idx = index_get_info(dep)
            if idx and idx["name"] != dep:
                # Paquet virtuel : substituer par le vrai fournisseur
                real_name = idx["name"]
                already_present = repo_get_info(real_name) is not None
        packages.append({"name": real_name, "already_in_repo": already_present,
                         **({"virtual": dep} if real_name != dep else {})})

    to_download = [p for p in packages if not p["already_in_repo"]]

    return {
        "success": True,
        "package": package_name,
        "total_deps": len(packages),
        "already_in_repo": len(packages) - len(to_download),
        "to_download": len(to_download),
        "packages": packages,
    }


_STEP_LABELS = {
    "format":       "Format     ",
    "provenance":   "Provenance ",
    "antivirus":    "Antivirus  ",
    "cve":          "CVE        ",
    "gpg":          "GPG        ",
    "dependencies": "Dépendances",
}


def import_one(pkg_row: dict, distribution: str, user: str, group: str | None = None) -> dict:
    """
    Télécharge, valide et ajoute un seul paquet indexé (.deb) au repo APT.

    Retourne un dict :
      {"status": "added"|"pending_review"|"blocked"|"skipped"|"error",
       "name": str, "version": str | None, "message": str, "steps": list[dict]}
    """
    from services.audit import log as audit_log
    from services.indexer import add_to_index
    from services.manifest import generate_manifest, save_manifest
    from services.validator import run_validation_pipeline

    pkg_name = pkg_row["name"]
    version = pkg_row.get("version")

    # Skip uniquement si CETTE VERSION précise est déjà présente dans le pool
    # hiérarchique reprepro (une version plus ancienne ne doit pas bloquer la
    # mise à jour vers le correctif).
    pool_hier = POOL_DIR / "main"
    if pool_hier.exists() and version and list(pool_hier.rglob(f"{pkg_name}_{version}_*.deb")):
        return {"status": "skipped", "name": pkg_name, "version": version,
                "message": "déjà présent dans le repo", "steps": []}

    tmp_dir = tempfile.mkdtemp(prefix="apt-import-")
    try:
        path, info, expected_sha256 = _download_deb(pkg_name, tmp_dir)
        if not path:
            return {"status": "error", "name": pkg_name, "version": version,
                    "message": info, "steps": []}

        validation = run_validation_pipeline(
            str(path), expected_sha256=expected_sha256, strict_deps=False, distro=distribution
        )

        if not validation.passed:
            status = "blocked" if validation.cve_status == "blocked" else "error"
            return {"status": status, "name": pkg_name, "version": version,
                    "message": "validation échouée", "steps": validation.steps}

        # Copie dans le pool principal (pour reprepro)
        dest = POOL_DIR / path.name
        shutil.copy2(str(path), str(dest))

        # Copie dans le répertoire du groupe d'import
        group_dir = IMPORTS_DIR / (group or pkg_name)
        group_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(path), str(group_dir / path.name))

        cve_status = validation.cve_status  # "approved" | "pending_review" | "blocked"

        manifest = generate_manifest(
            str(dest),
            imported_by=user,
            import_method="internet",
            validated_deps=validation.deps if validation.deps else None,
            import_group=group or pkg_name,
            validation_steps=validation.steps,
            cve_results=validation.cve_results if validation.cve_results else None,
            distribution=distribution,
        )
        manifest["status"] = "pending_review" if cve_status == "pending_review" else "validated"
        save_manifest(manifest)
        add_to_index(manifest)

        if cve_status == "pending_review":
            audit_log("IMPORT", user, "PENDING_REVIEW",
                      package=manifest["name"], version=manifest["version"],
                      detail="En attente de révision RSSI — non publié dans APT")
            return {"status": "pending_review", "name": manifest["name"], "version": manifest["version"],
                    "message": "en attente révision RSSI (non publié)", "steps": validation.steps}

        # Ajouter au repo APT
        add_result = subprocess.run(
            ["sh", ADD_DEB_SCRIPT, distribution, dest.name],
            capture_output=True, text=True
        )
        if add_result.returncode != 0:
            stderr_out = (add_result.stderr or add_result.stdout or "").strip()[:300]
            audit_log("IMPORT", user, "WARNING",
                      package=manifest["name"], version=manifest["version"],
                      detail=f"indexé mais reprepro rc={add_result.returncode}: {stderr_out}")
            return {"status": "added", "name": manifest["name"], "version": manifest["version"],
                    "message": f"indexé mais non publié dans APT (reprepro rc={add_result.returncode}) : {stderr_out}",
                    "steps": validation.steps, "warning": True}

        audit_log("IMPORT", user, "SUCCESS",
                  package=manifest["name"], version=manifest["version"],
                  detail=f"importé depuis internet, sha256={manifest['integrity']['sha256']}")
        return {"status": "added", "name": manifest["name"], "version": manifest["version"],
                "message": "ajouté au repo", "steps": validation.steps}

    except Exception as e:
        return {"status": "error", "name": pkg_name, "version": version,
                "message": f"erreur inattendue : {e}", "steps": []}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def import_package_stream(package_name: str, user: str, group: str | None = None, distribution: str | None = None) -> Generator[str, None, None]:
    """
    Télécharge un paquet et ses dépendances, les valide et les ajoute au repo.
    Génère des messages de log en temps réel (Server-Sent Events).
    """
    from services.distributions import detect_distribution_from_source
    from services.package_index import get_package_info as index_get_info

    def emit(msg: str, level: str = "info") -> str:
        return f"data: {level}|{msg}\n\n"

    yield emit(f"Démarrage de l'import de '{package_name}'...")

    try:
        # 1. Vérifier que le paquet est dans l'index
        row = index_get_info(package_name)
        # Auto-détecter la distribution depuis la source si non fournie
        target_distrib = distribution or detect_distribution_from_source(row.get("source_id", "") if row else "")
        yield emit(f"Distribution cible : {target_distrib}")
        if not row:
            yield emit(
                f"Paquet '{package_name}' introuvable dans l'index local. "
                "Lancez une synchronisation depuis l'onglet Synchronisation.",
                "error"
            )
            return

        # 2. Résolution récursive complète de l'arbre de dépendances (index SQLite)
        #    On explore niveau par niveau jusqu'à ce que tous les nœuds soient visités
        #    ou que la limite de profondeur soit atteinte.
        yield emit("Résolution de l'arbre de dépendances (transitif)...")

        def _parse_dep_field(depends_str: str) -> list[str]:
            """Extrait les noms de paquets depuis un champ Depends."""
            names = []
            for part in depends_str.split(","):
                raw = part.strip().split(" ")[0].split("|")[0].strip()
                name = raw.split(":")[0] if ":" in raw else raw  # strip arch qualifier
                if name and all(c.isalnum() or c in ".-+_" for c in name):
                    names.append(name)
            return names

        dep_names: set[str] = {package_name}
        frontier: list[str] = [package_name]
        max_depth = 8  # limite anti-boucle (arbres Debian sont rarement >6 niveaux)
        depth = 0

        while frontier and depth < max_depth:
            depth += 1
            next_frontier: list[str] = []
            for pkg in frontier:
                pkg_row = index_get_info(pkg)
                if not pkg_row or not pkg_row.get("depends"):
                    continue
                for dep_name in _parse_dep_field(pkg_row["depends"]):
                    if dep_name not in dep_names:
                        dep_names.add(dep_name)
                        next_frontier.append(dep_name)
            frontier = next_frontier

        yield emit(f"  Arbre résolu : {len(dep_names)} paquet(s) au total (profondeur ≤ {depth})")

        # Filtrer ceux déjà dans le repo APT (pool HIÉRARCHIQUE reprepro).
        # IMPORTANT : on vérifie la présence dans pool/main/**/{dep}_*.deb
        # et NON dans le pool plat pool/{dep}_*.deb.
        # Un paquet peut être dans le pool plat (index interne) sans être dans le pool
        # hiérarchique reprepro (donc invisible / 404 pour les clients APT).
        # Seul le pool hiérarchique garantit que le paquet est réellement accessible.
        POOL_HIER = POOL_DIR / "main"
        to_download = []
        skipped = []
        for dep in sorted(dep_names):
            hier_files = list(POOL_HIER.rglob(f"{dep}_*.deb")) if POOL_HIER.exists() else []
            if hier_files:
                skipped.append(dep)
            else:
                to_download.append(dep)

        yield emit(
            f"Trouvé {len(dep_names)} paquet(s) — "
            f"{len(skipped)} déjà présent(s), {len(to_download)} à télécharger"
        )

        if not to_download:
            yield emit("Tous les paquets sont déjà dans le repo !", "success")
            return

        for name in skipped:
            yield emit(f"  [SKIP] {name} — déjà dans le repo")

        # 3. Téléchargement, validation et ajout au repo, paquet par paquet
        yield emit("Téléchargement et validation depuis internet...")
        imported = []
        failed = []

        for pkg in to_download:
            pkg_row = index_get_info(pkg)
            if not pkg_row:
                yield emit(f"  [WARN] Ignoré : '{pkg}' introuvable dans l'index", "warning")
                continue

            yield emit(f"  [DL] {pkg}...")
            result = import_one(pkg_row, target_distrib, user, group=group or package_name)

            for step in result.get("steps", []):
                label = _STEP_LABELS.get(step["name"], step["name"].capitalize())
                passed = step.get("passed", True)
                icon = "[OK]" if passed else "[FAIL]"
                level = "success" if passed else "error"
                yield emit(f"     {icon} {label} : {step['message']}", level)

            status = result["status"]
            if status == "skipped":
                skipped.append(pkg)
            elif status in ("error", "blocked"):
                yield emit(f"  [FAIL] {pkg} — {result['message']}", "error")
                failed.append(pkg)
            elif status == "pending_review":
                yield emit(
                    f"  ⏳ {result['name']} {result['version']} — "
                    "en attente révision RSSI (non publié)", "warning"
                )
                imported.append(result["name"])
            else:  # added
                if result.get("warning"):
                    yield emit(f"  ⚠ {pkg} — {result['message']}", "warning")
                else:
                    yield emit(f"  [ADD] {result['name']} {result['version']} — ajouté au repo", "success")
                imported.append(result["name"])

        # 4. Résumé final
        yield emit("─" * 50)
        yield emit(
            f"Import terminé : {len(imported)} ajouté(s), "
            f"{len(skipped)} déjà présent(s), {len(failed)} échoué(s)",
            "success" if not failed else "warning"
        )
        if failed:
            yield emit(f"Échecs : {', '.join(failed)}", "warning")

    except Exception as e:
        yield emit(f"Erreur inattendue : {e}", "error")
