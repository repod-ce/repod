"""
Gestion de l'index central index.json.
Catalogue immuable de tous les artefacts validés dans le dépôt.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

INDEX_PATH = Path(os.getenv("INDEX_PATH", "/repos/manifests/index.json"))
INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)

_lock = Lock()

_CVE_SEVERITIES = ["critical", "high", "medium", "low", "negligible"]


def _extract_cve_summary(validation_steps: list) -> dict | None:
    """Extrait un résumé CVE depuis les validation_steps d'un manifest."""
    cve_step = next((s for s in validation_steps if s.get("name") == "cve"), None)
    if not cve_step:
        return None
    detail = cve_step.get("detail", "")
    counts = {s: 0 for s in _CVE_SEVERITIES}
    for line in detail.splitlines():
        for sev in _CVE_SEVERITIES:
            prefix = f"{sev.capitalize()} "
            if sev in line.lower() and "|" in line:
                for part in line.split("|"):
                    part = part.strip()
                    for s in _CVE_SEVERITIES:
                        if part.lower().endswith(s) or part.lower().endswith(f"{s}:"):
                            try:
                                counts[s] = int(part.split()[0])
                            except (ValueError, IndexError):
                                pass
    # Parsing plus robuste via le message court
    msg = cve_step.get("message", "")
    for part in msg.replace("Grype —", "").replace("CVE(s) bloquante(s) :", "").split("|"):
        part = part.strip()
        for sev in _CVE_SEVERITIES:
            if part.lower().endswith(sev):
                try:
                    counts[sev] = int(part.split()[0])
                except (ValueError, IndexError):
                    pass
    return {
        "scanned": True,
        "passed": cve_step.get("passed", True),
        **counts,
    }


def _load_index() -> dict:
    if not INDEX_PATH.exists():
        return {"version": "1.0", "updated_at": None, "packages": {}}
    with open(INDEX_PATH) as f:
        return json.load(f)


def _save_index(index: dict):
    """Écriture atomique : temp file + os.replace() pour éviter la corruption."""
    index["updated_at"] = datetime.now(timezone.utc).isoformat()
    dir_ = INDEX_PATH.parent
    with tempfile.NamedTemporaryFile("w", dir=dir_, delete=False, suffix=".tmp",
                                     encoding="utf-8") as tmp:
        json.dump(index, tmp, indent=2, ensure_ascii=False)
        tmp_path = tmp.name
    os.replace(tmp_path, INDEX_PATH)


def add_to_index(manifest: dict):
    """Ajoute ou met à jour un artefact dans l'index."""
    with _lock:
        index = _load_index()
        name = manifest["name"]

        if name not in index["packages"]:
            index["packages"][name] = {"versions": {}}

        version = manifest["version"]
        index["packages"][name]["versions"][version] = {
            "arch": manifest.get("arch", "unknown"),
            "filename": manifest.get("filename"),
            "sha256": manifest["integrity"]["sha256"],
            "size_bytes": manifest.get("file_size_bytes", 0),
            "imported_at": manifest["source"]["imported_at"],
            "imported_by": manifest["source"]["imported_by"],
            "status": manifest.get("status", "validated"),
            "distribution": manifest.get("distribution", "jammy"),
            "deps_missing": [
                d["name"] for d in manifest.get("dependencies", [])
                if not d.get("available_internally", True)
            ],
            "cve_summary": _extract_cve_summary(manifest.get("validation_steps", [])),
        }

        # Mettre à jour la version "latest"
        versions = index["packages"][name]["versions"]
        index["packages"][name]["latest"] = sorted(versions.keys())[-1]
        index["packages"][name]["description"] = manifest.get("description", "")
        index["packages"][name]["section"] = manifest.get("section", "")

        _save_index(index)


def remove_from_index(name: str, version: str | None = None):
    """Supprime un artefact ou une version spécifique de l'index."""
    with _lock:
        index = _load_index()
        if name not in index["packages"]:
            return

        if version:
            index["packages"][name]["versions"].pop(version, None)
            if not index["packages"][name]["versions"]:
                del index["packages"][name]
            else:
                remaining = list(index["packages"][name]["versions"].keys())
                index["packages"][name]["latest"] = sorted(remaining)[-1]
        else:
            del index["packages"][name]

        _save_index(index)


def get_index() -> dict:
    with _lock:
        return _load_index()


def get_package_info(name: str) -> dict | None:
    with _lock:
        index = _load_index()
        return index["packages"].get(name)


def _strip_arch_qualifier(name: str) -> str:
    """Supprime le qualificateur d'architecture Debian : 'perl:any' → 'perl'."""
    return name.split(":")[0] if ":" in name else name


def _collect_transitive_missing(
    pkg_name: str,
    index_packages: dict,
    known_names: set,
    visited: set,
    depth: int = 0,
    max_depth: int = 4,
) -> list[str]:
    """
    Remonte l'arbre de dépendances dans l'index (sans lire les .deb) pour
    détecter les dépendances transitives manquantes.

    Algorithme :
    - Si dep absente de l'index → manquante
    - Si dep présente mais A ELLE-MÊME des deps manquantes → transitif manquant
    Limité à max_depth niveaux pour rester O(N) en pratique.
    """
    if depth > max_depth or pkg_name in visited:
        return []
    visited.add(pkg_name)

    info = index_packages.get(pkg_name)
    if not info:
        return [pkg_name]  # absent de l'index → manquant

    latest = info.get("latest")
    if not latest:
        return []
    latest_info = info["versions"].get(latest, {})

    result: list[str] = []
    for dep in latest_info.get("deps_missing", []):
        clean = _strip_arch_qualifier(dep)
        if clean not in known_names:
            result.append(clean)
        else:
            # Dep présente dans l'index : vérifier SES propres manquantes
            sub = _collect_transitive_missing(clean, index_packages, known_names, visited, depth + 1, max_depth)
            result.extend(sub)
    return result


def list_packages_from_index() -> list[dict]:
    """Retourne la liste enrichie des paquets depuis l'index.
    deps_missing est recalculé dynamiquement à chaque appel, en incluant
    les dépendances transitives manquantes (dépendances des dépendances)."""
    with _lock:
        index = _load_index()
        known_packages = set(index["packages"].keys())
        packages = []
        for name, info in index["packages"].items():
            latest = info.get("latest")
            latest_info = info["versions"].get(latest, {})
            # Recalcul en temps réel : dep manquante = déclarée manquante ET toujours absente de l'index
            # On strip les qualificateurs d'architecture (perl:any → perl) avant la comparaison
            stored_missing = latest_info.get("deps_missing", [])
            deps_missing_direct = [
                _strip_arch_qualifier(dep)
                for dep in stored_missing
                if _strip_arch_qualifier(dep) not in known_packages
            ]
            # Dépendances transitives : une dep "connue" peut avoir SES PROPRES manquantes
            deps_missing_transitive: list[str] = []
            for dep in stored_missing:
                clean = _strip_arch_qualifier(dep)
                if clean in known_packages:
                    sub = _collect_transitive_missing(
                        clean, index["packages"], known_packages, visited=set(), depth=0
                    )
                    deps_missing_transitive.extend(sub)
            # Fusion + dédoublonnage en préservant l'ordre
            all_missing = list(dict.fromkeys(deps_missing_direct + deps_missing_transitive))
            packages.append({
                "name": name,
                "latest_version": latest,
                "versions": list(info["versions"].keys()),
                "arch": latest_info.get("arch", "unknown"),
                "sha256": latest_info.get("sha256", ""),
                "size_bytes": latest_info.get("size_bytes", 0),
                "imported_at": latest_info.get("imported_at", ""),
                "imported_by": latest_info.get("imported_by", ""),
                "status": latest_info.get("status", "validated"),
                "distribution": latest_info.get("distribution", "jammy"),
                "deps_missing": all_missing,
                "description": info.get("description", ""),
                "section": info.get("section", ""),
                "cve_summary": latest_info.get("cve_summary"),
            })
        return packages


def sync_index_from_pool():
    """
    Resynchronise l'index depuis les fichiers manifests existants.
    Utile pour reconstruire l'index après un import manuel.
    """
    from services.manifest import list_manifests
    with _lock:
        index = {"version": "1.0", "updated_at": None, "packages": {}}
        for manifest in list_manifests():
            name = manifest["name"]
            version = manifest["version"]
            if name not in index["packages"]:
                index["packages"][name] = {"versions": {}}
            index["packages"][name]["versions"][version] = {
                "arch": manifest.get("arch", "unknown"),
                "filename": manifest.get("filename"),
                "sha256": manifest["integrity"]["sha256"],
                "size_bytes": manifest.get("file_size_bytes", 0),
                "imported_at": manifest["source"]["imported_at"],
                "imported_by": manifest["source"]["imported_by"],
                "status": manifest.get("status", "validated"),
                "distribution": manifest.get("distribution", "jammy"),
                "deps_missing": [
                    d["name"] for d in manifest.get("dependencies", [])
                    if not d.get("available_internally", True)
                ],
                "cve_summary": _extract_cve_summary(manifest.get("validation_steps", [])),
            }
            versions = index["packages"][name]["versions"]
            index["packages"][name]["latest"] = sorted(versions.keys())[-1]
            index["packages"][name]["description"] = manifest.get("description", "")
            index["packages"][name]["section"] = manifest.get("section", "")
        _save_index(index)
        return len(index["packages"])
