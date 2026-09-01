# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_no_import_side_effects.py
Rôle   : garde-fou contre la régression qui a cassé la CI (7 erreurs de
         collecte pytest). services/component_sbom.py créait SBOM_DIR
         (/repos/sboms par défaut) au niveau module ; routers/upload.py
         l'importe et routers/__init__.py importe upload, donc le moindre
         `import routers` tentait un mkdir sur /repos et levait
         PermissionError sur un runner GitHub. Toute la collecte échouait
         avant qu'un seul test ne tourne.

         Le correctif est une convention : importer un module ne doit jamais
         toucher au filesystem. Les répertoires sont créés à la première
         écriture. Ce test verrouille la convention pour les prochains
         X_DIR ajoutés, sinon la panne réapparaît telle quelle.

         Analyse purement statique (ast) : ce module n'importe aucun des
         modules inspectés, ce qui serait précisément l'effet de bord testé.

Dépend : ast, pathlib (aucune dépendance applicative)
"""
import ast
import uuid
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parent.parent
_PACKAGES = ("services", "routers", "auth", "db")

# Appels considérés comme touchant le filesystem au niveau module.
_FS_WRITERS = frozenset({"mkdir", "makedirs", "touch", "write_text", "write_bytes"})


def _module_level_fs_calls(tree: ast.Module) -> list[tuple[str, int]]:
    """Retourne les (nom_appel, ligne) exécutés à l'import du module.

    On descend dans les `for`/`if`/`try`/`with` de premier niveau (le bug
    d'origine était un `for _d in [...]: _d.mkdir(...)`) mais jamais dans un
    corps de fonction ou de classe : là, le code ne s'exécute pas à l'import.
    """
    found: list[tuple[str, int]] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Call):
                func = child.func
                if isinstance(func, ast.Attribute) and func.attr in _FS_WRITERS:
                    found.append((func.attr, child.lineno))
            visit(child)

    visit(tree)
    return found


def _python_sources() -> list[Path]:
    return sorted(
        path
        for package in _PACKAGES
        for path in (_BACKEND / package).rglob("*.py")
    )


@pytest.mark.parametrize(
    "source", _python_sources(), ids=lambda p: str(p.relative_to(_BACKEND))
)
def test_module_import_does_not_touch_filesystem(source: Path):
    """Aucune écriture disque au niveau module dans services/ routers/ auth/ db/."""
    calls = _module_level_fs_calls(ast.parse(source.read_text(encoding="utf-8")))
    assert not calls, (
        f"{source.relative_to(_BACKEND)} écrit sur le disque à l'import : "
        + ", ".join(f"{name}() ligne {line}" for name, line in calls)
        + ". Déplacer l'appel dans la fonction qui écrit (voir "
        "services/component_sbom.py). Un mkdir au niveau module rend "
        "`import routers` impossible là où /repos n'est pas inscriptible et "
        "casse toute la collecte pytest."
    )


def test_guard_detects_a_module_level_mkdir():
    """Le détecteur voit bien le motif exact qui avait cassé la CI."""
    source = (
        "from pathlib import Path\n"
        "SBOM_DIR = Path('/repos/sboms')\n"
        "SBOM_DIR.mkdir(parents=True, exist_ok=True)\n"
    )
    assert _module_level_fs_calls(ast.parse(source)) == [("mkdir", 3)]


def test_guard_detects_a_mkdir_inside_a_module_level_loop():
    """Variante routers/upload.py : mkdir dans une boucle de premier niveau."""
    source = (
        "from pathlib import Path\n"
        "DIRS = [Path('/repos/pool')]\n"
        "for _d in DIRS:\n"
        "    _d.mkdir(parents=True, exist_ok=True)\n"
    )
    assert _module_level_fs_calls(ast.parse(source)) == [("mkdir", 4)]


def test_guard_allows_a_mkdir_inside_a_function():
    """Un mkdir différé dans une fonction est la forme attendue."""
    source = (
        "from pathlib import Path\n"
        "POOL = Path('/repos/pool')\n"
        "def save(name):\n"
        "    POOL.mkdir(parents=True, exist_ok=True)\n"
        "    (POOL / name).write_text('x')\n"
    )
    assert _module_level_fs_calls(ast.parse(source)) == []


# ── Contrepartie du garde-fou statique ───────────────────────────────────────
#
# Supprimer le mkdir d'import n'est correct que si l'écriture le recrée. Le
# test statique ci-dessus ne le prouve pas : il interdit le mkdir à l'import,
# il ne vérifie pas que le writer en fait un. Ces tests-ci pointent chaque
# répertoire sur un chemin ABSENT (deux niveaux non créés) puis appellent le
# writer, ce qui échouerait en FileNotFoundError sans le mkdir différé.


class TestWritersCreateTheirOwnDirectory:
    def test_audit_log_creates_audit_dir(self, tmp_path, monkeypatch):
        import services.audit as mod

        target = tmp_path / "absent" / "audit"
        monkeypatch.setattr(mod, "AUDIT_DIR", target)
        mod.log("UPLOAD", "alice", "SUCCESS", package="nmap")

        assert list(target.glob("*.jsonl"))

    def test_save_index_creates_parent_dir(self, tmp_path, monkeypatch):
        import services.indexer as mod

        target = tmp_path / "absent" / "manifests" / "index.json"
        monkeypatch.setattr(mod, "INDEX_PATH", target)
        mod._save_index({"version": "1.0", "packages": {}})

        assert target.exists()

    def test_create_pending_creates_pending_dir(self, tmp_path, monkeypatch):
        import services.pending_promotions as mod

        target = tmp_path / "absent" / "pending"
        monkeypatch.setattr(mod, "PENDING_DIR", target)
        record = mod.create_pending(
            name="nmap", version="7.94", from_dist="staging", to_dist="stable",
            requested_by="alice", policy_verdict={"allowed": True},
        )

        assert (target / f"{record['id']}.json").exists()

    def test_cve_cache_write_creates_security_dir(self, tmp_path, monkeypatch):
        """SECURITY_CACHE_DIR n'a pas de mkdir dédié : _save_json() est l'unique
        point d'écriture du module (refresh_kev + _save_epss_cache y passent) et
        crée lui-même path.parent."""
        import services.cve_enrichment as mod

        target = tmp_path / "absent" / "security" / "kev_cache.json"
        monkeypatch.setattr(mod, "KEV_CACHE_PATH", target)
        mod._save_json(mod.KEV_CACHE_PATH, {"cve_ids": ["CVE-2024-0001"]})

        assert target.exists()

    def test_save_component_sbom_creates_sbom_dir(self, tmp_path, monkeypatch):
        import services.component_sbom as mod

        target = tmp_path / "absent" / "sboms"
        monkeypatch.setattr(mod, "SBOM_DIR", target)
        mod.save_component_sbom("curl", "8.5.0-1", "amd64", {"components": []})

        assert mod.load_component_sbom("curl", "8.5.0-1", "amd64") == {"components": []}

    def test_update_pending_cannot_write_without_the_directory(self, tmp_path, monkeypatch):
        """update_pending() est le seul autre writer de PENDING_DIR et n'a pas
        de mkdir : il sort en None avant l'écriture si le fichier n'existe pas
        (donc si le répertoire n'existe pas). Invariant vérifié ici plutôt que
        supposé."""
        import services.pending_promotions as mod

        target = tmp_path / "absent" / "pending"
        monkeypatch.setattr(mod, "PENDING_DIR", target)

        assert mod.update_pending(str(uuid.uuid4()), status="approved") is None
        assert not target.exists()
