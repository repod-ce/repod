# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_import_group_path_traversal.py
Rôle   : le champ `group` de ImportRequest/BatchImportRequest
         (routers/import_router.py) n'était validé nulle part et finissait en
         composant de chemin dans services/importer_apt.py:_import_one_locked() :

             group_dir = IMPORTS_DIR / (group or pkg_name)
             group_dir.mkdir(parents=True, exist_ok=True)
             shutil.copy2(str(path), str(group_dir / path.name))

         Un compte de rôle `uploader` (le plus bas rôle disposant d'un droit
         d'écriture, typiquement un token de CI) pouvait donc poster
         {"package": "nginx", "distribution": "jammy",
          "group": "../../../tmp/pwn"} sur POST /import/fetch et faire créer une
         arborescence puis écrire le .deb hors de IMPORTS_DIR — partout où le
         process backend peut écrire, y compris les bind mounts en écriture
         /repos/dists, /repos/conf, /repos/db et /repos/gnupg. Une valeur
         absolue était pire : Path("/repos/imports") / "/tmp/x" vaut "/tmp/x",
         la base est purement écartée par pathlib.

         Ces tests verrouillent les deux gardes du correctif :
           - le garde faisant autorité dans _import_one_locked(), placé avant
             le téléchargement, qui couvre les trois appelants du sink
             (import_router, mirror_manager, upload) ;
           - le garde de frontière dans le routeur, qui renvoie un 400 avant
             l'ouverture du flux SSE plutôt qu'un 200 contenant une erreur.

         Le garde s'appuie sur services/path_safety.py:safe_path_join() et non
         sur une regex : ^[\\w.\\-+]+$, la forme qu'employait le endpoint frère
         DELETE /import/groups/{group_name} jusqu'à son propre correctif,
         accepte "." et ".." puisque le point est littéral dans la classe de
         caractères. Ce frère délègue désormais au même safe_path_join(), avec
         un refus supplémentaire de "." que l'opération de suppression impose
         (voir test_import_group_delete_traversal.py).

Dépend : pytest, unittest.mock.patch — aucun subprocess/réseau réel.
"""
import importlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Répertoires isolés positionnés AVANT tout import applicatif : les constantes
# de module (POOL_DIR, MANIFEST_DIR...) sont lues via os.getenv à l'import.
_TMP = tempfile.mkdtemp(prefix="repod_import_group_traversal_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", os.path.join(_TMP, "pool"))
os.environ.setdefault("IMPORTS_DIR", os.path.join(_TMP, "imports"))
os.environ.setdefault("INDEX_PATH", os.path.join(_TMP, "index.json"))
os.environ.setdefault("AUDIT_DIR", _TMP)
os.environ.setdefault("SECURITY_CACHE_DIR", os.path.join(_TMP, "security"))
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-import-group-traversal")


@pytest.fixture(autouse=True)
def _fresh_validator_module():
    """
    tests/test_format_router.py supprime services.validator de sys.modules sans
    le ré-importer, laissant sur le paquet `services` un attribut orphelin.
    patch("services.validator.X") résoudrait alors cet objet mort plutôt que
    celui que le `from services.validator import ...` local de
    _import_one_locked() importe réellement, désynchronisant silencieusement le
    mock du code testé. Un reload natif force la cohérence.
    """
    if "services.validator" in sys.modules:
        importlib.reload(sys.modules["services.validator"])
    else:
        import services.validator  # noqa: F401


def _fake_manifest(name="nginx", version="1.24.0-1"):
    return {
        "name": name,
        "version": version,
        "arch": "amd64",
        "integrity": {"sha256": "deadbeef"},
    }


def _validation_ok():
    v = MagicMock()
    v.passed = True
    v.cve_status = "approved"
    v.steps = []
    v.deps = []
    v.cve_results = []
    return v


# ══════════════════════════════════════════════════════════════════════════════
# 1. Garde faisant autorité — services/importer_apt.py:_import_one_locked()
# ══════════════════════════════════════════════════════════════════════════════

class TestImportOneGroupSink:
    """Le sink lui-même doit refuser tout `group` sortant de IMPORTS_DIR,
    quel que soit l'appelant."""

    def _run_import(self, tmp_path, group):
        """Exécute import_one() avec tout le pipeline mocké.
        Retourne (result, imports_dir, pool_dir, mock_download, mock_subproc).
        """
        import services.importer_apt as imp

        imports_dir = tmp_path / "imports"
        imports_dir.mkdir()
        pool_dir = tmp_path / "pool"
        pool_dir.mkdir()
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        deb_path = src_dir / "nginx_1.24.0-1_amd64.deb"
        deb_path.write_bytes(b"fake-deb")

        with patch("services.importer_apt.IMPORTS_DIR", imports_dir), \
             patch("services.importer_apt.POOL_DIR", pool_dir), \
             patch("services.importer_apt._download_deb",
                   return_value=(deb_path, "test-source", "deadbeef")) as mock_download, \
             patch("services.validator.run_validation_pipeline",
                   return_value=_validation_ok()), \
             patch("services.manifest.generate_manifest", return_value=_fake_manifest()), \
             patch("services.manifest.save_manifest"), \
             patch("services.component_sbom.save_component_sbom"), \
             patch("services.indexer.add_to_index"), \
             patch("services.audit.log"), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_subproc:

            result = imp.import_one(
                {"name": "nginx", "version": "1.24.0-1", "arch": "amd64"},
                "jammy", "uploader_test", group=group,
            )

        return result, imports_dir, pool_dir, mock_download, mock_subproc

    @pytest.mark.parametrize("group", [
        "../../evil",
        "../../../tmp/repod-evil",
        "..",
        "subdir/../../../evil",
    ])
    def test_traversal_relative_is_rejected(self, tmp_path, group):
        """Coeur du correctif : aucun `group` relatif ne doit sortir de
        IMPORTS_DIR. Le cas ".." est celui que la regex ^[\\w.\\-+]+$, employée
        ici puis dans le endpoint frère avant leurs correctifs respectifs,
        acceptait à tort."""
        result, imports_dir, pool_dir, mock_download, mock_subproc = \
            self._run_import(tmp_path, group)

        assert result["status"] == "error", \
            f"group={group!r} aurait dû être refusé, statut obtenu {result['status']!r}"
        assert "groupe" in result["message"], \
            f"le message doit désigner le nom de groupe, obtenu {result['message']!r}"

        # Le garde précède le téléchargement : ni réseau, ni ClamAV, ni Grype.
        mock_download.assert_not_called()
        mock_subproc.assert_not_called()

        # Rien n'a été écrit, ni hors de la base ni dans la base.
        assert list(imports_dir.iterdir()) == [], \
            "aucun répertoire de groupe ne doit être créé sur un rejet"
        assert list(pool_dir.iterdir()) == [], \
            "aucun .deb ne doit rester dans le pool sur un rejet"
        assert not (tmp_path / "evil").exists()
        assert not (tmp_path.parent / "evil").exists()

    def test_traversal_absolute_is_rejected(self, tmp_path):
        """Une valeur absolue écarte entièrement la base avec pathlib :
        Path("/repos/imports") / "/tmp/x" == Path("/tmp/x")."""
        victim = Path(tempfile.gettempdir()) / f"repod-evil-{os.getpid()}"
        assert not victim.exists(), "pré-condition : la cible ne doit pas déjà exister"

        result, imports_dir, pool_dir, mock_download, _ = \
            self._run_import(tmp_path, str(victim))

        assert result["status"] == "error"
        mock_download.assert_not_called()
        assert not victim.exists(), \
            f"{victim} a été créé — la base IMPORTS_DIR a été écartée"
        assert list(imports_dir.iterdir()) == []

    @pytest.mark.parametrize("group", [
        "mirror-ubuntu-jammy",        # valeur réelle de mirror_manager.py:269
        "g++",                        # valeurs réelles de upload.py:679
        "libssl1.1",
        "foo.bar-1+deb",
        "mon-groupe",
    ])
    def test_legitimate_group_still_imports(self, tmp_path, group):
        """Non-régression : safe_path_join n'impose aucune restriction de
        charset, il ne rejette que la sortie de la base. Les vraies valeurs des
        trois appelants doivent continuer de passer."""
        result, imports_dir, _, mock_download, _ = self._run_import(tmp_path, group)

        assert result["status"] == "added", \
            f"group={group!r} est légitime, statut obtenu {result['status']!r}"
        mock_download.assert_called_once()
        assert (imports_dir / group / "nginx_1.24.0-1_amd64.deb").exists(), \
            f"le .deb doit être copié dans {imports_dir / group}"

    def test_none_group_falls_back_to_package_name(self, tmp_path):
        """Le repli `group or pkg_name` est conservé à l'intérieur du garde."""
        result, imports_dir, _, _, _ = self._run_import(tmp_path, None)

        assert result["status"] == "added"
        assert (imports_dir / "nginx" / "nginx_1.24.0-1_amd64.deb").exists(), \
            "group=None doit toujours retomber sur le nom du paquet"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Garde de frontière — routers/import_router.py
# ══════════════════════════════════════════════════════════════════════════════

def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from slowapi.errors import RateLimitExceeded

    from auth.dependencies import get_uploader_user
    from limiter import limiter
    from routers.import_router import router as import_router
    from services.rate_limits import rate_limit_exceeded_handler

    app = FastAPI()
    # @limiter.limit() sur /fetch et /batch requiert app.state.limiter + le
    # handler d'exception slowapi associé.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    app.include_router(import_router)
    app.dependency_overrides[get_uploader_user] = lambda: "uploader_test"
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(db_test_engine):
    # Le limiter slowapi est un singleton de module : sans reset, les appels
    # des tests précédents (même IP "testclient") finissent par déclencher un
    # 429 sans rapport avec ce qui est testé ici.
    from limiter import limiter
    limiter.reset()
    return _client()


_BAD_GROUPS = ["../../../tmp/pwn", "..", "subdir/../../../pwn"]


class TestImportGroupBoundary:
    """Le routeur doit rejeter en 400 AVANT d'ouvrir le flux SSE : une
    HTTPException levée depuis le générateur de StreamingResponse n'atteindrait
    plus le client, le statut étant déjà parti."""

    @pytest.mark.parametrize("group", _BAD_GROUPS)
    def test_fetch_rejects_traversal_before_streaming(self, client, tmp_path, group):
        with patch("routers.import_router.IMPORTS_DIR", tmp_path), \
             patch("routers.import_router.import_package_stream") as mock_stream, \
             patch("routers.import_router.audit_log") as mock_audit:
            resp = client.post("/import/fetch", json={
                "package": "nginx", "distribution": "jammy", "group": group,
            })

        assert resp.status_code == 400, \
            f"group={group!r} doit être refusé en 400, obtenu {resp.status_code}"
        assert resp.json()["detail"] == "Nom de groupe invalide"
        mock_stream.assert_not_called(), \
            "le rejet doit précéder l'ouverture du flux SSE"
        mock_audit.assert_not_called(), \
            "un import refusé ne doit pas être journalisé comme démarré"

    @pytest.mark.parametrize("group", _BAD_GROUPS)
    def test_batch_rejects_traversal_before_streaming(self, client, tmp_path, group):
        with patch("routers.import_router.IMPORTS_DIR", tmp_path), \
             patch("routers.import_router.import_package_stream") as mock_stream:
            resp = client.post("/import/batch", json={
                "packages": ["nginx", "curl"], "distribution": "jammy", "group": group,
            })

        assert resp.status_code == 400, \
            f"group={group!r} doit être refusé en 400, obtenu {resp.status_code}"
        assert resp.json()["detail"] == "Nom de groupe invalide"
        mock_stream.assert_not_called()

    def test_fetch_absolute_group_rejected(self, client, tmp_path):
        with patch("routers.import_router.IMPORTS_DIR", tmp_path), \
             patch("routers.import_router.import_package_stream") as mock_stream:
            resp = client.post("/import/fetch", json={
                "package": "nginx", "group": "/tmp/repod-pwn",
            })

        assert resp.status_code == 400
        mock_stream.assert_not_called()

    def test_valid_group_is_forwarded(self, client, tmp_path):
        """Non-régression : un groupe légitime passe et arrive intact au
        service."""
        with patch("routers.import_router.IMPORTS_DIR", tmp_path), \
             patch("routers.import_router.import_package_stream",
                   side_effect=lambda *a, **k: iter(["data: info|ok\n\n"])) as mock_stream, \
             patch("routers.import_router.audit_log"):
            resp = client.post("/import/fetch", json={
                "package": "nginx", "distribution": "jammy", "group": "mon-groupe",
            })

        assert resp.status_code == 200, resp.text
        mock_stream.assert_called_once()
        assert mock_stream.call_args.kwargs["group"] == "mon-groupe"

    def test_absent_group_is_forwarded_as_none(self, client, tmp_path):
        """Non-régression : `group` omis reste None, le repli sur le nom du
        paquet est fait plus bas dans le service."""
        with patch("routers.import_router.IMPORTS_DIR", tmp_path), \
             patch("routers.import_router.import_package_stream",
                   side_effect=lambda *a, **k: iter(["data: info|ok\n\n"])) as mock_stream, \
             patch("routers.import_router.audit_log"):
            resp = client.post("/import/fetch", json={
                "package": "nginx", "distribution": "jammy",
            })

        assert resp.status_code == 200, resp.text
        assert mock_stream.call_args.kwargs["group"] is None
