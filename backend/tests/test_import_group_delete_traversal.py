# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_import_group_delete_traversal.py
Rôle   : DELETE /import/groups/{group_name} détruisait le dépôt avec « .. ».

         Le nom était validé par re.match(r'^[\\w.\\-+]+$', group_name), dont la
         classe de caractères contient un point littéral : « .. » satisfait donc
         entièrement ce motif ancré. IMPORTS_DIR / ".." résout vers /repos, et le
         seul contrôle restant était exists(), vrai pour /repos/imports/.. — pas
         de is_dir(), pas de confinement. shutil.rmtree effaçait alors le contenu
         du dépôt dans l'ordre de readdir, potentiellement /repos/gnupg (clé de
         signature privée), /repos/pool, /repos/db ou /repos/audit, jusqu'à
         buter sur une frontière de bind mount.

         La réfutation « le serveur normalise les segments de points » a été
         testée et infirmée : contre uvicorn 0.46.0 et starlette 1.6.0, des
         sockets brutes livrent group_name == ".." pour /.., /%2E%2E et /%2e%2e,
         on_url ne faisant qu'un unquote(). nginx relaie tel quel, son proxy_pass
         ne portant pas de composant d'URI.

         Ces tests appellent la fonction de route directement, sans passer par
         httpx : le client HTTP normalise « .. » côté client, exactement comme
         curl sans --path-as-is, et masquerait donc la vulnérabilité. C'est le
         garde applicatif qui est vérifié, pas le comportement du client.

         Le correctif remplace la regex par services/path_safety.py:
         safe_path_join(), plus un refus explicite du chemin qui résout vers
         IMPORTS_DIR lui-même — « . » ne sort pas de la base mais effacerait tous
         les groupes d'un coup — et un is_dir() à la place du exists().

Dépend : pytest, unittest.mock.patch — aucun accès réseau.
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_group_delete_traversal_")
os.environ.setdefault("IMPORTS_DIR", os.path.join(_TMP, "imports"))
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", os.path.join(_TMP, "pool"))
os.environ.setdefault("AUDIT_DIR", _TMP)
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-group-delete-traversal")

# ── Imports normaux ────────────────────────────────────────────────────────────
from unittest.mock import patch

import pytest
from fastapi import HTTPException

# Noms qui sortent de IMPORTS_DIR ou le désignent lui-même. « .. » et « . » sont
# précisément ceux que la regex ^[\w.\-+]+$ acceptait.
_NOMS_REFUSES = ["..", ".", "../..", "subdir/../..", "/etc", "../gnupg"]


@pytest.fixture
def arborescence(tmp_path):
    """
    Reproduit la disposition réelle : IMPORTS_DIR est un sous-répertoire de la
    racine du dépôt, à côté des répertoires que « .. » viserait.
    """
    repos = tmp_path / "repos"
    imports = repos / "imports"
    (imports / "groupe_a").mkdir(parents=True)
    (imports / "groupe_a" / "nginx_1.24.0-1_amd64.deb").write_bytes(b"fake-deb")
    (repos / "gnupg").mkdir()
    (repos / "gnupg" / "secring.gpg").write_bytes(b"cle-privee-de-signature")
    (repos / "pool").mkdir()
    (repos / "pool" / "curl_8.5.0-2_amd64.deb").write_bytes(b"fake-deb")
    return repos, imports


def _supprimer(imports_dir, group_name: str):
    """
    Appelle la fonction de route directement, avec la dépendance d'authentification
    déjà satisfaite : c'est le garde de chemin qui est testé, pas le RBAC, la
    route étant admin depuis toujours.
    """
    from routers.import_router import delete_import_group

    with patch("routers.import_router.IMPORTS_DIR", imports_dir), \
         patch("routers.import_router.audit_log") as mock_audit:
        resultat = delete_import_group(group_name=group_name, current_user="admin_test")
    return resultat, mock_audit


class TestNomsSortantDeImportsDir:
    """Coeur du correctif : aucun nom ne doit désigner un chemin hors du groupe."""

    @pytest.mark.parametrize("nom", _NOMS_REFUSES)
    def test_refus_en_400(self, arborescence, nom):
        _repos, imports = arborescence
        with pytest.raises(HTTPException) as exc:
            _supprimer(imports, nom)
        assert exc.value.status_code == 400, (
            f"« {nom} » doit être refusé en 400, reçu {exc.value.status_code}"
        )

    @pytest.mark.parametrize("nom", _NOMS_REFUSES)
    def test_rien_n_est_detruit(self, arborescence, nom):
        """
        C'est la destruction elle-même qui est verrouillée, pas le code de
        statut : avant correctif, « .. » passait la regex puis le exists(), et
        rmtree effaçait le contenu de /repos.
        """
        repos, imports = arborescence
        with pytest.raises(HTTPException):
            _supprimer(imports, nom)

        assert (repos / "gnupg" / "secring.gpg").exists(), \
            "La clé de signature privée a été détruite"
        assert (repos / "pool" / "curl_8.5.0-2_amd64.deb").exists(), \
            "Le pool a été détruit"
        assert (imports / "groupe_a" / "nginx_1.24.0-1_amd64.deb").exists(), \
            "Le groupe d'import légitime a été détruit"

    @pytest.mark.parametrize("nom", _NOMS_REFUSES)
    def test_aucune_entree_d_audit_sur_refus(self, arborescence, nom):
        """Un refus n'est pas une suppression : rien ne doit entrer dans l'audit."""
        from routers.import_router import delete_import_group

        _repos, imports = arborescence
        with patch("routers.import_router.IMPORTS_DIR", imports), \
             patch("routers.import_router.audit_log") as mock_audit:
            with pytest.raises(HTTPException):
                delete_import_group(group_name=nom, current_user="admin_test")
        mock_audit.assert_not_called()


class TestSuppressionLegitime:
    """Le correctif ne doit pas retirer la fonctionnalité."""

    def test_groupe_normal_est_supprime(self, arborescence):
        repos, imports = arborescence
        resultat, mock_audit = _supprimer(imports, "groupe_a")

        assert resultat == {"deleted": "groupe_a"}
        assert not (imports / "groupe_a").exists()
        assert (repos / "gnupg" / "secring.gpg").exists()
        mock_audit.assert_called_once()

    @pytest.mark.parametrize("nom", ["g++", "libssl1.1", "foo.bar-1+deb", "mon_groupe"])
    def test_noms_debian_realistes_acceptes(self, arborescence, nom):
        """
        Ces noms sont la raison pour laquelle une regex ne convient pas : toute
        classe assez large pour les accepter laisse passer les segments de points.
        """
        _repos, imports = arborescence
        (imports / nom).mkdir()
        resultat, _mock_audit = _supprimer(imports, nom)
        assert resultat == {"deleted": nom}
        assert not (imports / nom).exists()

    def test_groupe_inexistant_renvoie_404(self, arborescence):
        _repos, imports = arborescence
        with pytest.raises(HTTPException) as exc:
            _supprimer(imports, "jamais_importe")
        assert exc.value.status_code == 404

    def test_fichier_simple_renvoie_404_et_survit(self, arborescence):
        """
        exists() était vrai pour un fichier, et rmtree levait alors une
        NotADirectoryError remontée en 500. is_dir() donne un 404 honnête.
        """
        _repos, imports = arborescence
        fichier = imports / "pas_un_groupe"
        fichier.write_bytes(b"contenu")

        with pytest.raises(HTTPException) as exc:
            _supprimer(imports, "pas_un_groupe")
        assert exc.value.status_code == 404
        assert fichier.exists()
