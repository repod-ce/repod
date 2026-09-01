# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_packages_install_authz.py
Rôle   : POST /api/v1/packages/install/ était atteignable par le rôle reader.

         L'endpoint n'était gardé que par Depends(get_current_user), donc par
         n'importe quel compte authentifié. Il atteignait
         services/download.py:download_package(), qui ouvre une session SSH
         paramiko et lance « bash ~/repodata/download-package-dep.sh <nom> » sur
         la machine gérée. Ce script fait un « sudo apt-get download » puis
         copie le résultat dans le pool servi et relance l'indexation : l'effet
         n'est pas un simple téléchargement, un paquet amont et toute sa
         fermeture de dépendances entraient dans le dépôt auquel tous les
         clients APT font confiance. auth/users.py documente le compte reader
         comme « compte de service pour les machines clientes APT », donc
         distribué à chaque machine.

         Ce n'était pas une injection de commande : _SAFE_PKG_RE
         (download.py:28) impose une initiale alphanumérique, ce qui bloque les
         métacaractères shell comme l'injection d'argument en « - ». Le défaut
         était purement une autorisation manquante.

         L'endpoint était un doublon hérité de POST /artifacts/{name}/install
         (routers/artifacts.py:224), qui atteint le même sink mais exige
         get_uploader_user, refuse en 409 si des dépendances manquent et écrit
         une entrée d'audit. Le doublon n'avait aucun des trois et n'était
         appelé par aucune page du frontend. Le correctif le supprime.

Dépend : pytest, fastapi.testclient
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")

# ── Imports normaux ────────────────────────────────────────────────────────────
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_ROUTERS = Path(__file__).parent.parent / "routers"


@pytest.fixture
def client() -> TestClient:
    from routers.packages import router as packages_router

    app = FastAPI()
    app.include_router(packages_router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


def _bearer(username: str, role: str) -> dict:
    from auth.jwt import create_access_token

    return {"Authorization": f"Bearer {create_access_token({'sub': username, 'role': role})}"}


class TestEndpointInstallSupprime:
    """POST /packages/install/ ne doit plus exister."""

    def test_sans_authentification_renvoie_404(self, client):
        """
        404 et non 401 : c'est la différence entre une route supprimée et une
        route simplement gardée. Un 401 signifierait que le doublon est
        toujours monté.
        """
        reponse = client.post("/api/v1/packages/install/", json={"name": "curl"})
        assert reponse.status_code == 404, (
            f"La route doit avoir disparu, reçu {reponse.status_code}"
        )

    def test_avec_un_jeton_reader_renvoie_404(self, client):
        reponse = client.post(
            "/api/v1/packages/install/",
            json={"name": "curl"},
            headers=_bearer("lecteur", "reader"),
        )
        assert reponse.status_code == 404

    def test_avec_un_jeton_admin_renvoie_404(self, client):
        """
        Supprimé pour tout le monde, pas restreint : le chemin légitime est
        POST /artifacts/{name}/install, qui porte le gate de dépendances et
        l'audit.
        """
        reponse = client.post(
            "/api/v1/packages/install/",
            json={"name": "curl"},
            headers=_bearer("patron", "admin"),
        )
        assert reponse.status_code == 404


class TestSinkDownloadPackage:
    """Garde de refactor : un seul routeur atteint download_package()."""

    def test_seul_artifacts_appelle_download_package(self):
        appelants = sorted(
            chemin.name
            for chemin in _ROUTERS.glob("*.py")
            if "download_package" in chemin.read_text(encoding="utf-8")
        )
        assert appelants == ["artifacts.py"], (
            "download_package() ouvre une session SSH et injecte un paquet dans le "
            f"pool servi. Un seul point d'entrée gardé est admis, trouvé : {appelants}"
        )

    def test_artifacts_exige_le_role_uploader(self):
        source = (_ROUTERS / "artifacts.py").read_text(encoding="utf-8")
        bloc = source[source.index('@router.post("/{name}/install")'):]
        entete = bloc[: bloc.index("):")]
        assert "get_uploader_user" in entete, (
            "Le seul appelant restant doit rester gardé par get_uploader_user"
        )


class TestNonRegressionListePaquets:
    """GET /packages/ n'est pas touché par la suppression."""

    def test_liste_exige_une_authentification(self, client):
        assert client.get("/api/v1/packages/").status_code == 401

    def test_liste_toujours_montee_pour_un_reader(self, client):
        reponse = client.get("/api/v1/packages/", headers=_bearer("lecteur", "reader"))
        assert reponse.status_code != 404, "GET /packages/ doit rester monté"
