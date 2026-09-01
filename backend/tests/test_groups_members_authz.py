# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_groups_members_authz.py
Rôle   : GET /groups/{id}/members livrait l'annuaire du personnel à n'importe
         quel compte authentifié.

         La route n'était gardée que par Depends(get_current_user), alors que
         services/groups.py:get_group_members() renvoie
         {username, added_at, added_by, full_name, email, role} sans filtrage ni
         response_model. Le rôle reader, que auth/users.py documente comme
         compte de service distribué aux machines clientes APT, obtenait donc
         nom complet, adresse e-mail et rôle de chaque membre, dont la liste des
         comptes admin : une cible toute faite pour du hameçonnage ou de la
         pulvérisation de mots de passe. GET /groups fournissant les
         identifiants de groupe, leur caractère non devinable ne protégeait rien.

         Le correctif aligne la lecture sur l'écriture : POST et
         DELETE /members étaient déjà admin, l'annuaire canonique
         GET /auth/users l'est aussi, et le frontend déclare nav_users: [admin].

         GET /groups reste délibérément ouvert aux authentifiés : il ne renvoie
         que des métadonnées de groupe, sans donnée de contact, et alimente les
         listes d'assignation de SecurityPage, dont PATCH /decisions/{id}/assign
         n'exige que get_maintainer_user.

Dépend : pytest, conftest.db_test_engine (SQLite in-memory), fastapi.testclient
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")

# ── Imports normaux ────────────────────────────────────────────────────────────
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from auth.jwt import create_access_token
from auth.roles import seed_builtin_roles
from auth.users import create_user
from services.groups import add_member, create_group

_ROLES_NON_ADMIN = ["reader", "uploader", "maintainer", "auditor"]


@pytest.fixture(autouse=True)
def base_propre(db_test_engine):
    with db_test_engine.begin() as conn:
        conn.execute(text("DELETE FROM group_members"))
        conn.execute(text("DELETE FROM groups"))
        conn.execute(text("DELETE FROM users"))
    seed_builtin_roles()
    yield


@pytest.fixture
def client() -> TestClient:
    from routers.groups_router import router as groups_router

    app = FastAPI()
    app.include_router(groups_router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def groupe_peuple() -> str:
    """Un groupe contenant un membre dont le nom et l'e-mail sont renseignés."""
    create_user("dupont", "Passw0rd!23", "admin",
                full_name="Alice Dupont", email="alice.dupont@interne.example")
    groupe = create_group("RSSI", "Équipe sécurité", "red", "dupont")
    add_member(groupe["id"], "dupont", "dupont")
    return groupe["id"]


def _bearer(username: str, role: str) -> dict:
    """
    Crée le compte en base puis signe un jeton.

    Le compte doit exister : depuis le correctif de la Vuln 3, _parse_token
    relit le rôle dans la table users et ignore le claim du jeton.
    """
    create_user(username, "Passw0rd!23", role)
    jeton = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {jeton}"}


class TestListeMembresReserveeAdmin:
    """GET /groups/{id}/members — l'annuaire ne sort plus du cercle admin."""

    @pytest.mark.parametrize("role", _ROLES_NON_ADMIN)
    def test_role_non_admin_refuse(self, client, groupe_peuple, role):
        reponse = client.get(
            f"/api/v1/groups/{groupe_peuple}/members",
            headers=_bearer(f"compte_{role}", role),
        )
        assert reponse.status_code == 403, (
            f"Le rôle {role} ne doit pas lire l'annuaire, reçu {reponse.status_code}"
        )

    @pytest.mark.parametrize("role", _ROLES_NON_ADMIN)
    def test_aucune_donnee_personnelle_dans_le_refus(self, client, groupe_peuple, role):
        """C'est la fuite elle-même que ce test verrouille, pas seulement le code."""
        reponse = client.get(
            f"/api/v1/groups/{groupe_peuple}/members",
            headers=_bearer(f"fuite_{role}", role),
        )
        assert "alice.dupont@interne.example" not in reponse.text
        assert "Alice Dupont" not in reponse.text

    def test_sans_authentification_refuse(self, client, groupe_peuple):
        reponse = client.get(f"/api/v1/groups/{groupe_peuple}/members")
        assert reponse.status_code == 401

    def test_groupe_inexistant_refuse_avant_de_repondre_404(self, client):
        """
        La dépendance s'exécute avant le corps : un non-admin reçoit 403 même sur
        un identifiant inconnu, la route n'est donc pas un oracle d'existence.
        """
        reponse = client.get(
            "/api/v1/groups/00000000-0000-0000-0000-000000000000/members",
            headers=_bearer("curieux", "maintainer"),
        )
        assert reponse.status_code == 403


class TestAdminConserveLAnnuaire:
    """Le correctif ne doit pas retirer la fonctionnalité à qui y a droit."""

    def test_admin_recoit_les_membres_complets(self, client, groupe_peuple):
        reponse = client.get(
            f"/api/v1/groups/{groupe_peuple}/members",
            headers=_bearer("patronne", "admin"),
        )
        assert reponse.status_code == 200
        membres = reponse.json()["members"]
        assert [m["username"] for m in membres] == ["dupont"]
        # Ces champs sont précisément ce qui justifie la restriction : ils
        # restent servis à l'admin, c'est leur diffusion qui était le défaut.
        assert membres[0]["email"] == "alice.dupont@interne.example"
        assert membres[0]["full_name"] == "Alice Dupont"


class TestNonRegressionRoutesOuvertes:
    """GET /groups et /groups/me restent ouverts, choix délibéré et documenté."""

    def test_liste_des_groupes_lisible_par_un_reader(self, client, groupe_peuple):
        reponse = client.get("/api/v1/groups", headers=_bearer("lecteur", "reader"))
        assert reponse.status_code == 200
        assert [g["name"] for g in reponse.json()["groups"]] == ["RSSI"]

    def test_liste_des_groupes_sans_donnee_de_contact(self, client, groupe_peuple):
        """
        Ce qui rend acceptable de laisser cette route ouverte : sa charge utile
        ne contient aucune donnée personnelle, seulement des métadonnées.
        """
        reponse = client.get("/api/v1/groups", headers=_bearer("lecteur2", "reader"))
        assert "alice.dupont@interne.example" not in reponse.text
        assert "Alice Dupont" not in reponse.text

    def test_mes_groupes_lisibles_par_un_reader(self, client):
        reponse = client.get("/api/v1/groups/me", headers=_bearer("lecteur3", "reader"))
        assert reponse.status_code == 200
