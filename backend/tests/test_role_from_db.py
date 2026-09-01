# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_role_from_db.py
Rôle   : auth/dependencies.py:_parse_token() chargeait la ligne utilisateur puis
         la jetait ; elle ne servait que de test d'existence et d'activité. Le
         rôle utilisé par _require_role(), et donc par get_admin_user /
         get_maintainer_user / get_uploader_user / get_auditor_user, provenait
         du claim « role » du JWT, un instantané figé à l'émission du token.

         Conséquence : une rétrogradation via PATCH /auth/users/{username}
         renvoyait 200, modifiait la base et écrivait l'audit, sans aucun effet
         réel. La victime conservait ses droits jusqu'à expiration du token, et
         POST /auth/refresh (auth/router.py:227) recopiait le claim périmé dans
         un token neuf de 60 minutes. Le frontend appelant ce refresh toutes les
         45 minutes (AuthContext.js), la rétention était indéfinie et sans
         interaction. Seule la désactivation coupait réellement l'accès, parce
         que get_user() filtre active = true.

         Ces tests verrouillent le correctif : la table users est la seule
         source de vérité du rôle, la rétrogradation prend effet dès la requête
         suivante, et /auth/refresh ne peut plus reconduire un rôle périmé.

Dépend : pytest, PyJWT, fastapi.testclient (fixture autouse db_test_engine de
         conftest.py, SQLite in-memory).
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_role_from_db_test_")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("JWT_EXPIRE_MINUTES", "60")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("AUDIT_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import pytest
from sqlalchemy import text as _t

from auth.jwt import create_access_token, get_token_claims


@pytest.fixture(autouse=True)
def base_propre(db_test_engine):
    """Chaque test part d'une table users vide."""
    with db_test_engine.begin() as conn:
        conn.execute(_t("DELETE FROM users"))
    yield


@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from auth.router import router as auth_router

    app = FastAPI()
    app.include_router(auth_router)
    # Aucune des routes sollicitées ici (GET /auth/users, POST /auth/refresh)
    # ne porte de @limiter.limit ; inutile de câbler app.state.limiter.
    return TestClient(app, raise_server_exceptions=False)


def _entete(username: str, role: str) -> dict:
    """Forge un JWT valablement signé portant le rôle demandé.

    C'est ce qui permet de simuler un claim périmé : le token reste
    cryptographiquement valide, seul son claim « role » ment.
    """
    token = create_access_token({"sub": username, "role": role, "full_name": ""})
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# Le rôle des décisions d'autorisation provient de la base
# ══════════════════════════════════════════════════════════════════════════════

class TestRoleDepuisLaBase:
    """Sonde d'accès admin : GET /auth/users (Depends(get_admin_user))."""

    def test_retrogradation_coupe_acces_admin(self, client):
        """Cœur du correctif : rétrograder doit prendre effet immédiatement,
        sans attendre l'expiration du token."""
        from auth.users import create_user, update_user

        create_user("alice", "AlicePass1!", role="admin")
        entete = _entete("alice", "admin")

        assert client.get("/auth/users", headers=entete).status_code == 200, \
            "pré-condition : l'admin doit avoir accès avant la rétrogradation"

        update_user("alice", role="reader")

        resp = client.get("/auth/users", headers=entete)
        assert resp.status_code == 403, (
            "le token porte encore le claim « admin » : l'accès doit être refusé "
            f"sur la foi du rôle en base, obtenu {resp.status_code}"
        )

    def test_refresh_nemet_pas_le_role_perime(self, client):
        """POST /auth/refresh recopiait le claim périmé dans un token neuf, ce
        qui reconduisait le rôle indéfiniment toutes les 45 minutes."""
        from auth.users import create_user, update_user

        create_user("bob", "BobPass1!", role="admin")
        update_user("bob", role="reader")

        resp = client.post("/auth/refresh", headers=_entete("bob", "admin"))
        assert resp.status_code == 200, resp.text

        nouveau = resp.json()["access_token"]
        assert get_token_claims(nouveau)["role"] == "reader", (
            "POST /auth/refresh a reconduit un rôle périmé issu du claim JWT "
            "au lieu du rôle en base"
        )

        # Et le token réémis ne doit pas non plus ouvrir les routes admin.
        suite = client.get("/auth/users", headers={"Authorization": f"Bearer {nouveau}"})
        assert suite.status_code == 403, \
            "le token réémis ne doit pas donner accès aux routes admin"

    def test_promotion_prise_en_compte_immediatement(self, client):
        """Effet de bord symétrique et assumé : une promotion s'applique aussi
        sans relogin, ce qui rend effectives les promotions par groupe
        (services/groups.py écrit UPDATE users SET role en direct)."""
        from auth.users import create_user, update_user

        create_user("carol", "CarolPass1!", role="reader")
        entete = _entete("carol", "reader")

        assert client.get("/auth/users", headers=entete).status_code == 403, \
            "pré-condition : un reader ne doit pas accéder aux routes admin"

        update_user("carol", role="admin")

        resp = client.get("/auth/users", headers=entete)
        assert resp.status_code == 200, (
            "la promotion doit s'appliquer sans attendre un nouveau login, "
            f"obtenu {resp.status_code}"
        )

    def test_claim_falsifie_ne_donne_pas_admin(self, client):
        """Expression la plus directe de l'invariant : le claim « role » n'est
        plus qu'un indice d'affichage, il ne décide plus de rien."""
        from auth.users import create_user

        create_user("mallory", "MalloryPass1!", role="reader")

        resp = client.get("/auth/users", headers=_entete("mallory", "admin"))
        assert resp.status_code == 403, (
            "un claim « admin » sur un compte « reader » en base ne doit ouvrir "
            f"aucune route admin, obtenu {resp.status_code}"
        )

    def test_desactivation_donne_401(self, client):
        """Non-régression : la désactivation était déjà le seul chemin qui
        coupait l'accès, via le filtre active = true de get_user()."""
        from auth.users import create_user, update_user

        create_user("dave", "DavePass1!", role="admin")
        entete = _entete("dave", "admin")
        assert client.get("/auth/users", headers=entete).status_code == 200

        update_user("dave", active=False)

        resp = client.get("/auth/users", headers=entete)
        assert resp.status_code == 401, (
            "un compte désactivé doit être rejeté à l'authentification, "
            f"obtenu {resp.status_code}"
        )

    def test_role_inchange_conserve_acces(self, client):
        """Non-régression du cas ultra-majoritaire : rôle du claim identique au
        rôle en base, on réécrit la même valeur."""
        from auth.users import create_user, update_user

        create_user("erin", "ErinPass1!", role="admin")
        entete = _entete("erin", "admin")

        assert client.get("/auth/users", headers=entete).status_code == 200

        update_user("erin", full_name="Erin Admin")

        assert client.get("/auth/users", headers=entete).status_code == 200, \
            "une modification sans rapport avec le rôle ne doit rien changer"


class TestFormeDuDictDeClaims:
    """Garde-fou de refactor."""

    def test_parse_token_conserve_jti_et_claims(self):
        """_parse_token doit continuer de retourner les claims du token, avec le
        seul « role » écrasé. Remplacer ce dict par la ligne users perdrait
        « jti », dont POST /auth/logout a besoin pour révoquer le token."""
        from auth.dependencies import _parse_token
        from auth.users import create_user

        create_user("nina", "NinaPass1!", role="reader")
        token = create_access_token({"sub": "nina", "role": "reader", "full_name": "Nina"})

        data = _parse_token(token)

        assert {"username", "role", "full_name", "jti"} <= set(data), (
            "_parse_token doit exposer username, role, full_name et jti, "
            f"obtenu {sorted(data)}"
        )
        assert data["jti"], "le jti du token doit être préservé (requis par /auth/logout)"
        assert data["username"] == "nina"
        assert data["role"] == "reader"
