# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_metrics_public_exposure.py
Rôle   : GET /metrics exposait des données nominatives à un anonyme.

         Deux défauts se combinaient. D'une part
         routers/metrics_router.py:_require_metrics_auth() était un « if » sans
         « else » : quand METRICS_TOKEN n'est pas défini — le défaut livré — la
         fonction ne vérifiait rien. D'autre part
         middleware/metrics_middleware.py posait le chemin brut
         (request.url.path) en label Prometheus, si bien que le registre
         contenait « /api/v1/auth/users/alice »,
         « /api/v1/artifacts/nginx/versions/1.24.0-1/download » ou
         « /api/v1/security/packages/openssl/3.0.14/cve ». Un anonyme
         récupérait ainsi la liste des comptes touchés par une opération
         d'administration et l'inventaire des paquets hébergés, /metrics étant
         proxyé publiquement par défaut et le port backend écoutant sur
         0.0.0.0.

         Le correctif anonymise les labels — c'est lui qui retire la
         vulnérabilité, aucune donnée nominative n'existe plus dans le registre
         — et complète l'échelle de créance : quand METRICS_TOKEN est défini, un
         JWT de rôle auditeur devient une créance alternative acceptée. L'accès
         anonyme reste le repli documenté quand aucun jeton n'est configuré.

Dépend : pytest, PyJWT, fastapi.testclient (fixture autouse db_test_engine de
         conftest.py, SQLite in-memory).
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_metrics_expo_test_")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("JWT_EXPIRE_MINUTES", "60")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("AUDIT_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text as _t

from auth.jwt import create_access_token, create_mfa_token, get_token_claims

_JETON = "jeton-de-scrape-pour-les-tests"

# Valeur écrite en dur, jamais importée du middleware : elle fait partie du
# contrat exposé à Prometheus, c'est cela que le test verrouille.
_PATH_INCONNU = "__unmatched__"


def _charger_routeur():
    """
    Charge une instance neuve de routers/metrics_router.py, relisant METRICS_TOKEN.

    `_METRICS_TOKEN` est une constante de module lue à l'import, il faut donc
    ré-exécuter le module pour tester les deux modes. spec_from_file_location
    contourne routers/__init__.py, qui importe upload.py puis services.indexer
    et tente de créer /repos, impossible hors conteneur.

    services.metrics n'est PAS rechargé au passage : ses imports se résolvent
    normalement via sys.modules, donc REGISTRY reste l'objet unique de la
    session. Un importlib.reload(services.metrics) dupliquerait les collecteurs.
    """
    chemin = Path(__file__).parent.parent / "routers" / "metrics_router.py"
    spec = importlib.util.spec_from_file_location(f"metrics_router_{uuid4().hex}", chemin)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _client(mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(mod.router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def routeur_avec_jeton(monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", _JETON)
    return _charger_routeur()


@pytest.fixture
def routeur_sans_jeton(monkeypatch):
    # monkeypatch restaure l'environnement en fin de test, ce qui protège
    # test_metrics.py d'une fuite de METRICS_TOKEN quel que soit l'ordre de
    # collecte.
    monkeypatch.delenv("METRICS_TOKEN", raising=False)
    return _charger_routeur()


@pytest.fixture
def base_propre(db_test_engine):
    with db_test_engine.begin() as conn:
        conn.execute(_t("DELETE FROM users"))
    yield db_test_engine


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# 1. METRICS_TOKEN configuré — non-régression du mode strict
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricsJetonConfigure:

    def test_bon_jeton_accepte(self, routeur_avec_jeton):
        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(_JETON))
        assert resp.status_code == 200, resp.text
        assert "repod_" in resp.text

    def test_mauvais_jeton_refuse(self, routeur_avec_jeton):
        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer("mauvais"))
        assert resp.status_code == 403, resp.text
        assert "repod_" not in resp.text, \
            "aucune métrique ne doit fuiter dans une réponse de refus"

    def test_sans_en_tete_401(self, routeur_avec_jeton):
        resp = _client(routeur_avec_jeton).get("/metrics")
        assert resp.status_code == 401, resp.text
        assert "bearer" in resp.headers.get("www-authenticate", "").lower()
        assert "repod_" not in resp.text

    def test_en_tete_basic_401(self, routeur_avec_jeton):
        resp = _client(routeur_avec_jeton).get(
            "/metrics", headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        assert resp.status_code == 401, resp.text
        assert "repod_" not in resp.text


# ══════════════════════════════════════════════════════════════════════════════
# 2. JWT auditeur comme créance alternative
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricsJwtAuditeur:
    """Quand METRICS_TOKEN est défini, un humain doit pouvoir consulter
    /metrics avec son JWT plutôt qu'avec le jeton de scrape partagé."""

    @pytest.mark.parametrize("role", ["auditor", "admin", "maintainer"])
    def test_role_d_audit_accepte(self, routeur_avec_jeton, base_propre, role):
        from auth.users import create_user

        create_user("audrey", "AudreyPass1!", role=role)
        token = create_access_token({"sub": "audrey", "role": role})

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 200, (
            f"un JWT de rôle {role} doit être accepté, obtenu {resp.status_code}"
        )
        assert "repod_" in resp.text

    @pytest.mark.parametrize("role", ["reader", "uploader"])
    def test_role_sans_audit_refuse(self, routeur_avec_jeton, base_propre, role):
        from auth.users import create_user

        create_user("bob", "BobPass1!", role=role)
        token = create_access_token({"sub": "bob", "role": role})

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403, (
            f"un JWT de rôle {role} ne doit pas ouvrir /metrics, "
            f"obtenu {resp.status_code}"
        )
        assert "repod_" not in resp.text

    def test_role_falsifie_dans_le_claim_refuse(self, routeur_avec_jeton, base_propre):
        """Le rôle est relu en base, jamais pris dans le claim du JWT."""
        from auth.users import create_user

        create_user("mallory", "MalloryPass1!", role="reader")
        token = create_access_token({"sub": "mallory", "role": "admin"})

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403, (
            "un claim « admin » sur un compte « reader » en base ne doit rien ouvrir"
        )
        assert "repod_" not in resp.text

    def test_utilisateur_inexistant_refuse(self, routeur_avec_jeton, base_propre):
        token = create_access_token({"sub": "fantome", "role": "admin"})
        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403

    def test_utilisateur_desactive_refuse(self, routeur_avec_jeton, base_propre):
        from auth.users import create_user, update_user

        create_user("dave", "DavePass1!", role="auditor")
        token = create_access_token({"sub": "dave", "role": "auditor"})
        update_user("dave", active=False)

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403, \
            "un compte désactivé ne doit plus ouvrir /metrics"

    def test_jwt_revoque_refuse(self, routeur_avec_jeton, base_propre):
        from auth.token_revocation import revoke_jti
        from auth.users import create_user

        create_user("erin", "ErinPass1!", role="auditor")
        token = create_access_token({"sub": "erin", "role": "auditor"})
        jti = get_token_claims(token)["jti"]
        revoke_jti(jti, "erin", datetime.now(timezone.utc) + timedelta(hours=1))

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403, \
            "un JWT révoqué via /auth/logout ne doit plus ouvrir /metrics"

    def test_token_mfa_intermediaire_refuse(self, routeur_avec_jeton, base_propre):
        """Le token de l'étape 1 du login MFA (scope=mfa_required) n'est pas un
        access_token : decode_token() le rejette."""
        from auth.users import create_user

        create_user("nina", "NinaPass1!", role="auditor")
        token = create_mfa_token("nina", "auditor")

        resp = _client(routeur_avec_jeton).get("/metrics", headers=_bearer(token))
        assert resp.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 3. METRICS_TOKEN non configuré — repli anonyme documenté
# ══════════════════════════════════════════════════════════════════════════════

class TestMetricsSansJeton:
    """README.md et backend.env.example documentent l'accès anonyme comme le
    comportement par défaut. Il est conservé : c'est l'anonymisation des labels
    qui retire la vulnérabilité, pas la fermeture de l'endpoint."""

    def test_acces_anonyme_autorise(self, routeur_sans_jeton):
        resp = _client(routeur_sans_jeton).get("/metrics")
        assert resp.status_code == 200, resp.text
        assert "repod_" in resp.text

    def test_bearer_quelconque_toujours_autorise(self, routeur_sans_jeton):
        """Un Prometheus configuré avec un bearer_token face à un backend sans
        METRICS_TOKEN ne doit pas se mettre à échouer."""
        resp = _client(routeur_sans_jeton).get("/metrics", headers=_bearer("peu-importe"))
        assert resp.status_code == 200, resp.text


# ══════════════════════════════════════════════════════════════════════════════
# 4. Anonymisation du label path — le cœur du correctif
# ══════════════════════════════════════════════════════════════════════════════

def _app_instrumentee():
    from fastapi import FastAPI

    from middleware.metrics_middleware import MetricsMiddleware

    app = FastAPI()

    @app.get("/api/v1/auth/users/{username}")
    def _lire_utilisateur(username: str):
        return {"username": username}

    @app.get("/sonde-fixe")
    def _sonde():
        return {"ok": True}

    app.add_middleware(MetricsMiddleware)
    return app


def _valeur(nom: str, labels: dict) -> float:
    from services.metrics import REGISTRY

    return REGISTRY.get_sample_value(nom, labels) or 0.0


def _expose() -> str:
    from prometheus_client import generate_latest

    from services.metrics import REGISTRY

    return generate_latest(REGISTRY).decode()


class TestAnonymisationDuLabelPath:
    """Le registre Prometheus est cumulatif sur toute la session pytest : toutes
    les assertions numériques comparent des deltas, jamais des valeurs
    absolues."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        return TestClient(_app_instrumentee(), raise_server_exceptions=False)

    def test_le_gabarit_remplace_le_segment_variable(self, client):
        labels = {"method": "GET", "path": "/api/v1/auth/users/{username}",
                  "status_code": "200"}
        avant = _valeur("repod_http_requests_total", labels)

        client.get(f"/api/v1/auth/users/utilisateur-{uuid4().hex}")

        apres = _valeur("repod_http_requests_total", labels)
        assert apres == avant + 1, (
            "la requête doit être comptée sous le gabarit de route, "
            f"compteur passé de {avant} à {apres}"
        )

    def test_aucune_serie_ne_porte_le_nom_d_utilisateur(self, client):
        nom = f"utilisateur-{uuid4().hex}"

        client.get(f"/api/v1/auth/users/{nom}")

        assert nom not in _expose(), (
            f"le nom d'utilisateur {nom} ne doit jamais apparaître dans le "
            "registre Prometheus, exposé par GET /metrics"
        )

    def test_deux_valeurs_alimentent_la_meme_serie(self, client):
        """Cardinalité bornée : le nombre de séries ne dépend plus des valeurs
        envoyées par le client."""
        labels = {"method": "GET", "path": "/api/v1/auth/users/{username}",
                  "status_code": "200"}
        avant = _valeur("repod_http_requests_total", labels)

        client.get(f"/api/v1/auth/users/premier-{uuid4().hex}")
        client.get(f"/api/v1/auth/users/second-{uuid4().hex}")

        apres = _valeur("repod_http_requests_total", labels)
        assert apres == avant + 2, (
            f"les deux requêtes doivent alimenter la même série, obtenu {apres} "
            f"au lieu de {avant + 2}"
        )

    def test_404_se_replie_sur_la_constante(self, client):
        """Cas décisif : les 404 sont entièrement pilotées par le client. Un
        repli sur le chemin demandé réintroduirait la fuite et la cardinalité
        non bornée."""
        marqueur = uuid4().hex
        labels = {"method": "GET", "path": _PATH_INCONNU, "status_code": "404"}
        avant = _valeur("repod_http_requests_total", labels)

        resp = client.get(f"/inexistant/{marqueur}")
        assert resp.status_code == 404

        apres = _valeur("repod_http_requests_total", labels)
        assert apres == avant + 1, (
            f"une 404 doit être comptée sous {_PATH_INCONNU!r}, "
            f"compteur passé de {avant} à {apres}"
        )
        assert marqueur not in _expose(), \
            "le chemin demandé sur une 404 ne doit pas atteindre le registre"

    def test_route_sans_parametre_reste_lisible(self, client):
        """Non-régression : les routes fixes ne sont pas anonymisées."""
        labels = {"method": "GET", "path": "/sonde-fixe", "status_code": "200"}
        avant = _valeur("repod_http_requests_total", labels)

        client.get("/sonde-fixe")

        assert _valeur("repod_http_requests_total", labels) == avant + 1

    def test_histogramme_utilise_le_meme_gabarit(self, client):
        labels = {"method": "GET", "path": "/api/v1/auth/users/{username}"}
        avant = _valeur("repod_http_request_duration_seconds_count", labels)

        client.get(f"/api/v1/auth/users/utilisateur-{uuid4().hex}")

        apres = _valeur("repod_http_request_duration_seconds_count", labels)
        assert apres == avant + 1, (
            "l'histogramme doit utiliser le même gabarit que le compteur"
        )
