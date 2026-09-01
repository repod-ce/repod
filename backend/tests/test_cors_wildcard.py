# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_cors_wildcard.py
Rôle   : CORS_ORIGINS="*" combiné à allow_credentials=True réfléchit l'Origin
         de l'appelant.

         docker-compose.yaml posait « CORS_ORIGINS: ${CORS_ORIGINS:-*} », les
         deux env_file étant « required: false » et aucun .env n'existant dans
         le dépôt : un « docker compose up -d » depuis un clone propre livrait
         donc allow_origins=["*"] avec allow_credentials=True (main.py:449).

         La règle habituelle « wildcard plus credentials, le navigateur
         neutralise » ne s'applique pas : starlette/middleware/cors.py bascule
         sur allow_explicit_origin() quand les deux options sont combinées et
         renvoie l'Origin de l'appelant accompagnée de
         Access-Control-Allow-Credentials: true. N'importe quelle page web
         pouvait donc appeler l'API depuis le navigateur d'un utilisateur
         interne et lire les réponses, dont GET /api/v1/setup/preflight qui
         n'exige pas d'authentification et divulgue noms d'hôtes internes,
         capacité disque et versions des outils.

         Le correctif refuse le wildcard au démarrage : levée en production,
         avertissement en développement, comme les quatre autres blocs de
         validation de main.py.

Dépend : pytest, fastapi.testclient
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")

# ── Imports normaux ────────────────────────────────────────────────────────────
import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest

_ORIGINE_LEGITIME = "http://localhost:3003"
_ORIGINE_HOSTILE = "http://evil.test"


def _charger_main(monkeypatch, env: dict):
    """
    Charge une instance neuve de main.py, relisant l'environnement.

    ENV et CORS_ORIGINS sont lus au niveau module, il faut donc ré-exécuter le
    fichier pour tester chaque configuration. spec_from_file_location donne un
    objet module distinct sans écraser sys.modules["main"] (motif déjà utilisé
    par _charger_routeur() dans test_metrics_public_exposure.py).

    Les trois secrets sont fournis avec des valeurs non par défaut : sans eux,
    ce sont les blocs de validation précédents (JWT_SECRET_KEY:60,
    WEBHOOK_SECRET:74, REPOD_LICENSE_VENDOR_KEY:90) qui lèveraient, et le test
    ne prouverait rien sur le CORS.

    Aucun effet de bord notable au niveau module : seuls load_dotenv(),
    setup_logging() et la construction de l'app s'exécutent. seed_builtin_roles()
    et le BackgroundScheduler vivent dans le lifespan, jamais déclenché ici.
    """
    # Peupler sys.modules sous l'environnement ambiant AVANT tout monkeypatch.
    # Plusieurs modules importés par main.py figent une variable d'environnement
    # à leur propre import — routers/webhook_router.py:36 lit WEBHOOK_SECRET dans
    # une constante de module. Sans cet import préalable, le tout premier
    # chargement de main.py se ferait sous l'environnement patché et laisserait
    # ces constantes faussées pour tout le reste de la session pytest, ce qui
    # casse test_webhook.py à distance.
    import main  # noqa: F401

    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 64)
    monkeypatch.setenv("WEBHOOK_SECRET", "b" * 64)
    monkeypatch.setenv("REPOD_LICENSE_VENDOR_KEY", "c" * 64)
    for cle, valeur in env.items():
        monkeypatch.setenv(cle, valeur)

    chemin = Path(__file__).parent.parent / "main.py"
    spec = importlib.util.spec_from_file_location(f"main_sous_test_{uuid4().hex}", chemin)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _kwargs_cors(mod) -> dict:
    """Retourne les kwargs réellement passés à CORSMiddleware par main.py."""
    for couche in mod.app.user_middleware:
        if couche.cls.__name__ == "CORSMiddleware":
            return couche.kwargs
    raise AssertionError("CORSMiddleware absent de la pile de middlewares")


class TestGardeCorsWildcard:
    """main.py:449 — refus du wildcard, qui n'est pas neutralisé par les credentials."""

    def test_production_wildcard_refuse_le_demarrage(self, monkeypatch):
        with pytest.raises(RuntimeError) as exc:
            _charger_main(monkeypatch, {"ENV": "production", "CORS_ORIGINS": "*"})
        assert "CORS_ORIGINS" in str(exc.value), (
            "La levée doit venir de la garde CORS, pas d'un autre bloc de validation"
        )

    def test_production_wildcard_noye_dans_une_liste_refuse_aussi(self, monkeypatch):
        """
        Starlette teste « "*" in allow_origins », pas l'égalité : une liste
        contenant le wildcard active le mode toutes-origines aussi sûrement
        qu'un wildcard seul. La garde utilise le même prédicat.
        """
        with pytest.raises(RuntimeError) as exc:
            _charger_main(
                monkeypatch,
                {"ENV": "production", "CORS_ORIGINS": f"{_ORIGINE_LEGITIME},*"},
            )
        assert "CORS_ORIGINS" in str(exc.value)

    def test_production_liste_explicite_demarre(self, monkeypatch):
        mod = _charger_main(
            monkeypatch,
            {"ENV": "production", "CORS_ORIGINS": f"{_ORIGINE_LEGITIME},https://repod.interne"},
        )
        assert mod.allowed_origins == [_ORIGINE_LEGITIME, "https://repod.interne"]
        assert _kwargs_cors(mod)["allow_credentials"] is True, (
            "Les credentials restent autorisés pour les origines listées"
        )

    def test_developpement_wildcard_avertit_sans_lever(self, monkeypatch):
        """
        Même posture que les quatre autres blocs de validation de main.py :
        bloquant en production, simple avertissement en développement, où
        l'opérateur a explicitement demandé le wildcard.
        """
        mod = _charger_main(monkeypatch, {"ENV": "development", "CORS_ORIGINS": "*"})
        assert mod.allowed_origins == ["*"]


class TestReflexionOrigine:
    """Non-régression : le CORS légitime continue de fonctionner."""

    def _client(self, monkeypatch):
        from fastapi.testclient import TestClient

        mod = _charger_main(
            monkeypatch, {"ENV": "production", "CORS_ORIGINS": _ORIGINE_LEGITIME}
        )
        # Sans « with », le lifespan n'est pas déclenché : ni scheduler, ni
        # seed_builtin_roles, ni connexion base.
        return TestClient(mod.app, raise_server_exceptions=False)

    def test_origine_hostile_non_reflechie(self, monkeypatch):
        client = self._client(monkeypatch)
        reponse = client.options(
            "/api/v1/setup/preflight",
            headers={
                "Origin": _ORIGINE_HOSTILE,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert reponse.headers.get("access-control-allow-origin") != _ORIGINE_HOSTILE, (
            "L'Origin de l'appelant ne doit jamais être réfléchie"
        )

    def test_origine_legitime_autorisee_avec_credentials(self, monkeypatch):
        client = self._client(monkeypatch)
        reponse = client.options(
            "/api/v1/setup/preflight",
            headers={
                "Origin": _ORIGINE_LEGITIME,
                "Access-Control-Request-Method": "GET",
            },
        )
        assert reponse.headers.get("access-control-allow-origin") == _ORIGINE_LEGITIME
        assert reponse.headers.get("access-control-allow-credentials") == "true", (
            "Le frontend légitime doit conserver l'envoi de credentials"
        )
