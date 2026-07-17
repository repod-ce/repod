"""
Module : test_settings_router_patch.py
Rôle   : Régression — PATCH /settings/ ignorait silencieusement cve_policy,
         security, epss_policy et notification_rules : ces sections n'étaient
         pas déclarées comme champs sur le modèle Pydantic SettingsPatch
         (routers/settings_router.py), donc FastAPI les supprimait de la
         requête avant même d'appeler update_settings() — la fusion profonde
         elle-même (services/settings.py:_deep_merge) fonctionnait très bien,
         le problème était uniquement la validation de la requête entrante.
         Trouvé en reproduisant "je modifie la politique CVE dans les
         paramètres et ça ne sauvegarde pas" (page Paramètres).

Scénarios couverts :
  - Chaque section acceptée par le frontend (SettingsPage.js) est bien
    persistée par un PATCH, y compris celles ajoutées par ce correctif
  - Une section absente de la requête reste inchangée (fusion, pas remplacement)

Dépend : pytest
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_settings_patch_test_")
os.environ["JWT_SECRET_KEY"] = "test-secret-for-settings-patch"
os.environ["SETTINGS_PATH"]  = f"{_TMP}/settings.json"
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("INDEX_PATH", f"{_TMP}/index.json")
os.environ.setdefault("STAGING_INCOMING", f"{_TMP}/staging/incoming")
os.environ.setdefault("STAGING_QUARANTINE", f"{_TMP}/staging/quarantine")
os.environ.setdefault("AUDIT_DIR", f"{_TMP}/audit")
os.environ.setdefault("SECURITY_CACHE_DIR", f"{_TMP}/security")
os.environ.setdefault("PENDING_PROMOTIONS_DIR", f"{_TMP}/security/pending_promotions")

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import services.settings as settings_mod
importlib.reload(settings_mod)   # force reload avec les bonnes env vars

import routers.settings_router as settings_router_mod
importlib.reload(settings_router_mod)

from auth.dependencies import get_admin_user


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(settings_router_mod.router)
    app.dependency_overrides[get_admin_user] = lambda: "admin_test"
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _fresh_settings_file():
    """Repart d'un settings.json vierge à chaque test."""
    from pathlib import Path
    path = Path(os.environ["SETTINGS_PATH"])
    path.unlink(missing_ok=True)
    yield
    path.unlink(missing_ok=True)


# ── Sections que le frontend peut envoyer (SettingsPage.js) ───────────────────
# notification_rules est une LISTE (NotificationRulesSection.js), pas un dict —
# testée séparément ci-dessous plutôt que dans cette table à payload dict.
_SECTION_PAYLOADS = {
    "cve_policy":         {"critical": "block", "high": "review", "sla_high_days": 45},
    "security":           {"kev_ttl_hours": 12, "epss_ttl_hours": 6},
    "epss_policy":        {"threshold": 0.5, "action": "review"},
    "sync":               {"enabled": False, "hour": 4, "minute": 15},
    "sources":            {"debian-security": True},
    "email":              {"smtp_host": "smtp.example.com"},
    "retention":          {"audit_days": 60},
    "validation":         {"gpg_required": True},
}


class TestSettingsPatchPersistsEverySection:

    @pytest.mark.parametrize("section,payload", list(_SECTION_PAYLOADS.items()))
    def test_section_is_persisted(self, client, section, payload):
        r = client.patch("/settings/", json={section: payload})
        assert r.status_code == 200, r.text
        body = r.json()
        assert section in body, f"{section} absent de la réponse PATCH"
        for key, value in payload.items():
            assert body[section].get(key) == value, (
                f"{section}.{key} = {body[section].get(key)!r}, attendu {value!r} — "
                f"probablement absent du modèle SettingsPatch"
            )

        # Confirme que la persistance survit à une relecture (pas juste la
        # réponse de la requête elle-même).
        r2 = client.get("/settings/")
        assert r2.status_code == 200
        for key, value in payload.items():
            assert r2.json()[section].get(key) == value

    def test_notification_rules_list_payload_is_persisted(self, client):
        """notification_rules est une liste de règles {event, enabled, recipients},
        pas un dict — vérifie que le type déclaré sur SettingsPatch (list, pas
        dict) accepte bien la forme réelle envoyée par NotificationRulesSection.js."""
        rules = [{"event": "SCAN_FAILED", "enabled": True, "recipients": ["alice"]}]
        r = client.patch("/settings/", json={"notification_rules": rules})
        assert r.status_code == 200, r.text
        assert r.json()["notification_rules"] == rules

        r2 = client.get("/settings/")
        assert r2.json()["notification_rules"] == rules

    def test_unrelated_section_untouched_by_partial_patch(self, client):
        """Un PATCH sur cve_policy ne doit pas effacer une section sync déjà enregistrée."""
        client.patch("/settings/", json={"sync": {"enabled": False, "hour": 2, "minute": 0}})
        client.patch("/settings/", json={"cve_policy": {"critical": "block"}})

        r = client.get("/settings/")
        body = r.json()
        assert body["sync"]["enabled"] is False
        assert body["sync"]["hour"] == 2
        assert body["cve_policy"]["critical"] == "block"
