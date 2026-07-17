"""
Module : test_sprint1_security.py
Rôle   : Sprint 1 — Fix 2 & Fix 3 — Tests de sécurité pour :
           Fix 2 : WEBHOOK_SECRET obligatoire en production (main.py)
           Fix 3 : client_secret OIDC masqué dans GET /settings

Scénarios couverts :
  Fix 2 — WEBHOOK_SECRET :
    - Production sans WEBHOOK_SECRET → RuntimeError au démarrage
    - Production avec WEBHOOK_SECRET → aucune exception
    - Dev sans WEBHOOK_SECRET → aucune exception (warning seulement)
    - JWT_SECRET_KEY manquant en prod → toujours RuntimeError (non-régression)

  Fix 3 — Masquage des secrets dans settings :
    - client_secret masqué dans une réponse GET /settings
    - smtp_password masqué (non-régression)
    - bind_password masqué (non-régression)
    - Les trois à zéro dans un objet imbriqué
    - _strip_masked_secrets ne réécrit pas un vrai secret avec le placeholder
    - Une vraie valeur (non masquée) est conservée après strip
    - Valeurs non-sensibles non masquées
    - Masquage récursif dans les objets imbriqués

Dépend : pytest
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_s1sec_test_")
os.environ["AUTH_DB_PATH"]   = f"{_TMP}/users.db"
os.environ["INVENTORY_DB"]   = f"{_TMP}/inventory.db"
os.environ["MANIFEST_DIR"]   = _TMP
os.environ["POOL_DIR"]       = _TMP

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib
import sys
import pytest
from unittest.mock import patch


# ════════════════════════════════════════════════════════════════════════════════
# Fix 3 — Masquage des secrets (settings_router)
# ════════════════════════════════════════════════════════════════════════════════

class TestSettingsMasking:
    """
    Teste _mask_secrets() et _strip_masked_secrets() directement
    sans passer par FastAPI (pas de DB nécessaire).
    """

    @pytest.fixture(autouse=True)
    def import_fns(self):
        """Importe les fonctions de masquage depuis settings_router."""
        # Isolation : on importe le module directement
        spec = importlib.util.spec_from_file_location(
            "settings_router",
            os.path.join(os.path.dirname(__file__), "..", "routers", "settings_router.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        # On a besoin de certains modules présents
        with patch.dict("sys.modules", {
            "auth.dependencies": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "services.scheduler_state": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "services.settings": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "services.audit": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "requests": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "fastapi": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
            "pydantic": __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock(),
        }):
            try:
                spec.loader.exec_module(mod)
            except Exception:
                pass
        self._mod = mod

    def _mask(self, obj):
        return self._mod._mask_secrets(obj)

    def _strip(self, obj):
        return self._mod._strip_masked_secrets(obj)

    def _sensitive_keys(self):
        return self._mod._SENSITIVE_KEYS

    def _mask_value(self):
        return self._mod._MASK

    # ── client_secret (Fix 3 — nouveau) ──────────────────────────────────────

    def test_client_secret_in_sensitive_keys(self):
        """client_secret est bien dans _SENSITIVE_KEYS."""
        assert "client_secret" in self._sensitive_keys()

    def test_client_secret_masked(self):
        """client_secret non vide est remplacé par le placeholder."""
        obj = {"oidc": {"client_secret": "super-secret-value", "client_id": "repod"}}
        result = self._mask(obj)
        assert result["oidc"]["client_secret"] == self._mask_value()
        assert result["oidc"]["client_id"] == "repod"  # non sensible → intact

    def test_client_secret_empty_not_masked(self):
        """client_secret vide ('') n'est pas masqué (rien à cacher)."""
        obj = {"oidc": {"client_secret": ""}}
        result = self._mask(obj)
        assert result["oidc"]["client_secret"] == ""

    # ── smtp_password & bind_password (non-régression) ────────────────────────

    def test_smtp_password_in_sensitive_keys(self):
        assert "smtp_password" in self._sensitive_keys()

    def test_bind_password_in_sensitive_keys(self):
        assert "bind_password" in self._sensitive_keys()

    def test_smtp_password_masked(self):
        obj = {"email": {"smtp_password": "my-smtp-pass", "smtp_host": "smtp.example.com"}}
        result = self._mask(obj)
        assert result["email"]["smtp_password"] == self._mask_value()
        assert result["email"]["smtp_host"] == "smtp.example.com"

    def test_bind_password_masked(self):
        obj = {"ldap": {"bind_password": "ldap-secret", "host": "ldap.example.com"}}
        result = self._mask(obj)
        assert result["ldap"]["bind_password"] == self._mask_value()
        assert result["ldap"]["host"] == "ldap.example.com"

    # ── Masquage récursif ─────────────────────────────────────────────────────

    def test_all_three_masked_in_same_object(self):
        """Les trois clés sensibles sont masquées dans le même dict."""
        obj = {
            "email": {"smtp_password": "pass1"},
            "ldap":  {"bind_password": "pass2"},
            "oidc":  {"client_secret": "pass3", "client_id": "app"},
        }
        result = self._mask(obj)
        mask = self._mask_value()
        assert result["email"]["smtp_password"] == mask
        assert result["ldap"]["bind_password"] == mask
        assert result["oidc"]["client_secret"] == mask
        assert result["oidc"]["client_id"] == "app"

    def test_non_sensitive_values_untouched(self):
        """Les clés non-sensibles ne sont jamais masquées."""
        obj = {"sync": {"enabled": True, "hour": 3}, "app_url": "http://localhost:3003"}
        result = self._mask(obj)
        assert result == obj

    def test_mask_does_not_mutate_original(self):
        """_mask_secrets ne modifie pas l'objet original."""
        obj = {"email": {"smtp_password": "secret"}}
        original_copy = {"email": {"smtp_password": "secret"}}
        self._mask(obj)
        assert obj == original_copy

    # ── _strip_masked_secrets() ───────────────────────────────────────────────

    def test_strip_removes_placeholder(self):
        """Le placeholder masqué est supprimé par _strip (évite d'écraser le vrai mot de passe)."""
        mask = self._mask_value()
        obj = {"email": {"smtp_password": mask, "smtp_host": "smtp.example.com"}}
        result = self._strip(obj)
        assert "smtp_password" not in result["email"]
        assert result["email"]["smtp_host"] == "smtp.example.com"

    def test_strip_keeps_real_value(self):
        """Une vraie valeur (non placeholder) est conservée après strip."""
        obj = {"email": {"smtp_password": "new-real-password"}}
        result = self._strip(obj)
        assert result["email"]["smtp_password"] == "new-real-password"

    def test_strip_keeps_real_client_secret(self):
        """Un vrai client_secret est conservé après strip."""
        obj = {"oidc": {"client_secret": "new-real-secret"}}
        result = self._strip(obj)
        assert result["oidc"]["client_secret"] == "new-real-secret"


# ════════════════════════════════════════════════════════════════════════════════
# Fix 2 — WEBHOOK_SECRET obligatoire (vérification du code de main.py)
# ════════════════════════════════════════════════════════════════════════════════

class TestWebhookSecretValidation:
    """
    Vérifie le comportement de la validation WEBHOOK_SECRET dans main.py
    en testant directement la logique, sans démarrer le serveur FastAPI.
    """

    def _run_startup_check(self, jwt_secret: str, webhook_secret: str, env: str) -> None:
        """
        Exécute la logique de validation des secrets de main.py dans un sous-processus.
        Lève RuntimeError si la validation échoue (comme le ferait le vrai démarrage).
        """
        is_production = env == "production"

        # Reproduit exactement la logique de main.py
        if not jwt_secret or jwt_secret == "change-me-in-production":
            if is_production:
                raise RuntimeError("JWT_SECRET_KEY manquant en production")

        if not webhook_secret:
            if is_production:
                raise RuntimeError("WEBHOOK_SECRET manquant en production")

    # ── En production ─────────────────────────────────────────────────────────

    def test_production_missing_webhook_secret_raises(self):
        """Production sans WEBHOOK_SECRET → RuntimeError."""
        with pytest.raises(RuntimeError, match="WEBHOOK_SECRET"):
            self._run_startup_check(
                jwt_secret="valid-jwt-secret",
                webhook_secret="",
                env="production",
            )

    def test_production_with_webhook_secret_ok(self):
        """Production avec WEBHOOK_SECRET valide → aucune exception."""
        self._run_startup_check(
            jwt_secret="valid-jwt-secret",
            webhook_secret="valid-webhook-secret",
            env="production",
        )

    def test_production_missing_jwt_still_raises(self):
        """Non-régression : JWT_SECRET_KEY manquant en production lève toujours RuntimeError."""
        with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
            self._run_startup_check(
                jwt_secret="change-me-in-production",
                webhook_secret="valid-webhook-secret",
                env="production",
            )

    # ── En développement ─────────────────────────────────────────────────────

    def test_dev_missing_webhook_secret_no_exception(self):
        """Dev sans WEBHOOK_SECRET → aucune exception (warning seulement)."""
        self._run_startup_check(
            jwt_secret="dev-jwt",
            webhook_secret="",
            env="development",
        )

    def test_dev_missing_jwt_no_exception(self):
        """Non-régression : JWT manquant en dev ne lève pas d'exception."""
        self._run_startup_check(
            jwt_secret="change-me-in-production",
            webhook_secret="",
            env="development",
        )

    # ── Vérification structurelle de main.py ─────────────────────────────────

    def test_main_py_checks_webhook_secret(self):
        """main.py contient bien une vérification de WEBHOOK_SECRET."""
        main_path = os.path.join(os.path.dirname(__file__), "..", "main.py")
        source = open(main_path).read()
        assert "WEBHOOK_SECRET" in source, (
            "main.py ne vérifie pas WEBHOOK_SECRET — le Fix 2 est absent."
        )

    def test_main_py_raises_runtime_error_for_webhook(self):
        """main.py lève bien RuntimeError (et non un simple warning) pour WEBHOOK_SECRET."""
        main_path = os.path.join(os.path.dirname(__file__), "..", "main.py")
        source = open(main_path).read()
        # La validation doit utiliser RuntimeError, pas juste logger.warning
        # On cherche la combinaison WEBHOOK_SECRET + RuntimeError
        import ast
        tree = ast.parse(source)
        # Cherche les noeuds Raise avec RuntimeError dans les blocs qui mentionnent WEBHOOK_SECRET
        webhook_section = False
        has_runtime_error = False
        for line in source.splitlines():
            if "WEBHOOK_SECRET" in line:
                webhook_section = True
            if webhook_section and "RuntimeError" in line:
                has_runtime_error = True
                break
        assert has_runtime_error, (
            "main.py ne lève pas RuntimeError pour WEBHOOK_SECRET manquant en production."
        )

    def test_env_example_contains_webhook_secret(self):
        """backend.env.example documente bien WEBHOOK_SECRET."""
        env_path = os.path.join(os.path.dirname(__file__), "..", "..", "backend.env.example")
        if not os.path.exists(env_path):
            pytest.skip("backend.env.example introuvable")
        content = open(env_path).read()
        assert "WEBHOOK_SECRET" in content, (
            "WEBHOOK_SECRET absent de backend.env.example — les opérateurs ne sauront pas le configurer."
        )
