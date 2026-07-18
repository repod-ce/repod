"""
Module : test_structured_logging.py
Rôle   : P2-2 — Logging JSON structuré
         Vérifie que setup_logging() installe un formateur JSON sur le logger
         racine, que request_id est injecté depuis contextvars dans chaque
         enregistrement, et que le middleware RequestIdMiddleware propage
         correctement l'ID de corrélation.

Dépend : pytest, python-json-logger
"""

# ── Env avant tout import de services ─────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_logging_test_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")

# ── Imports normaux ────────────────────────────────────────────────────────────
import io
import json
import logging
import uuid
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Source inspection — main.py migré vers JSON logging
# ═══════════════════════════════════════════════════════════════════════════════

class TestMainPyMigrated:

    @staticmethod
    def _main_src() -> str:
        p = Path(__file__).parent.parent / "main.py"
        assert p.exists(), "main.py introuvable"
        return p.read_text()

    def test_basicconfig_removed_from_main(self):
        """
        ❌ ROUGE avant fix : logging.basicConfig(level=logging.INFO) présent
        ✅ VERT après fix  : remplacé par setup_logging()
        """
        assert "basicConfig" not in self._main_src(), (
            "main.py ne doit plus utiliser logging.basicConfig() — "
            "utiliser services.logging_config.setup_logging() (P2-2)"
        )

    def test_setup_logging_called_in_main(self):
        """main.py doit appeler setup_logging() au démarrage."""
        assert "setup_logging" in self._main_src(), (
            "main.py doit appeler setup_logging() depuis services.logging_config"
        )

    def test_request_id_middleware_registered_in_main(self):
        """main.py doit enregistrer RequestIdMiddleware via app.add_middleware."""
        src = self._main_src()
        assert "RequestIdMiddleware" in src, (
            "main.py doit enregistrer RequestIdMiddleware pour propager "
            "le X-Request-ID dans les logs"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# services/logging_config.py — module existe et exporte les bons symboles
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoggingConfigModule:

    def test_module_exists(self):
        """
        ❌ ROUGE avant fix : services/logging_config.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "services" / "logging_config.py"
        assert p.exists(), "services/logging_config.py doit être créé (P2-2)"

    def test_setup_logging_importable(self):
        """setup_logging doit être importable depuis services.logging_config."""
        from services.logging_config import setup_logging
        assert callable(setup_logging)

    def test_request_id_var_importable(self):
        """request_id_var (ContextVar) doit être exporté."""
        from services.logging_config import request_id_var
        from contextvars import ContextVar
        assert isinstance(request_id_var, ContextVar)

    def test_request_id_var_default_is_dash(self):
        """La valeur par défaut de request_id_var est '-' (aucune requête active)."""
        from services.logging_config import request_id_var
        assert request_id_var.get() == "-"


# ═══════════════════════════════════════════════════════════════════════════════
# setup_logging() — sortie JSON valide
# ═══════════════════════════════════════════════════════════════════════════════

class TestSetupLoggingOutput:
    """
    Vérifie le format de sortie après appel de setup_logging().
    On passe un stream StringIO pour capturer sans polluer stderr.
    """

    @pytest.fixture(autouse=True)
    def restore_root_logger(self):
        """Sauvegarde et restaure les handlers du logger racine après chaque test."""
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        original_level = root.level
        yield
        root.handlers = original_handlers
        root.level = original_level

    def _capture_log(self, level_name: str = "INFO", message: str = "test") -> dict:
        """Émet un log et retourne le dict JSON parsé."""
        from services.logging_config import setup_logging
        stream = io.StringIO()
        setup_logging(stream=stream, level=logging.DEBUG)
        logger = logging.getLogger(f"test_capture_{uuid.uuid4().hex[:6]}")
        getattr(logger, level_name.lower())(message)
        raw = stream.getvalue().strip()
        assert raw, "Aucune sortie du logger — setup_logging() ne fonctionne pas"
        return json.loads(raw)

    def test_output_is_valid_json(self):
        """
        ❌ ROUGE avant fix : basicConfig → sortie texte non parsable en JSON
        ✅ VERT après fix  : chaque ligne de log est du JSON valide
        """
        record = self._capture_log(message="hello json")
        assert isinstance(record, dict)

    def test_json_contains_message_field(self):
        """Le champ 'message' contient le texte du log."""
        record = self._capture_log(message="message field test")
        assert record.get("message") == "message field test"

    def test_json_contains_level_field(self):
        """Le champ 'level' (ou 'levelname') est présent."""
        record = self._capture_log(level_name="WARNING", message="warn test")
        level = record.get("level") or record.get("levelname") or ""
        assert "WARN" in level.upper() or "WARNING" in level.upper()

    def test_json_contains_timestamp_field(self):
        """Un champ timestamp / asctime / time est présent."""
        record = self._capture_log(message="ts test")
        has_ts = any(k in record for k in ("timestamp", "asctime", "time"))
        assert has_ts, f"Aucun champ timestamp trouvé dans {list(record.keys())}"

    def test_json_contains_logger_name(self):
        """Le nom du logger ('name') est présent dans le record JSON."""
        record = self._capture_log(message="name test")
        assert "name" in record, f"Clé 'name' absente : {list(record.keys())}"

    def test_request_id_injected_in_log(self):
        """
        Quand request_id_var est positionné, sa valeur apparaît dans le log JSON.
        """
        from services.logging_config import setup_logging, request_id_var
        stream = io.StringIO()
        setup_logging(stream=stream, level=logging.DEBUG)

        test_id = f"test-{uuid.uuid4()}"
        token = request_id_var.set(test_id)
        try:
            logger = logging.getLogger(f"test_reqid_{uuid.uuid4().hex[:6]}")
            logger.info("avec request_id")
        finally:
            request_id_var.reset(token)

        raw = stream.getvalue().strip()
        record = json.loads(raw)
        assert record.get("request_id") == test_id, (
            f"request_id attendu={test_id!r}, obtenu={record.get('request_id')!r}"
        )

    def test_request_id_defaults_to_dash_when_no_request(self):
        """Sans requête active, request_id vaut '-' dans le log."""
        from services.logging_config import setup_logging, request_id_var
        # S'assurer qu'on est hors contexte de requête
        token = request_id_var.set("-")
        stream = io.StringIO()
        setup_logging(stream=stream, level=logging.DEBUG)
        try:
            logger = logging.getLogger(f"test_noreq_{uuid.uuid4().hex[:6]}")
            logger.info("sans request_id")
        finally:
            request_id_var.reset(token)

        raw = stream.getvalue().strip()
        record = json.loads(raw)
        assert record.get("request_id") == "-"


# ═══════════════════════════════════════════════════════════════════════════════
# middleware/request_id.py — RequestIdMiddleware
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequestIdMiddlewareModule:

    def test_middleware_module_exists(self):
        """
        ❌ ROUGE avant fix : middleware/request_id.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "middleware" / "request_id.py"
        assert p.exists(), "middleware/request_id.py doit être créé (P2-2)"

    def test_request_id_middleware_importable(self):
        """RequestIdMiddleware doit être importable."""
        from middleware.request_id import RequestIdMiddleware
        assert RequestIdMiddleware is not None

    def test_middleware_sets_contextvar(self):
        """
        Appel direct du dispatch du middleware → request_id_var est positionné
        pendant l'exécution du handler.
        """
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        from middleware.request_id import RequestIdMiddleware
        from services.logging_config import request_id_var

        captured_id: list[str] = []

        async def fake_call_next(request):
            captured_id.append(request_id_var.get())
            response = MagicMock()
            response.headers = {}
            return response

        mw = RequestIdMiddleware(app=MagicMock())
        request = MagicMock()
        request.headers = {}

        asyncio.get_event_loop().run_until_complete(
            mw.dispatch(request, fake_call_next)
        )

        assert len(captured_id) == 1
        assert captured_id[0] != "-", (
            "request_id_var doit être positionné pendant le dispatch"
        )
        # Après le dispatch, le contextvar est réinitialisé
        assert request_id_var.get() == "-"

    def test_middleware_uses_incoming_header_if_present(self):
        """Si X-Request-ID est dans la requête, on le réutilise (traçabilité end-to-end)."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        from middleware.request_id import RequestIdMiddleware
        from services.logging_config import request_id_var

        incoming_id = str(uuid.uuid4())
        captured_id: list[str] = []

        async def fake_call_next(request):
            captured_id.append(request_id_var.get())
            response = MagicMock()
            response.headers = {}
            return response

        mw = RequestIdMiddleware(app=MagicMock())
        request = MagicMock()
        request.headers = {"X-Request-ID": incoming_id}

        asyncio.get_event_loop().run_until_complete(
            mw.dispatch(request, fake_call_next)
        )

        assert captured_id[0] == incoming_id

    def test_middleware_adds_header_to_response(self):
        """La réponse doit contenir l'en-tête X-Request-ID."""
        import asyncio
        from unittest.mock import MagicMock
        from middleware.request_id import RequestIdMiddleware

        response_headers: dict = {}

        async def fake_call_next(request):
            response = MagicMock()
            response.headers = response_headers
            return response

        mw = RequestIdMiddleware(app=MagicMock())
        request = MagicMock()
        request.headers = {}

        asyncio.get_event_loop().run_until_complete(
            mw.dispatch(request, fake_call_next)
        )

        assert "X-Request-ID" in response_headers, (
            "La réponse doit contenir l'en-tête X-Request-ID"
        )
