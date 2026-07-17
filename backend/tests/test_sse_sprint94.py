"""
Tests unitaires — Sprint 9.4 : Dashboard SSE

Couverture :
  • TestEventBus           (7)  — subscribe, unsubscribe, publish, full queue, count
  • TestPublishEvent       (3)  — retourne count, never raises, structure événement
  • TestSSEFormat          (2)  — format ligne SSE, JSON encodé
  • TestSSEStreamGenerator (3)  — heartbeat, événement, unsubscribe à déconnexion
  • TestSSEEndpoints       (5)  — 200 + event-stream, cache-control, auth, subscriber count
  • TestAuditIntegration   (3)  — audit.log publie, failure safe, champs de l'événement
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_sse94_test_")
os.environ.setdefault("MANIFEST_DIR",           _TMP)
os.environ.setdefault("MANIFEST_DB",            os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",               _TMP)
os.environ.setdefault("AUDIT_DIR",              _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",         os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",             os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",          os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",           os.path.join(_TMP, "users.db"))
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))
os.environ.setdefault("NOTIFICATIONS_LOG_PATH", os.path.join(_TMP, "notifications.jsonl"))
os.environ.setdefault("SECURITY_CACHE_DIR",     os.path.join(_TMP, "security"))

# ── Imports ───────────────────────────────────────────────────────────────────
import asyncio
import importlib.util
import json
import queue
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.sse_bus import (
    EventBus,
    get_bus,
    publish_event,
    sse_format,
    QUEUE_MAXSIZE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fresh_bus():
    """Retourne un EventBus isolé (non-singleton) pour les tests unitaires."""
    return EventBus()


# ─────────────────────────────────────────────────────────────────────────────
# 1. TestEventBus
# ─────────────────────────────────────────────────────────────────────────────

class TestEventBus:
    def test_subscribe_returns_queue(self, fresh_bus):
        q = fresh_bus.subscribe()
        assert isinstance(q, queue.Queue)

    def test_subscribe_increments_count(self, fresh_bus):
        assert fresh_bus.subscriber_count == 0
        fresh_bus.subscribe()
        assert fresh_bus.subscriber_count == 1
        fresh_bus.subscribe()
        assert fresh_bus.subscriber_count == 2

    def test_unsubscribe_decrements_count(self, fresh_bus):
        q = fresh_bus.subscribe()
        assert fresh_bus.subscriber_count == 1
        fresh_bus.unsubscribe(q)
        assert fresh_bus.subscriber_count == 0

    def test_unsubscribe_unknown_queue_is_safe(self, fresh_bus):
        unknown_q = queue.Queue()
        fresh_bus.unsubscribe(unknown_q)  # Ne doit pas lever d'exception

    def test_publish_puts_event_in_queue(self, fresh_bus):
        q = fresh_bus.subscribe()
        fresh_bus.publish("audit_log", {"action": "UPLOAD"})
        event = q.get_nowait()
        assert event["type"] == "audit_log"
        assert event["data"]["action"] == "UPLOAD"

    def test_publish_to_multiple_subscribers(self, fresh_bus):
        q1 = fresh_bus.subscribe()
        q2 = fresh_bus.subscribe()
        count = fresh_bus.publish("test", {"x": 1})
        assert count == 2
        assert q1.get_nowait()["type"] == "test"
        assert q2.get_nowait()["type"] == "test"

    def test_publish_full_queue_does_not_raise(self, fresh_bus):
        q = fresh_bus.subscribe()
        # Remplir la queue jusqu'à capacité
        for _ in range(QUEUE_MAXSIZE):
            q.put_nowait({"dummy": True})
        # Publish ne doit pas lever d'exception même si la queue est pleine
        fresh_bus.publish("overflow", {"x": 1})  # doit passer silencieusement


# ─────────────────────────────────────────────────────────────────────────────
# 2. TestPublishEvent
# ─────────────────────────────────────────────────────────────────────────────

class TestPublishEvent:
    def test_returns_subscriber_count(self):
        bus = get_bus()
        q = bus.subscribe()
        try:
            count = publish_event("test_event", {"k": "v"})
            assert isinstance(count, int)
            assert count >= 1  # au moins notre abonné
        finally:
            bus.unsubscribe(q)

    def test_never_raises_on_exception(self):
        """publish_event() ne lève jamais même si le bus plante."""
        with patch("services.sse_bus._bus") as mock_bus:
            mock_bus.publish.side_effect = RuntimeError("bus failure")
            result = publish_event("test", {})
        assert result == 0

    def test_event_received_in_queue(self):
        bus = get_bus()
        q = bus.subscribe()
        try:
            publish_event("pkg_upload", {"package": "nginx"})
            event = q.get_nowait()
            assert event["type"] == "pkg_upload"
            assert event["data"]["package"] == "nginx"
        finally:
            bus.unsubscribe(q)


# ─────────────────────────────────────────────────────────────────────────────
# 3. TestSSEFormat
# ─────────────────────────────────────────────────────────────────────────────

class TestSSEFormat:
    def test_starts_with_data_prefix(self):
        event = {"type": "test", "data": {}}
        line = sse_format(event)
        assert line.startswith("data: ")

    def test_ends_with_double_newline(self):
        event = {"type": "test", "data": {}}
        line = sse_format(event)
        assert line.endswith("\n\n")

    def test_json_parseable(self):
        event = {"type": "audit_log", "data": {"action": "UPLOAD", "user": "alice"}}
        line = sse_format(event)
        # Extraire la partie JSON après "data: "
        json_part = line[len("data: "):].strip()
        parsed = json.loads(json_part)
        assert parsed["type"] == "audit_log"
        assert parsed["data"]["action"] == "UPLOAD"


# ─────────────────────────────────────────────────────────────────────────────
# 4. TestSSEStreamGenerator
# ─────────────────────────────────────────────────────────────────────────────

class TestSSEStreamGenerator:
    """Tests du générateur _sse_stream avec heartbeat_interval court."""

    def _load_router_mod(self):
        spec = importlib.util.spec_from_file_location(
            "dashboard_router_sse94",
            Path(__file__).parent.parent / "routers" / "dashboard_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_heartbeat_emitted(self):
        """Avec heartbeat_interval=0, la première chunk doit être un heartbeat."""
        mod = self._load_router_mod()
        q   = queue.Queue()

        async def _collect():
            gen = mod._sse_stream(q, heartbeat_interval=0.0, poll_interval=0.01)
            chunks = []
            async for chunk in gen:
                chunks.append(chunk)
                if len(chunks) >= 1:
                    gen.aclose()  # type: ignore
                    break
            return chunks

        chunks = asyncio.get_event_loop().run_until_complete(_collect())
        assert any(": heartbeat" in c for c in chunks)

    def test_event_in_queue_is_yielded(self):
        """Un événement dans la queue doit être émis comme ligne SSE."""
        mod = self._load_router_mod()
        q   = queue.Queue()
        q.put_nowait({"type": "audit_log", "data": {"action": "UPLOAD"}})

        async def _collect():
            gen = mod._sse_stream(q, heartbeat_interval=9999.0, poll_interval=0.01)
            chunks = []
            async for chunk in gen:
                chunks.append(chunk)
                if len(chunks) >= 1:
                    break
            return chunks

        chunks = asyncio.get_event_loop().run_until_complete(_collect())
        # Au moins un chunk doit contenir "audit_log"
        assert any("audit_log" in c for c in chunks)

    def test_unsubscribe_called_on_finish(self):
        """Le bus doit avoir moins d'abonnés après fermeture explicite du générateur.

        Note : en Python 3.10, `break` dans `async for` ne déclenche PAS
        immédiatement `aclose()` — la cleanup est différée au GC ou à
        `shutdown_asyncgens()`. On appelle donc `await gen.aclose()`
        explicitement pour garantir l'exécution du finally block.
        """
        mod = self._load_router_mod()
        bus = mod.get_bus()
        # Mesurer le count avant notre subscribe
        initial = bus.subscriber_count
        q = bus.subscribe()
        assert bus.subscriber_count == initial + 1

        async def _run():
            gen = mod._sse_stream(q, heartbeat_interval=0.0, poll_interval=0.01)
            async for _ in gen:
                break
            await gen.aclose()  # Nécessaire en Python 3.10 : force le finally block

        asyncio.get_event_loop().run_until_complete(_run())
        assert bus.subscriber_count == initial  # abonné nettoyé par finally


# ─────────────────────────────────────────────────────────────────────────────
# 5. TestSSEEndpoints
# ─────────────────────────────────────────────────────────────────────────────

def _load_dashboard_router():
    spec = importlib.util.spec_from_file_location(
        "dashboard_router_sse94_http",
        Path(__file__).parent.parent / "routers" / "dashboard_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def dashboard_mod():
    return _load_dashboard_router()


@pytest.fixture(scope="module")
def sse_client(dashboard_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_current_user, get_admin_user

    app = FastAPI()
    app.include_router(dashboard_mod.router)
    app.dependency_overrides[get_current_user] = lambda: "user"
    app.dependency_overrides[get_admin_user]   = lambda: "admin"
    return TestClient(app)


async def _finite_stream(q, heartbeat_interval=25.0, poll_interval=0.2):
    """Générateur SSE fini pour les tests — émet un heartbeat puis se termine."""
    yield ": heartbeat\n\n"
    yield 'data: {"type": "test", "data": {}}\n\n'


class TestSSEEndpoints:
    def test_sse_returns_200(self, sse_client, dashboard_mod):
        with patch.object(dashboard_mod, "_sse_stream", _finite_stream):
            with sse_client.stream("GET", "/dashboard/events") as r:
                assert r.status_code == 200

    def test_sse_content_type_event_stream(self, sse_client, dashboard_mod):
        with patch.object(dashboard_mod, "_sse_stream", _finite_stream):
            with sse_client.stream("GET", "/dashboard/events") as r:
                ct = r.headers.get("content-type", "")
                assert "text/event-stream" in ct

    def test_sse_cache_control_no_cache(self, sse_client, dashboard_mod):
        with patch.object(dashboard_mod, "_sse_stream", _finite_stream):
            with sse_client.stream("GET", "/dashboard/events") as r:
                cc = r.headers.get("cache-control", "")
                assert "no-cache" in cc

    def test_sse_auth_required(self, dashboard_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(dashboard_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        with client.stream("GET", "/dashboard/events") as r:
            assert r.status_code in (401, 403, 422)

    def test_subscriber_count_endpoint(self, sse_client, dashboard_mod):
        resp = sse_client.get("/dashboard/events/subscribers")
        assert resp.status_code == 200
        body = resp.json()
        assert "subscribers" in body
        assert "checked_at"  in body
        assert isinstance(body["subscribers"], int)


# ─────────────────────────────────────────────────────────────────────────────
# 6. TestAuditIntegration
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditIntegration:
    def test_audit_log_calls_publish_event(self):
        """services.audit.log() doit appeler publish_event."""
        from services import audit as audit_mod

        with patch("services.sse_bus.publish_event") as mock_pub:
            audit_mod.log("UPLOAD", "alice", "SUCCESS", package="nginx")
        mock_pub.assert_called_once()
        args = mock_pub.call_args
        assert args[0][0] == "audit_log"  # premier argument = event_type

    def test_audit_log_event_has_required_fields(self):
        """L'événement publié doit contenir action, user, result, timestamp."""
        from services import audit as audit_mod

        published = {}

        def _capture(event_type, data):
            published["type"] = event_type
            published["data"] = data
            return 0

        with patch("services.sse_bus.publish_event", side_effect=_capture):
            audit_mod.log("DELETE", "bob", "FAILURE", package="apache")

        assert published["type"] == "audit_log"
        d = published["data"]
        assert d["action"]  == "DELETE"
        assert d["user"]    == "bob"
        assert d["result"]  == "FAILURE"
        assert d["package"] == "apache"
        assert "timestamp"  in d

    def test_sse_failure_does_not_break_audit(self):
        """Si le SSE bus plante, l'audit doit quand même être enregistré."""
        from services import audit as audit_mod

        with patch("services.sse_bus.publish_event", side_effect=RuntimeError("crash")):
            # Ne doit pas lever d'exception
            audit_mod.log("LOGIN", "carol", "SUCCESS")
        # Si on arrive ici, le test passe
