"""
Module : test_metrics.py
Rôle   : P3-B — Métriques Prometheus
         Vérifie les définitions de métriques (noms, labels), le middleware
         HTTP (compteur, durée), l'endpoint /metrics et l'intégration main.py.

Architecture :
  services/metrics.py           → registry isolé + Counter/Histogram/Gauge
  middleware/metrics_middleware.py → MetricsMiddleware (BaseHTTPMiddleware)
  routers/metrics_router.py     → GET /metrics (sans préfixe API, endpoint infra)

Le contrat d'authentification de GET /metrics et l'anonymisation des labels sont
couverts par tests/test_metrics_public_exposure.py, qui les teste sur le
comportement réel plutôt que par inspection de source.

Dépendances : prometheus-client
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_metrics_test_")
os.environ["MANIFEST_DIR"] = _TMP
os.environ.setdefault("POOL_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
from pathlib import Path

import pytest

import services.manifest as _manifest_mod
_manifest_mod.MANIFEST_DIR = Path(_TMP)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Module services/metrics.py — existence et imports
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetricsModuleExists:
    """
    ❌ ROUGE avant fix : services/metrics.py n'existe pas
    ✅ VERT après fix  : module présent avec objets attendus
    """

    def test_metrics_module_file_exists(self):
        """services/metrics.py doit exister."""
        p = Path(__file__).parent.parent / "services" / "metrics.py"
        assert p.exists(), "services/metrics.py doit être créé (P3-B)"

    def test_registry_importable(self):
        """REGISTRY (CollectorRegistry isolé) doit être importable."""
        from services.metrics import REGISTRY
        assert REGISTRY is not None

    def test_http_requests_counter_importable(self):
        """http_requests_total (Counter) doit être importable."""
        from services.metrics import http_requests_total
        assert http_requests_total is not None

    def test_http_duration_histogram_importable(self):
        """http_request_duration_seconds (Histogram) doit être importable."""
        from services.metrics import http_request_duration_seconds
        assert http_request_duration_seconds is not None

    def test_packages_gauge_importable(self):
        """packages_total (Gauge) doit être importable."""
        from services.metrics import packages_total
        assert packages_total is not None

    def test_vulnerabilities_gauge_importable(self):
        """vulnerabilities_total (Gauge) doit être importable."""
        from services.metrics import vulnerabilities_total
        assert vulnerabilities_total is not None

    def test_uploads_counter_importable(self):
        """uploads_total (Counter) doit être importable."""
        from services.metrics import uploads_total
        assert uploads_total is not None


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Noms et labels des métriques
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetricDefinitions:
    """Vérifie les noms Prometheus et les labels attendus."""

    def test_http_requests_counter_has_correct_name(self):
        """repod_http_requests_total doit apparaître dans la sortie generate_latest."""
        from services.metrics import http_requests_total, REGISTRY
        from prometheus_client import generate_latest
        # NOTE : prometheus_client stocke '_name' sans le suffixe '_total' pour les
        # Counters (ex. Counter("repod_http_requests_total", ...)._name == "repod_http_requests").
        # Le '_total' est réajouté automatiquement dans generate_latest().
        # On vérifie donc le nom tel qu'il apparaît dans la sortie Prometheus.
        output = generate_latest(REGISTRY).decode()
        assert "repod_http_requests_total" in output, (
            f"'repod_http_requests_total' absent de la sortie Prometheus :\n{output}"
        )

    def test_http_requests_counter_has_method_label(self):
        """Le compteur HTTP doit avoir le label 'method'."""
        from services.metrics import http_requests_total
        assert "method" in http_requests_total._labelnames

    def test_http_requests_counter_has_path_label(self):
        """Le compteur HTTP doit avoir le label 'path'."""
        from services.metrics import http_requests_total
        assert "path" in http_requests_total._labelnames

    def test_http_requests_counter_has_status_code_label(self):
        """Le compteur HTTP doit avoir le label 'status_code'."""
        from services.metrics import http_requests_total
        assert "status_code" in http_requests_total._labelnames

    def test_http_duration_histogram_name(self):
        """repod_http_request_duration_seconds doit être le nom exact."""
        from services.metrics import http_request_duration_seconds
        name = http_request_duration_seconds._name
        assert name == "repod_http_request_duration_seconds"

    def test_http_duration_histogram_labels(self):
        """L'histogramme de durée doit avoir method et path."""
        from services.metrics import http_request_duration_seconds
        assert "method" in http_request_duration_seconds._labelnames
        assert "path" in http_request_duration_seconds._labelnames

    def test_packages_gauge_name(self):
        """repod_packages_total doit être le nom exact."""
        from services.metrics import packages_total
        assert packages_total._name == "repod_packages_total"

    def test_vulnerabilities_gauge_name(self):
        """repod_vulnerabilities_total doit être le nom exact."""
        from services.metrics import vulnerabilities_total
        assert vulnerabilities_total._name == "repod_vulnerabilities_total"

    def test_uploads_counter_name(self):
        """repod_uploads_total doit apparaître dans la sortie generate_latest."""
        from services.metrics import REGISTRY
        from prometheus_client import generate_latest
        output = generate_latest(REGISTRY).decode()
        assert "repod_uploads_total" in output

    def test_metrics_use_isolated_registry(self):
        """
        Les métriques doivent utiliser un registry isolé (pas le global).
        Évite les erreurs 'duplicate metric' entre tests.
        """
        from prometheus_client import REGISTRY as DEFAULT_REGISTRY
        from services.metrics import REGISTRY
        assert REGISTRY is not DEFAULT_REGISTRY, (
            "services.metrics doit utiliser un CollectorRegistry() isolé, "
            "pas le registry global prometheus_client.REGISTRY"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Middleware — services/middleware/metrics_middleware.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetricsMiddlewareExists:
    """
    ❌ ROUGE avant fix : middleware/metrics_middleware.py n'existe pas
    ✅ VERT après fix  : middleware présent et importable
    """

    def test_middleware_file_exists(self):
        """middleware/metrics_middleware.py doit exister."""
        p = Path(__file__).parent.parent / "middleware" / "metrics_middleware.py"
        assert p.exists(), "middleware/metrics_middleware.py doit être créé (P3-B)"

    def test_metrics_middleware_importable(self):
        """MetricsMiddleware doit être importable."""
        from middleware.metrics_middleware import MetricsMiddleware
        assert MetricsMiddleware is not None

    def test_metrics_middleware_is_class(self):
        """MetricsMiddleware doit être une classe."""
        from middleware.metrics_middleware import MetricsMiddleware
        assert isinstance(MetricsMiddleware, type)

    def test_metrics_middleware_has_dispatch(self):
        """MetricsMiddleware doit implémenter dispatch (BaseHTTPMiddleware)."""
        from middleware.metrics_middleware import MetricsMiddleware
        assert hasattr(MetricsMiddleware, "dispatch")


class TestMetricsMiddlewareBehavior:
    """
    Vérifie que le middleware alimente réellement les compteurs.

    Ces tests portaient un marqueur @pytest.mark.asyncio alors que
    pytest-asyncio n'est pas une dépendance du projet : ils étaient donc
    ignorés, puis en échec à partir de pytest 8.4. Leur corps était pourtant
    entièrement synchrone, TestClient l'étant. Ils n'assertaient que
    la présence du *nom* de la métrique dans generate_latest(), vraie dès la
    déclaration du collecteur, sans qu'aucune requête n'ait eu lieu : ils
    auraient validé un middleware totalement inerte.

    Ils comparent désormais des deltas sur l'échantillon exact. Le registre
    (services/metrics.py) est cumulatif sur toute la session pytest, une valeur
    absolue serait donc dépendante de l'ordre d'exécution.
    """

    @staticmethod
    def _app(chemin: str):
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route

        from middleware.metrics_middleware import MetricsMiddleware

        async def homepage(request: Request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route(chemin, homepage)])
        app.add_middleware(MetricsMiddleware)
        return app

    @staticmethod
    def _valeur(nom: str, labels: dict) -> float:
        from services.metrics import REGISTRY

        return REGISTRY.get_sample_value(nom, labels) or 0.0

    # Une app Starlette nue ne renseigne jamais scope["route"] : seul
    # fastapi.routing.APIRoute.matches() le pose. Le middleware se replie donc
    # ici sur sa constante, et non sur « /ping ». La normalisation en gabarit de
    # route est couverte sur une app FastAPI dans
    # tests/test_metrics_public_exposure.py.
    _PATH_ATTENDU = "__unmatched__"

    def test_middleware_increments_request_counter(self):
        """Après une requête, repod_http_requests_total gagne exactement 1."""
        from starlette.testclient import TestClient

        labels = {"method": "GET", "path": self._PATH_ATTENDU, "status_code": "200"}
        avant = self._valeur("repod_http_requests_total", labels)

        TestClient(self._app("/ping")).get("/ping")

        apres = self._valeur("repod_http_requests_total", labels)
        assert apres == avant + 1, (
            f"le compteur devait passer de {avant} à {avant + 1}, obtenu {apres}"
        )

    def test_middleware_records_duration(self):
        """Après une requête, l'histogramme de durée enregistre une observation."""
        from starlette.testclient import TestClient

        labels = {"method": "GET", "path": self._PATH_ATTENDU}
        avant = self._valeur("repod_http_request_duration_seconds_count", labels)

        TestClient(self._app("/probe")).get("/probe")

        apres = self._valeur("repod_http_request_duration_seconds_count", labels)
        assert apres == avant + 1, (
            f"l'histogramme devait enregistrer une observation, "
            f"compteur passé de {avant} à {apres}"
        )

    def test_middleware_source_imports_metrics(self):
        """Le middleware doit importer les métriques depuis services.metrics."""
        src = (Path(__file__).parent.parent / "middleware" / "metrics_middleware.py").read_text()
        assert "services.metrics" in src or "from services" in src


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Router /metrics — source inspection
# ═══════════════════════════════════════════════════════════════════════════════

class TestMetricsRouterExists:
    """
    ❌ ROUGE avant fix : routers/metrics_router.py n'existe pas
    ✅ VERT après fix  : router présent
    """

    @staticmethod
    def _src() -> str:
        return (Path(__file__).parent.parent / "routers" / "metrics_router.py").read_text()

    def test_metrics_router_file_exists(self):
        """routers/metrics_router.py doit exister."""
        p = Path(__file__).parent.parent / "routers" / "metrics_router.py"
        assert p.exists(), "routers/metrics_router.py doit être créé (P3-B)"

    def test_metrics_route_defined(self):
        """GET /metrics doit être défini dans metrics_router.py."""
        src = self._src()
        assert '"/metrics"' in src or "'/metrics'" in src, (
            "metrics_router.py doit définir GET /metrics"
        )

    def test_generate_latest_used(self):
        """generate_latest() doit être appelé pour produire le format Prometheus."""
        src = self._src()
        assert "generate_latest" in src

    def test_content_type_prometheus(self):
        """Le router doit utiliser le Content-Type Prometheus (CONTENT_TYPE_LATEST)."""
        src = self._src()
        assert "CONTENT_TYPE_LATEST" in src or "text/plain" in src

    def test_pas_de_garde_utilisateur_generique(self):
        """
        /metrics ne doit pas être gardé par get_current_user.

        Un scraper Prometheus ne présente pas de session utilisateur : sa
        créance est dédiée (METRICS_TOKEN), avec un JWT de rôle d'audit comme
        alternative. Gater l'endpoint sur « tout utilisateur authentifié »
        casserait le scrape sans rien protéger de plus.

        Le contrat d'authentification complet, y compris le repli anonyme quand
        METRICS_TOKEN n'est pas défini, est testé sur le comportement réel dans
        tests/test_metrics_public_exposure.py.
        """
        src = self._src()
        assert "get_current_user" not in src, (
            "/metrics ne doit pas dépendre de get_current_user : la créance de "
            "scrape est METRICS_TOKEN, ou à défaut un JWT de rôle d'audit"
        )


class TestMetricsEndpointResponse:
    """
    Vérifie le format de la réponse /metrics.

    NOTE : on ne peut pas importer directement 'from routers.metrics_router import router'
    car cela déclenche routers/__init__.py qui importe upload.py → services.indexer
    → tente de créer /repos (permission denied hors Docker).
    On teste donc via generate_latest(REGISTRY) et via source inspection.
    """

    def test_metrics_endpoint_returns_200(self):
        """GET /metrics → 200 OK (ASGI minimale, sans routers/__init__.py)."""
        import importlib.util
        from pathlib import Path as _Path
        from fastapi import FastAPI
        from starlette.testclient import TestClient

        # Import direct du module sans passer par le package routers/
        spec = importlib.util.spec_from_file_location(
            "metrics_router_direct",
            _Path(__file__).parent.parent / "routers" / "metrics_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        app = FastAPI()
        app.include_router(mod.router)

        resp = TestClient(app).get("/metrics")
        assert resp.status_code == 200

    def test_metrics_endpoint_content_type(self):
        """GET /metrics → Content-Type contient 'text/plain'."""
        import importlib.util
        from pathlib import Path as _Path
        from fastapi import FastAPI
        from starlette.testclient import TestClient

        spec = importlib.util.spec_from_file_location(
            "metrics_router_direct2",
            _Path(__file__).parent.parent / "routers" / "metrics_router.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        app = FastAPI()
        app.include_router(mod.router)

        resp = TestClient(app).get("/metrics")
        assert "text/plain" in resp.headers.get("content-type", ""), (
            f"Content-Type attendu 'text/plain', obtenu : {resp.headers.get('content-type')!r}"
        )

    def test_metrics_output_is_prometheus_format(self):
        """La sortie generate_latest contient les métriques repod_ au format Prometheus."""
        from services.metrics import REGISTRY
        from prometheus_client import generate_latest
        body = generate_latest(REGISTRY).decode()
        # Format Prometheus : au moins une ligne # HELP ou # TYPE ou repod_
        assert "# HELP" in body or "# TYPE" in body or "repod_" in body, (
            f"La sortie Prometheus semble vide ou mal formatée :\n{body!r}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Intégration main.py — source inspection
# ═══════════════════════════════════════════════════════════════════════════════

class TestMainIntegration:
    """Vérifie que main.py intègre les métriques."""

    @staticmethod
    def _main_src() -> str:
        return (Path(__file__).parent.parent / "main.py").read_text()

    def test_metrics_middleware_imported_in_main(self):
        """
        ❌ ROUGE avant fix : MetricsMiddleware absent de main.py
        ✅ VERT après fix  : MetricsMiddleware importé et ajouté
        """
        src = self._main_src()
        assert "MetricsMiddleware" in src, (
            "main.py doit importer et ajouter MetricsMiddleware"
        )

    def test_metrics_router_imported_in_main(self):
        """metrics_router doit être inclus dans main.py."""
        src = self._main_src()
        assert "metrics_router" in src or "metrics" in src

    def test_metrics_endpoint_not_versioned(self):
        """
        /metrics ne doit PAS avoir le préfixe /api/v1
        (endpoint infra, comme /health).
        """
        src = self._main_src()
        # Le router metrics ne doit pas apparaître avec API_V1
        # On vérifie que metrics_router n'est pas inclus avec prefix=API_V1
        # Heuristique : si 'metrics_router' apparaît dans une ligne contenant API_V1 → KO
        lines = src.splitlines()
        for line in lines:
            if "metrics_router" in line and "API_V1" in line and "prefix" in line:
                pytest.fail(
                    f"metrics_router ne doit pas utiliser le préfixe API_V1 :\n{line}"
                )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. requirements.txt
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequirements:
    """prometheus-client doit être dans les dépendances."""

    def test_prometheus_client_in_requirements(self):
        """
        ❌ ROUGE avant fix : prometheus-client absent de requirements.txt
        ✅ VERT après fix  : dépendance présente
        """
        req = (Path(__file__).parent.parent / "requirements.txt").read_text()
        assert "prometheus-client" in req, (
            "prometheus-client doit être dans requirements.txt"
        )

    def test_prometheus_client_importable(self):
        """prometheus_client doit être installé dans l'environnement de test."""
        import prometheus_client
        assert prometheus_client is not None
