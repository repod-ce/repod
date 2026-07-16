"""
services/metrics.py — P3-B : Métriques Prometheus pour repod

Registry isolé (CollectorRegistry) pour éviter les conflits avec le registry
global prometheus_client.REGISTRY (important en tests et multi-process).

Métriques exposées :
  repod_http_requests_total          Counter  {method, path, status_code}
  repod_http_request_duration_seconds Histogram {method, path}
  repod_packages_total               Gauge    {distribution, arch}
  repod_vulnerabilities_total        Gauge    {severity}
  repod_uploads_total                Counter  {status}

Usage :
  from services.metrics import http_requests_total, REGISTRY
  from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
  data = generate_latest(REGISTRY)
"""

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

# ── Registry isolé ────────────────────────────────────────────────────────────
# N'utilise PAS le registry global (prometheus_client.REGISTRY) pour éviter :
#   • erreurs "duplicate metric" en tests (importlib.reload, fixtures)
#   • conflits en mode multi-process avec PROMETHEUS_MULTIPROC_DIR

REGISTRY = CollectorRegistry(auto_describe=True)

# ── Métriques HTTP (alimentées par MetricsMiddleware) ─────────────────────────

http_requests_total = Counter(
    "repod_http_requests_total",
    "Nombre total de requêtes HTTP reçues par repod",
    ["method", "path", "status_code"],
    registry=REGISTRY,
)

http_request_duration_seconds = Histogram(
    "repod_http_request_duration_seconds",
    "Durée des requêtes HTTP en secondes",
    ["method", "path"],
    # Buckets adaptés à une API REST (ms → secondes)
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    registry=REGISTRY,
)

# ── Métriques métier (Gauges — mises à jour périodiquement) ───────────────────

packages_total = Gauge(
    "repod_packages_total",
    "Nombre de paquets dans le dépôt",
    ["distribution", "arch"],
    registry=REGISTRY,
)

vulnerabilities_total = Gauge(
    "repod_vulnerabilities_total",
    "Nombre de vulnérabilités détectées (par sévérité)",
    ["severity"],
    registry=REGISTRY,
)

# ── Métriques d'activité ──────────────────────────────────────────────────────

uploads_total = Counter(
    "repod_uploads_total",
    "Nombre total d'uploads de paquets",
    ["status"],    # status ∈ {success, failure}
    registry=REGISTRY,
)


# ── Helpers de mise à jour ────────────────────────────────────────────────────

def update_packages_gauge(manifests: list[dict]) -> None:
    """
    Met à jour la Gauge repod_packages_total depuis une liste de manifests.
    Appeler après chaque modification de l'inventaire.
    """
    counts: dict[tuple[str, str], int] = {}
    for m in manifests:
        key = (m.get("distribution", "unknown"), m.get("arch", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    for (distrib, arch), n in counts.items():
        packages_total.labels(distribution=distrib, arch=arch).set(n)


def update_vulnerabilities_gauge(manifests: list[dict]) -> None:
    """
    Met à jour la Gauge repod_vulnerabilities_total depuis une liste de manifests.
    Appeler après chaque scan de vulnérabilités.
    """
    counts: dict[str, int] = {}
    for m in manifests:
        for cve in m.get("cve_results") or []:
            sev = (cve.get("severity") or "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
    for sev, n in counts.items():
        vulnerabilities_total.labels(severity=sev).set(n)
