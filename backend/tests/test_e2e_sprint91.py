"""
tests/test_e2e_sprint91.py — Tests d'intégration E2E Sprint 9.1

Scénarios end-to-end complets — workflow RSSI de promotion de paquets.
Couverture :

  E2E-1 — promote → pending_review → approve   (workflow RSSI complet)
  E2E-2 — promote → pending_review → reject    (rejet formel RSSI)
  E2E-3 — promote bloquée par CVE critical     (409 blocked)
  E2E-4 — promote directe sans pending         (200 approved)
  E2E-5 — RBAC : maintainer peut promouvoir, pas approuver (403)
  E2E-6 — RBAC : viewer ne peut rien faire (403)
  E2E-7 — Sécurité : path traversal sur pending_id (404, pas 500)
  E2E-8 — Sécurité : MFA token rejeté sur endpoints protégés (401)
  E2E-9 — Liste & filtrage des demandes (total, statut, pagination)
  E2E-10 — Double approbation (idempotence → 409 conflit)
  E2E-11 — Approve demande déjà rejetée (409)
  E2E-12 — Approve avec justification vide (400)
  E2E-13 — Reject sans motif (400)
  E2E-14 — Promote → approve → re-évaluation blocked bloque l'approbation (409)

Architecture :
  - TestClient FastAPI avec router artifacts chargé via importlib
  - Mocks ciblés : reprepro (I/O système), notify, audit, get_package_info
  - pending_promotions CRUD réel (répertoire temp isolé par test)
  - JWT auth réel pour E2E-5/6/7/8, dependency_overrides pour le reste
"""

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call

# ── Configuration de l'environnement AVANT tout import ───────────────────────
_TMP = tempfile.mkdtemp(prefix="repod_e2e91_")
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending_e2e"))
os.environ.setdefault("AUTH_DB_PATH",    os.path.join(_TMP, "users.db"))
os.environ.setdefault("MANIFEST_DIR",    _TMP)
os.environ.setdefault("MANIFEST_DB",     os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",        _TMP)
os.environ.setdefault("AUDIT_DIR",       _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",  os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",      os.path.join(_TMP, "index.json"))
os.environ.setdefault("INVENTORY_DB",    os.path.join(_TMP, "inv.db"))
os.environ.setdefault("JWT_SECRET_KEY",  "test-secret-e2e-sprint91")

import pytest

# ── Fixtures partagées ────────────────────────────────────────────────────────

# Paquet fictif retourné par get_package_info
FAKE_PKG_INFO = {
    "latest":   "1.24.0",
    "versions": {
        "1.24.0": {
            "arch":        "amd64",
            "sha256":      "abc123",
            "size_bytes":  100_000,
            "imported_at": "2026-01-01T00:00:00+00:00",
            "imported_by": "ci_pipeline",
            "status":      "validated",
            "distribution": "jammy",
            "cve_summary": {
                "critical": 0,
                "high":     1,
                "medium":   0,
                "low":      0,
                "negligible": 0,
            },
        }
    },
}

# Verdicts CVE prédéfinis
VERDICT_PENDING = {
    "verdict":   "pending_review",
    "reason":    "CVE HIGH détectée (CVE-2026-9999)",
    "reviewing": ["CVE-2026-9999"],
    "warnings":  [],
    "blocking":  [],
}
VERDICT_BLOCKED = {
    "verdict":   "blocked",
    "reason":    "CVE CRITICAL détectée (CVE-2026-0001)",
    "reviewing": [],
    "warnings":  [],
    "blocking":  ["CVE-2026-0001"],
}
VERDICT_APPROVED = {
    "verdict":   "approved",
    "reason":    "Aucune CVE bloquante",
    "reviewing": [],
    "warnings":  [],
    "blocking":  [],
}


# ── Chargement du router artifacts ───────────────────────────────────────────

def _load_artifacts_module():
    spec = importlib.util.spec_from_file_location(
        "artifacts_router_e2e",
        str(Path(__file__).parent.parent / "routers" / "artifacts.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["artifacts_router_e2e"] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from slowapi.errors import RateLimitExceeded
    from limiter import limiter
    from services.rate_limits import rate_limit_exceeded_handler
    from auth.dependencies import (
        get_admin_user,
        get_maintainer_user,
        get_current_user,
    )
    from auth.jwt import create_access_token, create_mfa_token

    _artifacts = _load_artifacts_module()

    # ── Application principale (dependency overrides) ─────────────────────────
    _app = FastAPI()
    _app.state.limiter = limiter
    _app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    _app.include_router(_artifacts.router)
    _app.dependency_overrides[get_admin_user]       = lambda: "rssi_admin"
    _app.dependency_overrides[get_maintainer_user]  = lambda: "maintainer_alice"

    _client = TestClient(_app, raise_server_exceptions=False)

    # ── Application JWT réelle (pour tests RBAC/MFA) ──────────────────────────
    _app_jwt = FastAPI()
    _app_jwt.state.limiter = limiter
    _app_jwt.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    _app_jwt.include_router(_artifacts.router)

    _client_jwt = TestClient(_app_jwt, raise_server_exceptions=False)

    _E2E_AVAILABLE = True
except Exception as _exc:
    _E2E_AVAILABLE = False
    _exc_info = str(_exc)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _admin_headers():
    """JWT avec rôle admin pour _client_jwt."""
    tok = create_access_token({"sub": "rssi_admin", "role": "admin"})
    return {"Authorization": f"Bearer {tok}"}


def _maintainer_headers():
    """JWT avec rôle maintainer pour _client_jwt."""
    tok = create_access_token({"sub": "alice_maint", "role": "maintainer"})
    return {"Authorization": f"Bearer {tok}"}


def _viewer_headers():
    """JWT avec rôle reader pour _client_jwt."""
    tok = create_access_token({"sub": "bob_viewer", "role": "reader"})
    return {"Authorization": f"Bearer {tok}"}


def _mfa_headers():
    """Token MFA intermédiaire (scope=mfa_required) — doit être rejeté."""
    tok = create_mfa_token("carol", "admin")
    return {"Authorization": f"Bearer {tok}"}


def _fake_user(username: str, role: str = "admin") -> dict:
    """Faux utilisateur actif pour mocker auth.users.get_user."""
    return {"username": username, "role": role, "active": 1, "full_name": username}


# ── Fixture d'isolation du répertoire pending ─────────────────────────────────

@pytest.fixture
def isolated_pending(tmp_path):
    """
    Remplace PENDING_DIR par un répertoire temp isolé pour chaque test.
    Garantit que les tests E2E ne se polluent pas entre eux.
    """
    import services.pending_promotions as pp
    new_dir = tmp_path / "pending"
    new_dir.mkdir()
    orig = pp.PENDING_DIR
    pp.PENDING_DIR = new_dir
    yield new_dir
    pp.PENDING_DIR = orig


# ── Mocks de base : I/O externe systématiquement neutralisé ──────────────────

BASE_PATCHES = [
    patch("services.indexer.get_package_info", return_value=FAKE_PKG_INFO),
    patch("services.audit.log"),
    patch("services.notifications.notify"),
]


def _apply_base_patches():
    """Retourne un stack de context managers pour les mocks de base."""
    from contextlib import ExitStack
    stack = ExitStack()
    for p in BASE_PATCHES:
        stack.enter_context(p)
    return stack


# ═════════════════════════════════════════════════════════════════════════════
# E2E-1 — promote → pending_review → approve (workflow complet RSSI)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EWorkflowApprove:
    """Flux complet : un mainteneur promeut, le RSSI approuve."""

    def test_promote_returns_202_with_pending_id(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                resp = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["status"] == "pending_review"
        assert "pending_promotion_id" in body
        assert body["package"] == "nginx"

    def test_pending_record_exists_in_list(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
            pending_id = r.json()["pending_promotion_id"]

        resp = _client.get("/artifacts/admin/pending-promotions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        # body["items"] est le dict retourné par paginate() ; les éléments sont dans ["items"]["items"]
        ids = [item["id"] for item in body["items"]["items"]]
        assert pending_id in ids

    def test_approve_returns_200_and_status_approved(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "Promoted OK")):

                # Étape 1 : promote → 202
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                assert r.status_code == 202, r.text
                pending_id = r.json()["pending_promotion_id"]

                # Étape 2 : approve → 200
                r2 = _client.post(
                    f"/artifacts/nginx/promote/{pending_id}/approve",
                    json={"justification": "Revue CVE effectuée — risque acceptable.", "reason": ""},
                )
        assert r2.status_code == 200, r2.text
        body = r2.json()
        assert body["status"] == "approved"
        assert body["pending_id"] == pending_id
        assert body["approved_by"] == "rssi_admin"

    def test_approved_record_visible_in_filtered_list(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "Promoted OK")):

                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pending_id = r.json()["pending_promotion_id"]

                _client.post(
                    f"/artifacts/nginx/promote/{pending_id}/approve",
                    json={"justification": "OK", "reason": ""},
                )

        # La liste filtrée "approved" doit contenir notre demande
        resp = _client.get("/artifacts/admin/pending-promotions?status=approved")
        assert resp.status_code == 200
        ids = [item["id"] for item in resp.json()["items"]["items"]]
        assert pending_id in ids

    def test_pending_list_empty_after_approve(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "Promoted OK")):

                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pending_id = r.json()["pending_promotion_id"]
                _client.post(
                    f"/artifacts/nginx/promote/{pending_id}/approve",
                    json={"justification": "Approuvé", "reason": ""},
                )

        resp = _client.get("/artifacts/admin/pending-promotions?status=pending")
        body = resp.json()
        pending_ids = [item["id"] for item in body["items"]["items"]]
        assert pending_id not in pending_ids


# ═════════════════════════════════════════════════════════════════════════════
# E2E-2 — promote → pending_review → reject (rejet RSSI)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EWorkflowReject:
    """Flux complet : un mainteneur promeut, le RSSI rejette."""

    def test_reject_returns_200_and_status_rejected(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/curl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                assert r.status_code == 202, r.text
                pending_id = r.json()["pending_promotion_id"]

            r2 = _client.post(
                f"/artifacts/curl/promote/{pending_id}/reject",
                json={"justification": "", "reason": "CVE-2026-9999 non corrigée — risque inacceptable."},
            )
        assert r2.status_code == 200, r2.text
        body = r2.json()
        assert body["status"] == "rejected"
        assert body["pending_id"] == pending_id
        assert body["rejected_by"] == "rssi_admin"

    def test_rejected_record_visible_in_filtered_list(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/curl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pending_id = r.json()["pending_promotion_id"]

            _client.post(
                f"/artifacts/curl/promote/{pending_id}/reject",
                json={"justification": "", "reason": "Non validé."},
            )

        resp = _client.get("/artifacts/admin/pending-promotions?status=rejected")
        ids = [item["id"] for item in resp.json()["items"]["items"]]
        assert pending_id in ids

    def test_reject_without_reason_returns_400(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/curl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pending_id = r.json()["pending_promotion_id"]

            r2 = _client.post(
                f"/artifacts/curl/promote/{pending_id}/reject",
                json={"justification": "", "reason": ""},  # motif vide → 400
            )
        assert r2.status_code == 400


# ═════════════════════════════════════════════════════════════════════════════
# E2E-3 — Promote bloquée par CVE critical (409)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EPromoteBlocked:
    """La politique CVE bloque totalement la promotion."""

    def test_blocked_returns_409(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                resp = _client.post(
                    "/artifacts/openssl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 409

    def test_blocked_response_contains_policy_verdict(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                resp = _client.post(
                    "/artifacts/openssl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        body = resp.json()
        assert "policy_verdict" in body.get("detail", body)

    def test_blocked_creates_no_pending_record(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                _client.post(
                    "/artifacts/openssl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )

        resp = _client.get("/artifacts/admin/pending-promotions?status=pending")
        total = resp.json()["total"]
        assert total == 0, f"Aucun enregistrement pending ne doit exister (got {total})"

    def test_force_true_does_not_bypass_blocked(self, isolated_pending):
        """force=True ne contourne JAMAIS le niveau blocked (CVE critiques)."""
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                resp = _client.post(
                    "/artifacts/openssl/promote",
                    json={"from_dist": "jammy", "to_dist": "noble",
                          "force": True, "justification": "Force quand même"},
                )
        assert resp.status_code == 409


# ═════════════════════════════════════════════════════════════════════════════
# E2E-4 — Promote directe (200 approved, sans pending)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EPromoteDirect:
    """Pas de CVE bloquante → promotion immédiate (approved)."""

    def test_direct_promote_returns_200(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_APPROVED), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "nginx 1.24.0 promoted")):
                resp = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "approved"

    def test_direct_promote_creates_no_pending_record(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_APPROVED), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "OK")):
                _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )

        resp = _client.get("/artifacts/admin/pending-promotions?status=pending")
        assert resp.json()["total"] == 0

    def test_already_present_returns_200(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_APPROVED), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "nginx already present in noble")):
                resp = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_present"

    def test_reprepro_failure_returns_400(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_APPROVED), \
                 patch("services.distributions.promote_package",
                       return_value=(False, "reprepro: error copying package")):
                resp = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 400
        assert "reprepro" in resp.json()["detail"].lower()


# ═════════════════════════════════════════════════════════════════════════════
# E2E-5 & 6 — RBAC : contrôle d'accès par rôle
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2ERbac:
    """Vérification de la matrice RBAC sur les endpoints de promotion."""

    def test_maintainer_can_promote(self, isolated_pending):
        """Le mainteneur peut déclencher une promotion."""
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                resp = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 202

    def test_maintainer_cannot_approve(self, isolated_pending):
        """Le mainteneur ne peut PAS approuver (réservé admin/RSSI).
        Un token maintainer valide → 403 sur l'endpoint approve (admin-only).
        """
        # Créer un pending avec le client admin global
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
            pending_id = r.json()["pending_promotion_id"]

            # Token maintainer valide → _require_role lève 403 (role≠admin)
            with patch("auth.dependencies.get_user",
                       side_effect=lambda u: _fake_user(u, role="maintainer")):
                r2 = _client_jwt.post(
                    f"/artifacts/nginx/promote/{pending_id}/approve",
                    json={"justification": "Je m'auto-approuve", "reason": ""},
                    headers=_maintainer_headers(),
                )
        assert r2.status_code == 403

    def test_maintainer_cannot_reject(self, isolated_pending):
        """Le mainteneur ne peut PAS rejeter (réservé admin/RSSI)."""
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
            pending_id = r.json()["pending_promotion_id"]

            with patch("auth.dependencies.get_user",
                       side_effect=lambda u: _fake_user(u, role="maintainer")):
                r2 = _client_jwt.post(
                    f"/artifacts/nginx/promote/{pending_id}/reject",
                    json={"justification": "", "reason": "Auto-rejet"},
                    headers=_maintainer_headers(),
                )
        assert r2.status_code == 403

    def test_viewer_cannot_promote(self, isolated_pending):
        """Un viewer ne peut pas déclencher de promotion."""
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("auth.dependencies.get_user",
                       side_effect=lambda u: _fake_user(u, role="reader")):
                resp = _client_jwt.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                    headers=_viewer_headers(),
                )
        assert resp.status_code == 403


# ═════════════════════════════════════════════════════════════════════════════
# E2E-7 — Sécurité : path traversal sur pending_id (SEC-2)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2ESecurityPathTraversal:
    """
    Vérifie que l'endpoint /approve ne peut pas être exploité avec
    un pending_id malformé pour traverser le système de fichiers.
    SEC-2 — La validation UUID v4 bloque toute tentative.
    """

    @pytest.mark.parametrize("bad_id", [
        "000e8400-e29b-41d4-a716-000000000000",   # UUID v4 syntaxiquement valide mais inexistant
        "not-a-uuid-at-all",
        "../etc/passwd",
        "../../shadow",
    ])
    def test_traversal_approve_returns_404_not_500(self, bad_id, isolated_pending):
        """Un pending_id invalide ou inexistant → 404, jamais 500."""
        resp = _client.post(
            f"/artifacts/nginx/promote/{bad_id}/approve",
            json={"justification": "test", "reason": ""},
        )
        # 404 (non trouvé), 422 (validation FastAPI) ou 405 (URL normalisée
        # par le client HTTP, ex. ../../shadow → autre route) sont acceptables.
        # L'important : pas de 500 (traversal réussi ou exception non gérée)
        assert resp.status_code in (404, 405, 422), (
            f"bad_id={bad_id!r} → status={resp.status_code} (attendu 404, 405 ou 422)"
        )

    @pytest.mark.parametrize("bad_id", [
        "000e8400-e29b-41d4-a716-000000000000",
        "not-a-uuid-at-all",
        "../etc/passwd",
    ])
    def test_traversal_reject_returns_404_not_500(self, bad_id, isolated_pending):
        """Même protection sur l'endpoint reject."""
        resp = _client.post(
            f"/artifacts/nginx/promote/{bad_id}/reject",
            json={"justification": "", "reason": "test"},
        )
        assert resp.status_code in (404, 405, 422)

    def test_nonexistent_but_valid_uuid_returns_404(self, isolated_pending):
        """UUID v4 valide mais absent → 404 propre (pas d'exception non gérée)."""
        fake_id = "550e8400-e29b-41d4-a716-446655440000"
        resp = _client.post(
            f"/artifacts/nginx/promote/{fake_id}/approve",
            json={"justification": "test", "reason": ""},
        )
        assert resp.status_code == 404


# ═════════════════════════════════════════════════════════════════════════════
# E2E-8 — Sécurité : MFA token rejeté (SEC-1)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2ESecurityMfaToken:
    """
    Un token MFA intermédiaire (scope=mfa_required) ne doit PAS donner accès
    aux endpoints de promotion/approve/reject.
    SEC-1 — decode_token rejette scope=mfa_required.
    """

    def test_mfa_token_rejected_on_promote(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                resp = _client_jwt.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                    headers=_mfa_headers(),
                )
        assert resp.status_code == 401

    def test_mfa_token_rejected_on_approve(self, isolated_pending):
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        resp = _client_jwt.post(
            f"/artifacts/nginx/promote/{fake_uuid}/approve",
            json={"justification": "test", "reason": ""},
            headers=_mfa_headers(),
        )
        assert resp.status_code == 401

    def test_mfa_token_rejected_on_reject(self, isolated_pending):
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        resp = _client_jwt.post(
            f"/artifacts/nginx/promote/{fake_uuid}/reject",
            json={"justification": "", "reason": "test"},
            headers=_mfa_headers(),
        )
        assert resp.status_code == 401

    def test_mfa_token_rejected_on_list(self, isolated_pending):
        resp = _client_jwt.get(
            "/artifacts/admin/pending-promotions",
            headers=_mfa_headers(),
        )
        assert resp.status_code == 401

    def test_valid_admin_token_accepted_on_list(self, isolated_pending):
        """Contrôle : un token valide admin est accepté."""
        # Patcher auth.dependencies.get_user (référence dans le module dependencies)
        with patch("auth.dependencies.get_user",
                   side_effect=lambda u: _fake_user(u, role="admin")):
            resp = _client_jwt.get(
                "/artifacts/admin/pending-promotions",
                headers=_admin_headers(),
            )
        assert resp.status_code == 200


# ═════════════════════════════════════════════════════════════════════════════
# E2E-9 — Liste & filtrage des demandes
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EListAndFilter:
    """Vérification des endpoints de liste et de filtrage."""

    def test_list_empty_initially(self, isolated_pending):
        resp = _client.get("/artifacts/admin/pending-promotions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        # body["items"] est le dict paginate() ; les éléments réels sont dans ["items"]["items"]
        assert body["items"]["items"] == []

    def test_list_structure(self, isolated_pending):
        resp = _client.get("/artifacts/admin/pending-promotions")
        body = resp.json()
        assert "total" in body
        assert "items" in body
        assert "status" in body

    def test_filter_pending_after_promotion(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                for pkg in ["pkgA", "pkgB"]:
                    _client.post(
                        f"/artifacts/{pkg}/promote",
                        json={"from_dist": "jammy", "to_dist": "noble"},
                    )

        resp = _client.get("/artifacts/admin/pending-promotions?status=pending")
        body = resp.json()
        assert body["total"] == 2

    def test_filter_all_shows_all_statuses(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "OK")):

                # Créer 2 demandes
                r1 = _client.post("/artifacts/pkgC/promote",
                                  json={"from_dist": "jammy", "to_dist": "noble"})
                r2 = _client.post("/artifacts/pkgD/promote",
                                  json={"from_dist": "jammy", "to_dist": "noble"})
                id1 = r1.json()["pending_promotion_id"]
                id2 = r2.json()["pending_promotion_id"]

                # Approuver la première
                _client.post(
                    f"/artifacts/pkgC/promote/{id1}/approve",
                    json={"justification": "OK", "reason": ""},
                )
                # Rejeter la seconde
                _client.post(
                    f"/artifacts/pkgD/promote/{id2}/reject",
                    json={"justification": "", "reason": "Refus."},
                )

        # status=all (ou pas de filtre) doit tout montrer
        resp = _client.get("/artifacts/admin/pending-promotions?status=all")
        body = resp.json()
        assert body["total"] >= 2
        statuses = {item["id"]: item["status"] for item in body["items"]["items"]}
        assert statuses.get(id1) == "approved"
        assert statuses.get(id2) == "rejected"

    def test_pagination_per_page(self, isolated_pending):
        """per_page=1 ne doit retourner qu'un seul élément."""
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                for pkg in ["pkg1", "pkg2", "pkg3"]:
                    _client.post(
                        f"/artifacts/{pkg}/promote",
                        json={"from_dist": "jammy", "to_dist": "noble"},
                    )

        resp = _client.get("/artifacts/admin/pending-promotions?per_page=1")
        body = resp.json()
        assert body["total"] == 3
        assert len(body["items"]["items"]) == 1


# ═════════════════════════════════════════════════════════════════════════════
# E2E-10 & 11 — Idempotence : double décision (409 conflit)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EIdempotence:
    """Une demande déjà décidée ne peut pas être re-décidée (409)."""

    def test_double_approve_returns_409(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "OK")):

                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

                # Première approbation → 200
                r1 = _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "Approuvé 1x", "reason": ""},
                )
                assert r1.status_code == 200

                # Deuxième approbation → 409 (déjà décidée)
                r2 = _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "Approuvé 2x", "reason": ""},
                )
        assert r2.status_code == 409

    def test_approve_then_reject_returns_409(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING), \
                 patch("services.distributions.promote_package",
                       return_value=(True, "OK")):

                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

                _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "Approuvé", "reason": ""},
                )
                r2 = _client.post(
                    f"/artifacts/nginx/promote/{pid}/reject",
                    json={"justification": "", "reason": "Trop tard"},
                )
        assert r2.status_code == 409

    def test_reject_then_approve_returns_409(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

                _client.post(
                    f"/artifacts/nginx/promote/{pid}/reject",
                    json={"justification": "", "reason": "Rejeté"},
                )

            with patch("services.distributions.promote_package",
                       return_value=(True, "OK")):
                r2 = _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "Trop tard", "reason": ""},
                )
        assert r2.status_code == 409


# ═════════════════════════════════════════════════════════════════════════════
# E2E-12 & 13 — Validation des champs obligatoires
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EValidation:
    """Les champs obligatoires sont validés avant traitement."""

    def test_approve_empty_justification_returns_400(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

            r2 = _client.post(
                f"/artifacts/nginx/promote/{pid}/approve",
                json={"justification": "   ", "reason": ""},  # espaces → vide
            )
        assert r2.status_code == 400

    def test_promote_invalid_dist_returns_400(self, isolated_pending):
        with _apply_base_patches():
            resp = _client.post(
                "/artifacts/nginx/promote",
                json={"from_dist": "nonexistent_dist", "to_dist": "noble"},
            )
        assert resp.status_code == 400

    def test_promote_same_dist_returns_400(self, isolated_pending):
        with _apply_base_patches():
            resp = _client.post(
                "/artifacts/nginx/promote",
                json={"from_dist": "jammy", "to_dist": "jammy"},
            )
        assert resp.status_code == 400

    def test_promote_missing_package_returns_400(self, isolated_pending):
        with _apply_base_patches():
            with patch("services.indexer.get_package_info", return_value=None):
                resp = _client.post(
                    "/artifacts/ghost_package/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
        assert resp.status_code == 400


# ═════════════════════════════════════════════════════════════════════════════
# E2E-14 — Re-évaluation CVE au moment de l'approbation (bloquée)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.skipif(not _E2E_AVAILABLE, reason="Router non chargeable")
class TestE2EReEvaluation:
    """
    Si de nouvelles CVEs critiques apparaissent entre la demande
    et l'approbation, l'approbation doit être refusée (409).
    """

    def test_approve_refused_if_reeval_blocked(self, isolated_pending):
        with _apply_base_patches():
            # Étape 1 : promotion → pending_review (CVEs high, pas blocked)
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

            # Étape 2 : re-évaluation au moment de l'approbation → blocked !
            # (nouvelle CVE critique découverte entre-temps)
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                r2 = _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "J'approuve malgré tout", "reason": ""},
                )
        # Le RSSI ne peut pas approuver si la re-évaluation dit "blocked"
        assert r2.status_code == 409

    def test_pending_stays_pending_after_reeval_block(self, isolated_pending):
        """La demande reste 'pending' si l'approbation échoue (intégrité)."""
        import services.pending_promotions as pp

        with _apply_base_patches():
            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_PENDING):
                r = _client.post(
                    "/artifacts/nginx/promote",
                    json={"from_dist": "jammy", "to_dist": "noble"},
                )
                pid = r.json()["pending_promotion_id"]

            with patch("services.promotion.evaluate_cve_policy",
                       return_value=VERDICT_BLOCKED):
                _client.post(
                    f"/artifacts/nginx/promote/{pid}/approve",
                    json={"justification": "Tentative bloquée", "reason": ""},
                )

        record = pp.get_pending(pid)
        assert record is not None
        assert record["status"] == "pending", (
            f"La demande doit rester 'pending' après échec d'approbation, "
            f"got: {record['status']!r}"
        )
