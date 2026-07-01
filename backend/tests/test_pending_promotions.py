"""
Tests — services/pending_promotions.py + services/promotion.py (approve/reject)
            + routers/artifacts.py (pending-promotions endpoints)

Couverture :
  TestPendingPromotionsService  — CRUD, filtres, purge
  TestPromotionPersistence      — promote() persiste les pending_review
  TestApprovePending            — approve_pending() flux complet
  TestRejectPending             — reject_pending() flux complet
  TestPendingRouter             — endpoints HTTP
  TestNotificationIntegration   — PROMOTION_REJECTED émis
"""

import importlib.util
import os
import sys
import tempfile as _tmp_mod
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

_TMP = _tmp_mod.mkdtemp(prefix="repod_pending_")
os.environ.setdefault("MANIFEST_DIR",            _TMP)
os.environ.setdefault("MANIFEST_DB",             os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",                _TMP)
os.environ.setdefault("AUDIT_DIR",               _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",          os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",              os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",           os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",            os.path.join(_TMP, "users.db"))
os.environ.setdefault("SECURITY_CACHE_DIR",      _TMP)
os.environ.setdefault("PENDING_PROMOTIONS_DIR",  os.path.join(_TMP, "pending"))

import pytest

import services.pending_promotions as pp_mod
from services.pending_promotions import (
    create_pending, get_pending, update_pending,
    list_pending, delete_pending, purge_old_decided,
)
from services.promotion import (
    approve_pending, reject_pending, PromotionError,
)
import services.promotion as promo_mod
import services.notifications as notif_mod


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_verdict(v="pending_review"):
    return {"verdict": v, "reason": "CVE high", "warnings": [], "blocking": [], "reviewing": []}

def _fake_pkg_info(name="nginx", version="1.0"):
    return {
        "name": name, "latest": version,
        "versions": {version: {"cve_summary": {"high": 2}}},
    }


# ─────────────────────────────────────────────────────────────────────────────
# CRUD — services/pending_promotions.py
# ─────────────────────────────────────────────────────────────────────────────

class TestPendingPromotionsService:

    def test_create_returns_record_with_id(self):
        r = create_pending("nginx", "1.0", "jammy", "noble", "alice", _fake_verdict())
        assert "id" in r
        assert r["status"] == "pending"
        assert r["name"] == "nginx"
        assert r["decided_by"] is None

    def test_get_returns_same_record(self):
        r = create_pending("curl", "7.8", "jammy", "noble", "bob", _fake_verdict())
        loaded = get_pending(r["id"])
        assert loaded is not None
        assert loaded["id"] == r["id"]
        assert loaded["name"] == "curl"

    def test_get_nonexistent_returns_none(self):
        assert get_pending("nonexistent-id-xxxxxxx") is None

    def test_update_changes_fields(self):
        r = create_pending("vim", "9.0", "jammy", "noble", "carol", _fake_verdict())
        upd = update_pending(r["id"], status="approved", decided_by="rssi")
        assert upd["status"] == "approved"
        assert upd["decided_by"] == "rssi"
        # Persistance vérifiée
        loaded = get_pending(r["id"])
        assert loaded["status"] == "approved"

    def test_update_nonexistent_returns_none(self):
        assert update_pending("ghost-id", status="approved") is None

    def test_list_returns_all(self):
        before = len(list_pending())
        create_pending("pkg-a", "1.0", "jammy", "noble", "u", _fake_verdict())
        create_pending("pkg-b", "2.0", "jammy", "focal", "u", _fake_verdict())
        after = list_pending()
        assert len(after) >= before + 2

    def test_list_filter_by_status(self):
        r1 = create_pending("filter-pkg1", "1.0", "jammy", "noble", "u", _fake_verdict())
        r2 = create_pending("filter-pkg2", "1.0", "jammy", "noble", "u", _fake_verdict())
        update_pending(r1["id"], status="approved")
        # Only r2 should remain pending
        pending = list_pending(status="pending")
        ids = [r["id"] for r in pending]
        assert r2["id"] in ids
        # r1 must not appear in pending list
        assert r1["id"] not in ids

    def test_list_filter_approved(self):
        r = create_pending("filter-approved", "1.0", "jammy", "noble", "u", _fake_verdict())
        update_pending(r["id"], status="approved", decided_by="rssi")
        approved = list_pending(status="approved")
        ids = [rec["id"] for rec in approved]
        assert r["id"] in ids

    def test_list_sorted_most_recent_first(self):
        r1 = create_pending("sort-a", "1.0", "jammy", "noble", "u", _fake_verdict())
        time.sleep(0.01)
        r2 = create_pending("sort-b", "1.0", "jammy", "noble", "u", _fake_verdict())
        records = list_pending()
        ids = [r["id"] for r in records]
        # r2 is more recent → should appear before r1
        assert ids.index(r2["id"]) < ids.index(r1["id"])

    def test_delete_removes_record(self):
        r = create_pending("del-pkg", "1.0", "jammy", "noble", "u", _fake_verdict())
        assert delete_pending(r["id"]) is True
        assert get_pending(r["id"]) is None

    def test_delete_nonexistent_returns_false(self):
        assert delete_pending("ghost-id-xyz") is False

    def test_purge_old_decided_removes_old(self):
        r = create_pending("purge-old", "1.0", "jammy", "noble", "u", _fake_verdict())
        # Forcer une decided_at très ancienne
        old_date = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        update_pending(r["id"], status="approved", decided_at=old_date)
        count = purge_old_decided(max_age_days=90)
        assert count >= 1
        assert get_pending(r["id"]) is None

    def test_purge_preserves_recent_decided(self):
        r = create_pending("purge-recent", "1.0", "jammy", "noble", "u", _fake_verdict())
        recent_date = datetime.now(timezone.utc).isoformat()
        update_pending(r["id"], status="approved", decided_at=recent_date)
        purge_old_decided(max_age_days=90)
        # Should still exist
        assert get_pending(r["id"]) is not None
        delete_pending(r["id"])

    def test_purge_preserves_pending(self):
        """Les demandes encore en attente ne sont jamais purgées."""
        r = create_pending("purge-still-pending", "1.0", "jammy", "noble", "u", _fake_verdict())
        purge_old_decided(max_age_days=0)  # max_age_days=0 → ne purge rien
        assert get_pending(r["id"]) is not None
        delete_pending(r["id"])

    def test_purge_max_age_zero_purges_nothing(self):
        r = create_pending("purge-zero", "1.0", "jammy", "noble", "u", _fake_verdict())
        old_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        update_pending(r["id"], status="rejected", decided_at=old_date)
        count = purge_old_decided(max_age_days=0)
        assert count == 0
        delete_pending(r["id"])


# ─────────────────────────────────────────────────────────────────────────────
# promote() — persistence des pending_review
# ─────────────────────────────────────────────────────────────────────────────

class TestPromotionPersistence:

    def _make_cfg_pending(self):
        """Config settings avec PENDING_REVIEW pour high CVE."""
        return {"cve_policy": {"critical": "block", "high": "review"}}

    def test_pending_review_creates_pending_record(self):
        """promote() retourne pending_review → crée une entrée dans pending_promotions."""
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")

        created_records = []

        def capturing_create(name, version, from_dist, to_dist, requested_by, policy_verdict):
            r = {
                "id": str(uuid.uuid4()), "name": name, "version": version,
                "from_dist": from_dist, "to_dist": to_dist,
                "requested_by": requested_by, "requested_at": datetime.now(timezone.utc).isoformat(),
                "policy_verdict": policy_verdict, "status": "pending",
                "decided_by": None, "decided_at": None, "decision_note": "",
            }
            created_records.append(r)
            return r

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
            patch("services.pending_promotions.create_pending", side_effect=capturing_create),
        ):
            result = promo_mod.promote(
                name="nginx", from_dist="jammy", to_dist="noble",
                promoted_by="alice", version="1.0", force=False,
            )

        assert result["status"] == "pending_review"
        assert "pending_promotion_id" in result
        assert len(created_records) == 1
        assert created_records[0]["name"] == "nginx"

    def test_pending_review_includes_id_in_result(self):
        """Le pending_promotion_id est inclus dans le retour de promote()."""
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")
        fixed_id = "test-uuid-123"

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
            patch("services.pending_promotions.create_pending",
                  return_value={"id": fixed_id, "status": "pending"}),
        ):
            result = promo_mod.promote(
                name="nginx", from_dist="jammy", to_dist="noble",
                promoted_by="alice", force=False,
            )

        assert result["pending_promotion_id"] == fixed_id

    def test_blocked_does_not_create_pending(self):
        """promote() blocked → crée un enregistrement d'audit avec status='blocked'
        (pas un enregistrement 'pending' nécessitant une revue).
        Le résultat doit avoir status='blocked' et create_pending est appelé
        uniquement pour tracer le refus, pas pour créer un ticket de revue."""
        pkg_info = _fake_pkg_info()
        verdict  = {**_fake_verdict("blocked"), "blocking": ["critical"]}

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
            patch("services.pending_promotions.create_pending") as mock_create,
        ):
            result = promo_mod.promote(
                name="nginx", from_dist="jammy", to_dist="noble",
                promoted_by="alice", force=False,
            )

        assert result["status"] == "blocked"
        # Si create_pending est appelé pour tracer le refus, il doit l'être
        # avec status="blocked" (pas "pending") — jamais pour créer une revue.
        if mock_create.called:
            call_kwargs = mock_create.call_args.kwargs
            assert call_kwargs.get("status") == "blocked", (
                "create_pending ne doit pas créer un ticket 'pending' pour un verdict 'blocked' ; "
                f"statut obtenu : {call_kwargs.get('status')!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# approve_pending()
# ─────────────────────────────────────────────────────────────────────────────

class TestApprovePending:

    def _make_record(self, status="pending", name="nginx", version="1.0"):
        return {
            "id": str(uuid.uuid4()), "name": name, "version": version,
            "from_dist": "jammy", "to_dist": "noble",
            "requested_by": "alice",
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "policy_verdict": _fake_verdict(), "status": status,
            "decided_by": None, "decided_at": None, "decision_note": "",
        }

    def test_approve_calls_reprepro_and_returns_approved(self):
        record   = self._make_record()
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending", return_value={**record, "status": "approved"}),
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", return_value=(True, "OK")),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            result = approve_pending(record["id"], "rssi_user", "Justification valide")

        assert result["status"] == "approved"
        assert result["approved_by"] == "rssi_user"
        assert result["package"] == "nginx"

    def test_approve_nonexistent_raises(self):
        with patch("services.pending_promotions.get_pending", return_value=None):
            with pytest.raises(PromotionError, match="introuvable"):
                approve_pending("ghost-id", "rssi_user", "justif")

    def test_approve_already_decided_raises(self):
        record = self._make_record(status="approved")
        with patch("services.pending_promotions.get_pending", return_value=record):
            with pytest.raises(PromotionError, match="déjà traitée"):
                approve_pending(record["id"], "rssi_user", "justif")

    def test_approve_blocked_verdict_raises(self):
        """Re-évaluation CVE donne 'blocked' → approbation refusée."""
        record   = self._make_record()
        pkg_info = _fake_pkg_info()
        blocked_verdict = {**_fake_verdict("blocked"), "blocking": ["critical"]}

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=blocked_verdict),
            patch("services.audit.log"),
        ):
            with pytest.raises(PromotionError, match="bloquée"):
                approve_pending(record["id"], "rssi_user", "justif")

    def test_approve_reprepro_failure_raises(self):
        record   = self._make_record()
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", return_value=(False, "reprepro error")),
            patch("services.audit.log"),
        ):
            with pytest.raises(PromotionError, match="reprepro"):
                approve_pending(record["id"], "rssi_user", "justif")

    def test_approve_package_not_found_raises(self):
        record = self._make_record()
        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.indexer.get_package_info", return_value=None),
        ):
            with pytest.raises(PromotionError, match="introuvable"):
                approve_pending(record["id"], "rssi_user", "justif")

    def test_approve_sends_promotion_approved_notification(self):
        record   = self._make_record()
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")
        notif_calls = []

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending", return_value={**record, "status": "approved"}),
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", return_value=(True, "OK")),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify",
                         side_effect=lambda e, ctx=None, **kw: notif_calls.append(e)),
        ):
            approve_pending(record["id"], "rssi_user", "justif")

        assert "PROMOTION_APPROVED" in notif_calls

    def test_approve_updates_pending_status(self):
        record   = self._make_record()
        pkg_info = _fake_pkg_info()
        verdict  = _fake_verdict("pending_review")
        update_calls = []

        def track_update(pid, **fields):
            update_calls.append(fields)
            return {**record, **fields}

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending", side_effect=track_update),
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", return_value=(True, "OK")),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            approve_pending(record["id"], "rssi_user", "justif")

        assert any(c.get("status") == "approved" for c in update_calls)
        assert any(c.get("decided_by") == "rssi_user" for c in update_calls)


# ─────────────────────────────────────────────────────────────────────────────
# reject_pending()
# ─────────────────────────────────────────────────────────────────────────────

class TestRejectPending:

    def _make_record(self, status="pending"):
        return {
            "id": str(uuid.uuid4()), "name": "curl", "version": "7.8",
            "from_dist": "jammy", "to_dist": "noble",
            "requested_by": "alice",
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "policy_verdict": _fake_verdict(), "status": status,
            "decided_by": None, "decided_at": None, "decision_note": "",
        }

    def test_reject_returns_rejected_status(self):
        record = self._make_record()
        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending",
                  return_value={**record, "status": "rejected"}),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            result = reject_pending(record["id"], "rssi_user", "CVE trop anciennes")

        assert result["status"] == "rejected"
        assert result["rejected_by"] == "rssi_user"
        assert result["reason"] == "CVE trop anciennes"

    def test_reject_nonexistent_raises(self):
        with patch("services.pending_promotions.get_pending", return_value=None):
            with pytest.raises(PromotionError, match="introuvable"):
                reject_pending("ghost-id", "rssi_user", "motif")

    def test_reject_already_decided_raises(self):
        record = self._make_record(status="rejected")
        with patch("services.pending_promotions.get_pending", return_value=record):
            with pytest.raises(PromotionError, match="déjà traitée"):
                reject_pending(record["id"], "rssi_user", "motif")

    def test_reject_empty_reason_raises(self):
        record = self._make_record()
        with patch("services.pending_promotions.get_pending", return_value=record):
            with pytest.raises(PromotionError, match="obligatoire"):
                reject_pending(record["id"], "rssi_user", "   ")

    def test_reject_sends_promotion_rejected_notification(self):
        record = self._make_record()
        notif_calls = []

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending",
                  return_value={**record, "status": "rejected"}),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify",
                         side_effect=lambda e, ctx=None, **kw: notif_calls.append(e)),
        ):
            reject_pending(record["id"], "rssi_user", "motif valide")

        assert "PROMOTION_REJECTED" in notif_calls

    def test_reject_does_not_call_reprepro(self):
        record = self._make_record()
        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending",
                  return_value={**record, "status": "rejected"}),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
            patch("services.distributions.promote_package") as mock_reprepro,
        ):
            reject_pending(record["id"], "rssi_user", "motif valide")

        mock_reprepro.assert_not_called()

    def test_reject_updates_pending_status(self):
        record = self._make_record()
        update_calls = []

        def track_update(pid, **fields):
            update_calls.append(fields)
            return {**record, **fields}

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.pending_promotions.update_pending", side_effect=track_update),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            reject_pending(record["id"], "rssi_user", "motif valide")

        assert any(c.get("status") == "rejected" for c in update_calls)
        assert any(c.get("decided_by") == "rssi_user" for c in update_calls)
        assert any("motif valide" in str(c.get("decision_note", "")) for c in update_calls)


# ─────────────────────────────────────────────────────────────────────────────
# Router — endpoints HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _load_artifacts_router():
    """Charge le router artifacts sans passer par __init__.py."""
    artifacts_path = os.path.join(
        os.path.dirname(__file__), "..", "routers", "artifacts.py"
    )
    spec = importlib.util.spec_from_file_location(
        "artifacts_router",
        artifacts_path,
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["artifacts_router"] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from slowapi.errors import RateLimitExceeded
    from limiter import limiter
    from services.rate_limits import rate_limit_exceeded_handler
    _artifacts_mod = _load_artifacts_router()

    _app = FastAPI()
    # SEC-3 : le router utilise @limiter.limit() — slowapi requiert
    # app.state.limiter + le handler d'exception pour fonctionner.
    _app.state.limiter = limiter
    _app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    _app.include_router(_artifacts_mod.router)

    def _admin_override():
        return "rssi_admin"

    def _maintainer_override():
        return "maintainer_user"

    from auth.dependencies import get_admin_user, get_maintainer_user as _get_maintainer
    _app.dependency_overrides[get_admin_user]    = _admin_override
    _app.dependency_overrides[_get_maintainer]   = _maintainer_override
    _client = TestClient(_app, raise_server_exceptions=False)
    _ROUTER_AVAILABLE = True
except Exception:
    _ROUTER_AVAILABLE = False


@pytest.mark.skipif(not _ROUTER_AVAILABLE, reason="Router non chargeable")
class TestPendingRouter:

    def test_list_pending_empty(self):
        with patch.object(_artifacts_mod, "list_pending", return_value=[]):
            resp = _client.get("/artifacts/admin/pending-promotions")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_list_pending_with_items(self):
        fake_records = [
            {"id": "abc", "name": "nginx", "status": "pending",
             "from_dist": "jammy", "to_dist": "noble",
             "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"},
        ]
        with patch.object(_artifacts_mod, "list_pending", return_value=fake_records):
            resp = _client.get("/artifacts/admin/pending-promotions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    def test_approve_returns_200_on_success(self):
        record = {"id": "tid", "name": "nginx", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        ok_result = {"status": "approved", "package": "nginx", "version": "1.0",
                     "from_dist": "jammy", "to_dist": "noble",
                     "approved_by": "rssi_admin", "approved_at": "2026-01-01T00:00:00+00:00",
                     "justification": "OK", "policy_verdict": {}, "reprepro_msg": "OK",
                     "pending_id": "tid"}
        with (
            patch.object(_artifacts_mod, "get_pending", return_value=record),
            patch.object(_artifacts_mod, "approve_pending", return_value=ok_result),
        ):
            resp = _client.post(
                "/artifacts/nginx/promote/tid/approve",
                json={"justification": "Approuvé formellement", "reason": ""},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved"

    def test_approve_404_when_not_found(self):
        with patch.object(_artifacts_mod, "get_pending", return_value=None):
            resp = _client.post(
                "/artifacts/nginx/promote/ghost-id/approve",
                json={"justification": "test", "reason": ""},
            )
        assert resp.status_code == 404

    def test_approve_400_when_wrong_package(self):
        record = {"id": "tid2", "name": "curl", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        with patch.object(_artifacts_mod, "get_pending", return_value=record):
            resp = _client.post(
                "/artifacts/nginx/promote/tid2/approve",  # nginx ≠ curl
                json={"justification": "test", "reason": ""},
            )
        assert resp.status_code == 400

    def test_reject_returns_200_on_success(self):
        record = {"id": "rid", "name": "curl", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        ok_result = {"status": "rejected", "package": "curl", "version": "7.8",
                     "from_dist": "jammy", "to_dist": "noble",
                     "rejected_by": "rssi_admin", "rejected_at": "2026-01-01T00:00:00+00:00",
                     "reason": "CVE non corrigées", "pending_id": "rid"}
        with (
            patch.object(_artifacts_mod, "get_pending", return_value=record),
            patch.object(_artifacts_mod, "reject_pending", return_value=ok_result),
        ):
            resp = _client.post(
                "/artifacts/curl/promote/rid/reject",
                json={"justification": "", "reason": "CVE non corrigées"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

    def test_reject_409_already_decided(self):
        record = {"id": "rid2", "name": "curl", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        with (
            patch.object(_artifacts_mod, "get_pending", return_value=record),
            patch.object(_artifacts_mod, "reject_pending",
                         side_effect=PromotionError("déjà traitée")),
        ):
            resp = _client.post(
                "/artifacts/curl/promote/rid2/reject",
                json={"justification": "", "reason": "motif"},
            )
        assert resp.status_code == 409

    def test_approve_400_empty_justification(self):
        record = {"id": "tid3", "name": "nginx", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        with patch.object(_artifacts_mod, "get_pending", return_value=record):
            resp = _client.post(
                "/artifacts/nginx/promote/tid3/approve",
                json={"justification": "   ", "reason": ""},
            )
        assert resp.status_code == 400

    def test_reject_400_empty_reason(self):
        record = {"id": "rid3", "name": "curl", "status": "pending",
                  "from_dist": "jammy", "to_dist": "noble",
                  "requested_by": "alice", "requested_at": "2026-01-01T00:00:00+00:00"}
        with patch.object(_artifacts_mod, "get_pending", return_value=record):
            resp = _client.post(
                "/artifacts/curl/promote/rid3/reject",
                json={"justification": "", "reason": "   "},
            )
        assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# Intégration — PROMOTION_REJECTED dans le système de notifications
# ─────────────────────────────────────────────────────────────────────────────

class TestNotificationIntegration:

    def test_promotion_rejected_in_supported_events(self):
        from services.notifications import SUPPORTED_EVENTS
        assert "PROMOTION_REJECTED" in SUPPORTED_EVENTS

    def test_promotion_rejected_has_template(self):
        from services.notifications import _TEMPLATES
        assert "PROMOTION_REJECTED" in _TEMPLATES
        subj, body = _TEMPLATES["PROMOTION_REJECTED"]
        assert "{package}" in subj
        assert "{user}" in body
        assert "{reason}" in body

    def test_promotion_rejected_render_no_keyerror(self):
        from services.notifications import _render_event
        s, b = _render_event("PROMOTION_REJECTED", {
            "package":   "curl",
            "version":   "7.8",
            "from_dist": "jammy",
            "to_dist":   "noble",
            "user":      "rssi_admin",
            "reason":    "CVE non corrigées",
        })
        assert "curl" in s
        assert "rssi_admin" in b
        assert "CVE non corrigées" in b

    def test_retention_calls_purge_old_decided(self):
        """run_retention() appelle purge_old_decided."""
        from services import retention as ret_mod
        purge_calls = []

        def fake_purge(max_age_days=90):
            purge_calls.append(max_age_days)
            return 0

        with (
            patch("services.audit.log"),
            patch.object(ret_mod, "_purge_audit_logs",
                         return_value={"deleted": 0, "freed_bytes": 0}),
            patch.object(ret_mod, "_purge_old_packages",
                         return_value={"deleted": 0, "freed_bytes": 0}),
            patch("services.snapshots.run_version_gc",
                  return_value={"versions_deleted": 0, "versions_skipped": 0,
                                "packages_checked": 0, "max_versions": 5, "min_age_days": 0}),
            patch("services.dashboard.get_sla_overdue", return_value=[]),
            patch.object(notif_mod, "notify"),
            patch("services.pending_promotions.purge_old_decided", side_effect=fake_purge),
        ):
            from services.retention import run_retention
            result = run_retention()

        assert len(purge_calls) >= 1
        assert "pending_promotions_gc" in result
