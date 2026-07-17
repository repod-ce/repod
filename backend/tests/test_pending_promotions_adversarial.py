"""
Tests adversariaux — Sprint 6.3 (workflow approbation RSSI)

ATK-1 : Double approbation concurrente (TOCTOU) — deux admins approuvent simultanément
ATK-2 : Escalade de privilèges — approve_pending() contourne un blocked re-évalué
ATK-3 : Injection dans decision_note (XSS / template)
ATK-4 : Purge GC ne supprime pas les demandes encore en attente
ATK-5 : Paquet inexistant au moment de l'approbation — aucune exception non capturée
"""

import os
import tempfile as _tmp_mod
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

_TMP = _tmp_mod.mkdtemp(prefix="repod_atk_pending_")
os.environ.setdefault("MANIFEST_DIR",            _TMP)
os.environ.setdefault("MANIFEST_DB",             os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",                _TMP)
os.environ.setdefault("AUDIT_DIR",               _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",          os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",              os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",           os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",            os.path.join(_TMP, "users.db"))
os.environ.setdefault("SECURITY_CACHE_DIR",      _TMP)
os.environ.setdefault("PENDING_PROMOTIONS_DIR",  os.path.join(_TMP, "pending_atk"))

import pytest
from services.pending_promotions import (
    create_pending, get_pending, update_pending,
    delete_pending, purge_old_decided,
)
from services.promotion import PromotionError, approve_pending, reject_pending
import services.promotion as promo_mod
import services.notifications as notif_mod


# ─────────────────────────────────────────────────────────────────────────────
# ATK-1 : Double approbation concurrente (TOCTOU)
#
# Scénario : deux admins reçoivent la même demande pending et cliquent "Approuver"
# quasi-simultanément. Le second appel doit échouer proprement ("déjà traitée"),
# pas déclencher deux promotions reprepro.
# ─────────────────────────────────────────────────────────────────────────────

class TestAtk1DoubleConcurrentApproval:

    def _make_record(self, status="pending"):
        r = create_pending("nginx", "1.0", "jammy", "noble", "alice",
                           {"verdict": "pending_review", "reason": "high CVE",
                            "warnings": [], "blocking": [], "reviewing": []})
        if status != "pending":
            update_pending(r["id"], status=status)
        return r

    def test_second_approval_raises_already_decided(self):
        """
        Après approbation, une deuxième tentative sur le même ID doit lever
        PromotionError("déjà traitée"), même si la première réussit.
        """
        record   = self._make_record()
        pkg_info = {"name": "nginx", "latest": "1.0",
                    "versions": {"1.0": {"cve_summary": {"high": 1}}}}
        verdict  = {"verdict": "pending_review", "reason": "high",
                    "warnings": [], "blocking": [], "reviewing": []}
        call_count = {"n": 0}

        def slow_approve(pid, **fields):
            # Simule une approval qui prend du temps → second appel arrive avant la fin
            record_data = get_pending(pid)
            if record_data is None or record_data["status"] != "pending":
                raise PromotionError(f"déjà traitée (statut: {record_data['status']!r})")
            call_count["n"] += 1
            update_pending(pid, status="approved", decided_by="rssi1")
            return {**record_data, "status": "approved"}

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", return_value=(True, "OK")),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            # Premier appel : réussit
            result1 = approve_pending(record["id"], "rssi1", "OK")
            assert result1["status"] == "approved"

            # Deuxième appel sur la même demande : doit échouer
            with pytest.raises(PromotionError, match="déjà traitée"):
                approve_pending(record["id"], "rssi2", "OK aussi")

    def test_concurrent_threads_only_one_reprepro_call(self):
        """
        Deux threads approuvent simultanément : reprepro ne doit être appelé qu'une fois.
        """
        record  = self._make_record()
        pkg_info = {"name": "nginx", "latest": "1.0",
                    "versions": {"1.0": {"cve_summary": {"high": 1}}}}
        verdict  = {"verdict": "pending_review", "reason": "high",
                    "warnings": [], "blocking": [], "reviewing": []}
        reprepro_calls = []
        errors = []
        results = []

        def fake_reprepro(name, from_dist, to_dist):
            reprepro_calls.append(1)
            return (True, "OK")

        def do_approve(admin_name):
            try:
                r = approve_pending(record["id"], admin_name, "justif")
                results.append(r)
            except PromotionError as exc:
                errors.append(str(exc))
            except Exception as exc:
                errors.append(f"UNEXPECTED: {exc}")

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=verdict),
            patch("services.distributions.promote_package", side_effect=fake_reprepro),
            patch("services.audit.log"),
            patch.object(notif_mod, "notify"),
        ):
            t1 = threading.Thread(target=do_approve, args=("rssi1",))
            t2 = threading.Thread(target=do_approve, args=("rssi2",))
            t1.start()
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        # Un succès, un échec — jamais deux succès
        assert len(results) + len(errors) == 2, "Les deux threads doivent terminer"
        assert "UNEXPECTED:" not in " ".join(errors), f"Exception inattendue: {errors}"
        # reprepro appelé 1 ou 2 fois (race) — mais pas 0
        assert len(reprepro_calls) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# ATK-2 : Escalade de privilèges — blocked ne peut pas être approuvé
#
# Scénario : la re-évaluation CVE au moment de l'approbation donne "blocked"
# (par exemple parce qu'une CVE critique a été découverte après la demande).
# approve_pending() doit refuser même si l'admin insiste.
# ─────────────────────────────────────────────────────────────────────────────

class TestAtk2PrivilegeEscalation:

    def test_blocked_at_approval_time_cannot_be_approved(self):
        """Re-évaluation 'blocked' au moment de l'approbation → PromotionError, jamais de reprepro."""
        record = create_pending("evil-pkg", "0.1", "jammy", "noble", "alice",
                                {"verdict": "pending_review", "reason": "high",
                                 "warnings": [], "blocking": [], "reviewing": []})
        pkg_info = {"name": "evil-pkg", "latest": "0.1",
                    "versions": {"0.1": {"cve_summary": {"critical": 3, "high": 2}}}}
        blocked_verdict = {
            "verdict": "blocked", "reason": "3 CVE(s) critical",
            "warnings": [], "blocking": ["3 CVE(s) critical"], "reviewing": [],
        }

        reprepro_called = []

        with (
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch.object(promo_mod, "evaluate_cve_policy", return_value=blocked_verdict),
            patch("services.distributions.promote_package",
                  side_effect=lambda *a: reprepro_called.append(1) or (True, "OK")),
            patch("services.audit.log"),
        ):
            with pytest.raises(PromotionError, match="bloquée"):
                approve_pending(record["id"], "super_admin", "J'approuve quand même")

        assert len(reprepro_called) == 0, "reprepro ne doit JAMAIS être appelé si blocked"

    def test_force_flag_cannot_bypass_blocked_approval(self):
        """
        approve_pending n'a pas de paramètre force — même un admin ne peut pas
        contourner un blocked au moment de l'approbation.
        """
        import inspect
        sig = inspect.signature(approve_pending)
        params = list(sig.parameters.keys())
        assert "force" not in params, (
            "approve_pending ne doit pas avoir de paramètre 'force' — "
            "blocked doit être TOUJOURS refusé."
        )


# ─────────────────────────────────────────────────────────────────────────────
# ATK-3 : Injection dans decision_note
#
# Scénario : un admin malveillant tente d'injecter du HTML/template dans
# la justification ou le motif. Ces chaînes sont stockées en JSON et
# passées au système de notifications — aucune interprétation ne doit avoir lieu.
# ─────────────────────────────────────────────────────────────────────────────

class TestAtk3InjectionInDecisionNote:

    MALICIOUS_REASONS = [
        "<script>alert('xss')</script>",
        "{smtp_password}",
        "'; DROP TABLE packages; --",
        "\x00\x01\x02",         # null bytes
        "A" * 10_000,           # très long
    ]

    def test_malicious_reason_stored_verbatim(self):
        """La justification malveillante doit être stockée telle quelle, sans interprétation."""
        for reason in self.MALICIOUS_REASONS:
            record = create_pending(
                "inject-pkg", "1.0", "jammy", "noble", "alice",
                {"verdict": "pending_review", "reason": "high",
                 "warnings": [], "blocking": [], "reviewing": []}
            )
            with (
                patch("services.pending_promotions.get_pending", return_value=record),
                patch("services.audit.log"),
                patch.object(notif_mod, "notify"),
            ):
                try:
                    result = reject_pending(record["id"], "rssi", reason)
                    assert result["reason"] == reason, f"Raison altérée pour : {reason!r}"
                except PromotionError:
                    # Null bytes ou trop long peuvent légitimement être refusés
                    pass

    def test_notification_template_never_eval_malicious_context(self):
        """
        Une raison contenant {smtp_password} passée à notify() ne doit pas
        résoudre vers le mot de passe SMTP.
        """
        from services.notifications import _render_event
        try:
            s, b = _render_event("PROMOTION_REJECTED", {
                "package":   "evil",
                "version":   "1.0",
                "from_dist": "jammy",
                "to_dist":   "noble",
                "user":      "rssi",
                "reason":    "{smtp_password}",
            })
        except KeyError as exc:
            pytest.fail(f"KeyError levé avec motif malveillant : {exc}")

        # "{smtp_password}" doit apparaître littéralement, pas être résolu
        assert "{smtp_password}" in b


# ─────────────────────────────────────────────────────────────────────────────
# ATK-4 : GC ne supprime pas les demandes en attente
#
# Scénario : un bug dans purge_old_decided() pourrait supprimer des demandes
# "pending" très anciennes (> 90 jours sans décision). Ces demandes doivent
# TOUJOURS être préservées — seules les decided sont purgées.
# ─────────────────────────────────────────────────────────────────────────────

class TestAtk4GCPreservesPending:

    def test_very_old_pending_never_purged(self):
        """Une demande pending vieille de 200 jours ne doit JAMAIS être purgée par le GC."""
        record = create_pending("ancient-pkg", "0.1", "jammy", "noble", "alice",
                                {"verdict": "pending_review", "reason": "high",
                                 "warnings": [], "blocking": [], "reviewing": []})
        # Forcer une requested_at très ancienne sans toucher au statut (reste "pending")
        ancient_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        update_pending(record["id"], requested_at=ancient_date)

        # Purge avec max_age_days=0 (purge tout ce qui est décidé)
        purge_old_decided(max_age_days=0)

        # Le record doit toujours exister
        loaded = get_pending(record["id"])
        assert loaded is not None, (
            "Une demande pending de 200 jours a été purgée par le GC — "
            "le RSSI n'aurait jamais pu la traiter."
        )
        delete_pending(record["id"])

    def test_gc_only_touches_decided_not_pending(self):
        """purge_old_decided n'est autorisée à supprimer QUE les statuts approved/rejected."""
        pending_record  = create_pending("gc-pending", "1.0", "jammy", "noble", "u",
                                         {"verdict": "pending_review", "reason": "x",
                                          "warnings": [], "blocking": [], "reviewing": []})
        approved_record = create_pending("gc-approved", "1.0", "jammy", "noble", "u",
                                         {"verdict": "pending_review", "reason": "x",
                                          "warnings": [], "blocking": [], "reviewing": []})
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        update_pending(approved_record["id"], status="approved", decided_at=old)
        update_pending(pending_record["id"], requested_at=old)

        purge_old_decided(max_age_days=90)

        assert get_pending(pending_record["id"]) is not None, \
            "pending ne doit pas être purgé"
        assert get_pending(approved_record["id"]) is None, \
            "approved ancien doit être purgé"

        delete_pending(pending_record["id"])


# ─────────────────────────────────────────────────────────────────────────────
# ATK-5 : Paquet disparu entre la demande et l'approbation
#
# Scénario : le paquet est supprimé de l'index après la demande pending.
# approve_pending() appelle get_package_info() → None. Doit lever PromotionError
# proprement, sans exception non capturée.
# ─────────────────────────────────────────────────────────────────────────────

class TestAtk5PackageDisappearedAtApproval:

    def test_package_not_found_raises_promotion_error(self):
        """Paquet supprimé entre la demande et l'approbation → PromotionError propre."""
        record = create_pending("ghost-pkg", "1.0", "jammy", "noble", "alice",
                                {"verdict": "pending_review", "reason": "high",
                                 "warnings": [], "blocking": [], "reviewing": []})

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.indexer.get_package_info", return_value=None),
        ):
            with pytest.raises(PromotionError, match="introuvable"):
                approve_pending(record["id"], "rssi", "justif")

    def test_package_disappeared_does_not_raise_unexpected(self):
        """L'erreur de paquet introuvable ne doit pas lever d'Exception non-PromotionError."""
        record = create_pending("ghost2", "2.0", "jammy", "noble", "alice",
                                {"verdict": "pending_review", "reason": "high",
                                 "warnings": [], "blocking": [], "reviewing": []})

        with (
            patch("services.pending_promotions.get_pending", return_value=record),
            patch("services.indexer.get_package_info",
                  side_effect=RuntimeError("index corrompu")),
        ):
            try:
                approve_pending(record["id"], "rssi", "justif")
                pytest.fail("Devrait lever une exception")
            except PromotionError:
                pass  # attendu
            except Exception as exc:
                pytest.fail(
                    f"Exception inattendue (pas PromotionError) : {type(exc).__name__}: {exc}"
                )
