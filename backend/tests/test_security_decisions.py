"""
Module : test_security_decisions.py
Rôle   : Tests des décisions de sécurité RSSI (stockage PostgreSQL/SQLite).
         Vérifie save_decision(), load_decision(), delete_decision(),
         list_all_decisions(), is_decision_expired(), get_sla_status().

Dépend : pytest, conftest.db_test_engine (SQLite in-memory)
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_decisions_test_")
os.environ.setdefault("SECURITY_CACHE_DIR", _TMP)
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
from datetime import datetime, timezone, timedelta

import pytest

from services.security_decisions import (
    save_decision,
    load_decision,
    delete_decision,
    list_all_decisions,
    is_decision_expired,
    get_sla_status,
    VALID_ACTIONS,
    ACTION_TO_STATUS,
)


# ── Fixture : nettoyage avant chaque test ─────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_decisions(db_test_engine):
    """Vide la table decision_records avant et après chaque test."""
    from sqlalchemy import text
    with db_test_engine.begin() as c:
        c.execute(text("DELETE FROM decision_records"))
    yield
    with db_test_engine.begin() as c:
        c.execute(text("DELETE FROM decision_records"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _save(
    name="nginx", version="1.24.0", arch="amd64",
    action="accept_risk", justification="Testé en staging",
    decided_by="rssi@company.com", expires_in_days=None,
) -> dict:
    return save_decision(
        name=name, version=version, arch=arch,
        action=action, justification=justification,
        decided_by=decided_by, expires_in_days=expires_in_days,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# save_decision()
# ═══════════════════════════════════════════════════════════════════════════════

class TestSaveDecision:

    def test_returns_dict_with_all_fields(self):
        """save_decision() retourne un dict complet."""
        dec = _save()
        for key in ("package", "version", "arch", "action", "status",
                    "justification", "decided_by", "decided_at"):
            assert key in dec, f"Clé manquante : {key!r}"

    def test_action_maps_to_correct_status(self):
        """Chaque action produit le statut de manifest correspondant."""
        for action, expected_status in ACTION_TO_STATUS.items():
            dec = _save(action=action)
            assert dec["status"] == expected_status, (
                f"action={action!r} → attendu={expected_status!r}, obtenu={dec['status']!r}"
            )
            delete_decision("nginx", "1.24.0", "amd64")

    def test_invalid_action_raises_value_error(self):
        """Une action invalide lève ValueError."""
        with pytest.raises(ValueError, match="invalide"):
            save_decision(
                name="vim", version="9.0", arch="amd64",
                action="unknown_action",
                justification="test", decided_by="admin",
            )

    def test_expires_at_set_when_expires_in_days_provided(self):
        """Avec expires_in_days=30, expires_at est une date future."""
        dec = _save(expires_in_days=30)
        assert dec["expires_at"] is not None
        exp = datetime.fromisoformat(dec["expires_at"])
        now = datetime.now(timezone.utc)
        assert exp > now
        delta = (exp - now).days
        assert 28 <= delta <= 31

    def test_expires_at_is_none_without_expiry(self):
        """Sans expires_in_days, expires_at vaut None."""
        dec = _save(expires_in_days=None)
        assert dec["expires_at"] is None

    def test_cve_ids_stored(self):
        """Les IDs de CVE associées sont persistés."""
        dec = save_decision(
            name="openssl", version="3.0.2", arch="amd64",
            action="accept_risk", justification="CVE acceptée",
            decided_by="rssi@co.fr", cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
        )
        assert dec["cve_ids"] == ["CVE-2024-1234", "CVE-2024-5678"]

    def test_overwrite_existing_decision(self):
        """Sauvegarder deux fois le même paquet écrase la décision précédente."""
        _save(action="accept_risk")
        _save(action="reject")
        dec = load_decision("nginx", "1.24.0", "amd64")
        assert dec is not None
        assert dec["action"] == "reject"
        # Une seule entrée en base
        all_dec = list_all_decisions()
        assert len(all_dec) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# load_decision()
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoadDecision:

    def test_returns_none_when_no_decision(self):
        """Paquet sans décision → None."""
        assert load_decision("nonexistent", "1.0.0") is None

    def test_returns_saved_decision(self):
        """Charge la décision sauvegardée correctement."""
        _save(name="vim", version="9.0", action="exception",
              justification="Test", decided_by="admin")
        dec = load_decision("vim", "9.0", "amd64")
        assert dec is not None
        assert dec["action"] == "exception"
        assert dec["package"] == "vim"

    def test_version_with_colon_handled(self):
        """Les versions avec ':' (époch RPM/deb) sont stockées correctement."""
        _save(name="epoch_pkg", version="1:2.0.0", action="accept_risk",
              justification="epoch test", decided_by="admin")
        dec = load_decision("epoch_pkg", "1:2.0.0", "amd64")
        assert dec is not None
        assert dec["version"] == "1:2.0.0"


# ═══════════════════════════════════════════════════════════════════════════════
# delete_decision()
# ═══════════════════════════════════════════════════════════════════════════════

class TestDeleteDecision:

    def test_returns_true_when_deleted(self):
        """Retourne True si la décision existait et a été supprimée."""
        _save()
        assert delete_decision("nginx", "1.24.0", "amd64") is True

    def test_returns_false_when_not_found(self):
        """Retourne False si aucune décision à supprimer."""
        assert delete_decision("nonexistent", "1.0.0") is False

    def test_record_removed_from_db(self):
        """La décision est bien supprimée de la base."""
        _save()
        delete_decision("nginx", "1.24.0", "amd64")
        assert load_decision("nginx", "1.24.0", "amd64") is None


# ═══════════════════════════════════════════════════════════════════════════════
# list_all_decisions()
# ═══════════════════════════════════════════════════════════════════════════════

class TestListAllDecisions:

    def test_empty_db_returns_empty_list(self):
        """Aucune décision → liste vide."""
        assert list_all_decisions() == []

    def test_returns_all_saved_decisions(self):
        """Toutes les décisions sauvegardées sont retournées."""
        _save(name="nginx", version="1.24.0")
        _save(name="curl",  version="7.88.0")
        _save(name="vim",   version="9.0", action="reject")
        decisions = list_all_decisions()
        assert len(decisions) == 3
        names = {d["package"] for d in decisions}
        assert names == {"nginx", "curl", "vim"}


# ═══════════════════════════════════════════════════════════════════════════════
# is_decision_expired()
# ═══════════════════════════════════════════════════════════════════════════════

class TestIsDecisionExpired:

    def test_no_expiry_never_expires(self):
        """Décision sans expires_at → False."""
        dec = {"action": "accept_risk", "expires_at": None}
        assert is_decision_expired(dec) is False

    def test_future_expiry_not_expired(self):
        """Date future → False."""
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        assert is_decision_expired({"expires_at": future}) is False

    def test_past_expiry_is_expired(self):
        """Date passée → True."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert is_decision_expired({"expires_at": past}) is True

    def test_malformed_date_returns_false(self):
        """Date malformée → False (pas d'exception)."""
        assert is_decision_expired({"expires_at": "not-a-date"}) is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_sla_status()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetSlaStatus:

    def test_no_expiry_returns_has_sla_false(self):
        """Décision sans SLA → {has_sla: False}."""
        status = get_sla_status({"expires_at": None})
        assert status["has_sla"] is False

    def test_future_expiry_returns_remaining_days(self):
        """30 jours dans le futur → remaining_days ≈ 30, expired=False."""
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        status = get_sla_status({"expires_at": future})
        assert status["has_sla"] is True
        assert status["expired"] is False
        assert 28 <= status["remaining_days"] <= 31

    def test_past_expiry_returns_expired_true(self):
        """Date passée → expired=True."""
        past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        status = get_sla_status({"expires_at": past})
        assert status["expired"] is True
        assert status["remaining_days"] < 0

    def test_j_minus_7_triggers_warning(self):
        """5 jours restants → warning=True (seuil J-7)."""
        soon = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        status = get_sla_status({"expires_at": soon})
        assert status["warning"] is True
        assert status["expired"] is False

    def test_30_days_remaining_no_warning(self):
        """30 jours restants → warning=False."""
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        status = get_sla_status({"expires_at": future})
        assert status["warning"] is False
