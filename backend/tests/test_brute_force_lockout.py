"""
Module : test_brute_force_lockout.py
Rôle   : Sprint 1 — Fix 4 — Vérifie la protection brute-force par username.
         Teste get_lockout_status(), record_failed_login(), reset_failed_logins()
         directement sur la couche service (sans passer par HTTP).

Scénarios couverts :
  - Compte sans historique d'échec → non verrouillé
  - N-1 échecs → non verrouillé, attempts_left décrémenté
  - N échecs (atteinte du seuil) → verrouillé avec durée correcte
  - Reset après login réussi → compteur remis à zéro, verrouillage levé
  - Verrouillage expiré naturellement → compte accessible
  - Utilisateur inexistant → aucune exception, pas de création fantôme
  - Paramètres configurables via env (MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES)

Dépend : pytest, db_test_engine (conftest.py)
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
from datetime import datetime, timezone, timedelta

os.environ.setdefault("JWT_SECRET_KEY",        "test-secret-for-lockout")
os.environ.setdefault("LOGIN_MAX_ATTEMPTS",    "5")
os.environ.setdefault("LOGIN_LOCKOUT_MINUTES", "30")

# ── Imports ───────────────────────────────────────────────────────────────────
import pytest
from auth.users import (
    init_db, create_user, get_user,
    get_lockout_status, record_failed_login, reset_failed_logins,
    MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db(db_test_engine):
    """Vide la table users et crée une DB vierge avant chaque test."""
    from sqlalchemy import text as _t
    with db_test_engine.begin() as conn:
        conn.execute(_t("DELETE FROM users"))
    yield


@pytest.fixture
def alice(fresh_db):
    """Crée l'utilisateur 'alice' et retourne son dict."""
    return create_user("alice", "AlicePass1!", role="reader")


# ── Paramètres configurables ──────────────────────────────────────────────────

class TestConfig:

    def test_max_attempts_from_env(self):
        """MAX_FAILED_ATTEMPTS est bien lu depuis LOGIN_MAX_ATTEMPTS."""
        assert MAX_FAILED_ATTEMPTS == 5

    def test_lockout_minutes_from_env(self):
        """LOCKOUT_MINUTES est bien lu depuis LOGIN_LOCKOUT_MINUTES."""
        assert LOCKOUT_MINUTES == 30


# ── get_lockout_status() ──────────────────────────────────────────────────────

class TestGetLockoutStatus:

    def test_unknown_user_not_locked(self):
        """Utilisateur inexistant → locked=False, aucune exception."""
        status = get_lockout_status("nobody")
        assert status["locked"] is False
        assert status["failed_count"] == 0

    def test_fresh_user_not_locked(self, alice):
        """Nouveau compte → non verrouillé, compteur à zéro."""
        status = get_lockout_status("alice")
        assert status["locked"] is False
        assert status["failed_count"] == 0
        assert status["attempts_left"] == MAX_FAILED_ATTEMPTS

    def test_attempts_left_decrements(self, alice):
        """attempts_left diminue à chaque échec."""
        record_failed_login("alice")
        record_failed_login("alice")
        status = get_lockout_status("alice")
        assert status["failed_count"] == 2
        assert status["attempts_left"] == MAX_FAILED_ATTEMPTS - 2
        assert status["locked"] is False

    def test_locked_after_max_attempts(self, alice):
        """Compte verrouillé après MAX_FAILED_ATTEMPTS échecs."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_login("alice")
        status = get_lockout_status("alice")
        assert status["locked"] is True
        assert status["attempts_left"] == 0
        assert status["remaining_seconds"] > 0

    def test_remaining_seconds_approximately_correct(self, alice):
        """remaining_seconds ≈ LOCKOUT_MINUTES × 60 (± 5s)."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_login("alice")
        status = get_lockout_status("alice")
        expected_secs = LOCKOUT_MINUTES * 60
        assert abs(status["remaining_seconds"] - expected_secs) < 5

    def test_locked_until_field_set(self, alice):
        """locked_until est une chaîne ISO après verrouillage."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_login("alice")
        status = get_lockout_status("alice")
        assert status["locked_until"] is not None
        dt = datetime.fromisoformat(status["locked_until"])
        assert dt > datetime.now(timezone.utc)


# ── record_failed_login() ─────────────────────────────────────────────────────

class TestRecordFailedLogin:

    def test_increments_counter(self, alice):
        """Chaque appel incrémente failed_login_count de 1."""
        record_failed_login("alice")
        assert get_lockout_status("alice")["failed_count"] == 1
        record_failed_login("alice")
        assert get_lockout_status("alice")["failed_count"] == 2

    def test_returns_lockout_status(self, alice):
        """Retourne le statut de verrouillage mis à jour."""
        result = record_failed_login("alice")
        assert "locked" in result
        assert "failed_count" in result
        assert result["failed_count"] == 1

    def test_triggers_lock_at_threshold(self, alice):
        """Retourne locked=True exactement au N-ième échec."""
        for i in range(MAX_FAILED_ATTEMPTS - 1):
            r = record_failed_login("alice")
            assert r["locked"] is False, f"Verrouillé trop tôt à l'essai {i+1}"
        r = record_failed_login("alice")
        assert r["locked"] is True

    def test_unknown_user_no_exception(self):
        """record_failed_login sur un user inexistant ne lève pas d'exception."""
        result = record_failed_login("ghost_user")
        assert result["locked"] is False

    def test_no_phantom_user_created(self):
        """record_failed_login ne crée pas d'entrée pour un user inexistant."""
        record_failed_login("ghost_user")
        assert get_user("ghost_user") is None


# ── reset_failed_logins() ─────────────────────────────────────────────────────

class TestResetFailedLogins:

    def test_clears_counter(self, alice):
        """reset_failed_logins remet le compteur à zéro."""
        record_failed_login("alice")
        record_failed_login("alice")
        reset_failed_logins("alice")
        status = get_lockout_status("alice")
        assert status["failed_count"] == 0
        assert status["locked"] is False

    def test_unlocks_locked_account(self, alice):
        """Un compte verrouillé est déverrouillé après reset."""
        for _ in range(MAX_FAILED_ATTEMPTS):
            record_failed_login("alice")
        assert get_lockout_status("alice")["locked"] is True

        reset_failed_logins("alice")
        status = get_lockout_status("alice")
        assert status["locked"] is False
        assert status["locked_until"] is None

    def test_reset_on_unknown_user_no_exception(self):
        """reset_failed_logins sur user inexistant ne lève pas d'exception."""
        reset_failed_logins("nobody")


# ── Expiration naturelle du verrou ────────────────────────────────────────────

class TestLockExpiry:

    def test_lock_appears_expired_when_locked_until_is_past(self, alice):
        """
        Si locked_until est dans le passé, le compte doit apparaître
        comme non verrouillé (le verrou a expiré naturellement).
        """
        from sqlalchemy import text as _t
        from db.engine import db_conn
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with db_conn() as conn:
            conn.execute(_t(
                "UPDATE users SET failed_login_count = :count, locked_until = :ts "
                "WHERE username = :u"
            ), {"count": MAX_FAILED_ATTEMPTS, "ts": past, "u": "alice"})

        status = get_lockout_status("alice")
        assert status["locked"] is False
        assert status["remaining_seconds"] == 0
