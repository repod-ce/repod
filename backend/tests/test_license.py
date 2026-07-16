"""
Tests unitaires — services/license.py

Couverture :
  • TestGenerateLicenseKey     (7)  — génération, format, champs, features par défaut
  • TestDecodeLicenseKey       (9)  — décodage valide, expiration, clé invalide, HMAC forgé
  • TestActivateDeactivate     (6)  — stockage, clé expirée, retour Community
  • TestGetLicenseStatus       (6)  — community, enterprise, clé invalide, erreur settings
  • TestLicenseHelpers         (7)  — get_edition, is_enterprise, check_feature, check_quota
  • TestGetLicenseSummary      (3)  — pas de clé brute exposée
"""

import base64
import hashlib
import hmac as _hmac_mod
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# ── module under test ─────────────────────────────────────────────────────────
import services.license as lic_mod
from services.license import (
    COMMUNITY_LIMITS,
    ENTERPRISE_FEATURES,
    LicenseError,
    _decode_license_key,
    _vendor_key,
    activate_license,
    check_feature,
    check_quota,
    deactivate_license,
    generate_license_key,
    get_edition,
    get_license_status,
    get_license_summary,
    is_enterprise,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _forge_key(payload: dict, key: bytes | None = None) -> str:
    """Fabrique une clé de licence signée avec la clé vendeur courante (ou `key`)."""
    actual_key = key if key is not None else _vendor_key()
    payload_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig = _hmac_mod.new(actual_key, payload_b64.encode("ascii"), digestmod=hashlib.sha256).hexdigest()
    return f"repod_lic_{payload_b64}.{sig}"


def _future_iso(days: int = 365) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past_iso(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _enterprise_payload(**overrides) -> dict:
    base = {
        "edition":           "enterprise",
        "license_id":        "test-" + secrets.token_hex(4),
        "issued_to":         "ACME Corp",
        "issued_at":         datetime.now(timezone.utc).isoformat(),
        "expires_at":        _future_iso(365),
        "max_packages":      0,
        "max_users":         0,
        "max_distributions": 0,
        "features":          list(ENTERPRISE_FEATURES),
    }
    base.update(overrides)
    return base


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestGenerateLicenseKey
# ═════════════════════════════════════════════════════════════════════════════

class TestGenerateLicenseKey:
    def test_prefix(self):
        key = generate_license_key("enterprise", "Test Org")
        assert key.startswith("repod_lic_")

    def test_format_two_parts(self):
        key = generate_license_key("enterprise", "Test Org")
        body = key[len("repod_lic_"):]
        assert "." in body
        parts = body.rsplit(".", 1)
        assert len(parts) == 2
        payload_b64, sig = parts
        assert len(sig) == 64  # SHA-256 hexdigest

    def test_payload_fields(self):
        key = generate_license_key(
            "enterprise", "Widgets SAS",
            max_packages=200, max_users=10, max_distributions=5,
            expires_days=180,
        )
        decoded = _decode_license_key(key)
        assert decoded["edition"] == "enterprise"
        assert decoded["issued_to"] == "Widgets SAS"
        assert decoded["max_packages"] == 200
        assert decoded["max_users"] == 10
        assert decoded["max_distributions"] == 5
        assert decoded["valid"] is True
        assert decoded["active"] is True

    def test_features_default_all_enterprise(self):
        key = generate_license_key("enterprise", "Corp")
        decoded = _decode_license_key(key)
        assert set(decoded["features"]) == ENTERPRISE_FEATURES

    def test_features_custom_subset(self):
        key = generate_license_key("enterprise", "Corp", features=["ldap", "oidc"])
        decoded = _decode_license_key(key)
        assert set(decoded["features"]) == {"ldap", "oidc"}

    def test_no_expiry(self):
        key = generate_license_key("enterprise", "Corp", expires_days=None)
        decoded = _decode_license_key(key)
        assert decoded["expires_at"] is None
        assert decoded["active"] is True

    def test_custom_license_id(self):
        key = generate_license_key("enterprise", "Corp", license_id="lic-abc-123")
        decoded = _decode_license_key(key)
        assert decoded["license_id"] == "lic-abc-123"


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestDecodeLicenseKey
# ═════════════════════════════════════════════════════════════════════════════

class TestDecodeLicenseKey:
    def test_valid_key_returns_payload(self):
        payload = _enterprise_payload()
        key = _forge_key(payload)
        result = _decode_license_key(key)
        assert result["edition"] == "enterprise"
        assert result["issued_to"] == "ACME Corp"

    def test_valid_active_flags(self):
        payload = _enterprise_payload(expires_at=_future_iso(30))
        key = _forge_key(payload)
        result = _decode_license_key(key)
        assert result["valid"] is True
        assert result["active"] is True
        assert result["expired"] is False
        assert result["days_remaining"] is not None
        assert result["days_remaining"] > 0

    def test_expired_key(self):
        payload = _enterprise_payload(expires_at=_past_iso(1))
        key = _forge_key(payload)
        result = _decode_license_key(key)
        assert result["valid"] is True
        assert result["active"] is False
        assert result["expired"] is True
        assert result["days_remaining"] == 0

    def test_no_expiry_active(self):
        payload = _enterprise_payload(expires_at=None)
        key = _forge_key(payload)
        result = _decode_license_key(key)
        assert result["active"] is True
        assert result["days_remaining"] is None

    def test_missing_prefix_raises(self):
        with pytest.raises(LicenseError, match="préfixe"):
            _decode_license_key("wrong_prefix_abc.def")

    def test_empty_key_raises(self):
        with pytest.raises(LicenseError):
            _decode_license_key("")

    def test_missing_signature_raises(self):
        with pytest.raises(LicenseError, match="signature"):
            _decode_license_key("repod_lic_abc")

    def test_invalid_signature_raises(self):
        payload = _enterprise_payload()
        good_key = _forge_key(payload)
        tampered = good_key[:-4] + "aaaa"  # alter the last 4 hex chars
        with pytest.raises(LicenseError, match="[Ss]ignature"):
            _decode_license_key(tampered)

    def test_wrong_vendor_key_raises(self):
        # Sign with a different key → should fail on decode
        wrong_key = b"totally-different-vendor-key-00000000000000000000000000000000"
        payload = _enterprise_payload()
        bad_key = _forge_key(payload, key=wrong_key)
        with pytest.raises(LicenseError, match="[Ss]ignature"):
            _decode_license_key(bad_key)


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestActivateDeactivate
# ═════════════════════════════════════════════════════════════════════════════

class TestActivateDeactivate:
    def test_activate_stores_key(self):
        key = generate_license_key("enterprise", "Store Test")
        stored = {}

        def _fake_update(partial):
            stored.update(partial)

        with patch("services.settings.update_settings", side_effect=_fake_update):
            result = activate_license(key)

        assert stored.get("license", {}).get("key") == key
        assert result["edition"] == "enterprise"
        assert result["issued_to"] == "Store Test"

    def test_activate_returns_decoded(self):
        key = generate_license_key("enterprise", "ReturnTest", max_packages=100)
        with patch("services.settings.update_settings"):
            result = activate_license(key)
        assert result["max_packages"] == 100
        assert result["valid"] is True

    def test_activate_expired_raises(self):
        payload = _enterprise_payload(expires_at=_past_iso(1))
        key = _forge_key(payload)
        with pytest.raises(LicenseError, match="[Ee]xpir"):
            activate_license(key)

    def test_activate_invalid_key_raises(self):
        with pytest.raises(LicenseError):
            activate_license("repod_lic_garbage.invalidhex")

    def test_deactivate_clears_key(self):
        stored = {}

        def _fake_update(partial):
            stored.update(partial)

        with patch("services.settings.update_settings", side_effect=_fake_update):
            deactivate_license()

        assert stored.get("license", {}).get("key") == ""

    def test_deactivate_does_not_raise(self):
        with patch("services.settings.update_settings"):
            deactivate_license()  # must not raise


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestGetLicenseStatus
# ═════════════════════════════════════════════════════════════════════════════

class TestGetLicenseStatus:
    def test_no_key_returns_community(self):
        with patch("services.license._load_stored_key", return_value=None):
            status = get_license_status()
        assert status["edition"] == "community"
        assert status["valid"] is True

    def test_empty_key_returns_community(self):
        with patch("services.license._load_stored_key", return_value=""):
            status = get_license_status()
        assert status["edition"] == "community"

    def test_valid_enterprise_key(self):
        key = generate_license_key("enterprise", "Status Test")
        with patch("services.license._load_stored_key", return_value=key):
            status = get_license_status()
        assert status["edition"] == "enterprise"
        assert status["valid"] is True
        assert status["active"] is True

    def test_expired_key_returns_community_fields_with_inactive(self):
        payload = _enterprise_payload(expires_at=_past_iso(1))
        key = _forge_key(payload)
        with patch("services.license._load_stored_key", return_value=key):
            status = get_license_status()
        # expired key is decoded successfully but active=False
        assert status["active"] is False
        assert status["valid"] is True

    def test_invalid_key_returns_community_with_error(self):
        with patch("services.license._load_stored_key", return_value="repod_lic_bad.key"):
            status = get_license_status()
        assert status["edition"] == "community"
        assert status["valid"] is False
        assert "error" in status

    def test_community_limits_values(self):
        with patch("services.license._load_stored_key", return_value=None):
            status = get_license_status()
        assert status["max_packages"] == 50
        assert status["max_users"] == 5
        assert status["max_distributions"] == 1
        assert status["features"] == []


# ═════════════════════════════════════════════════════════════════════════════
# 5. TestLicenseHelpers
# ═════════════════════════════════════════════════════════════════════════════

class TestLicenseHelpers:
    def _patch_enterprise(self):
        key = generate_license_key("enterprise", "Helper Test")
        return patch("services.license._load_stored_key", return_value=key)

    def _patch_community(self):
        return patch("services.license._load_stored_key", return_value=None)

    def test_get_edition_enterprise(self):
        with self._patch_enterprise():
            assert get_edition() == "enterprise"

    def test_get_edition_community(self):
        with self._patch_community():
            assert get_edition() == "community"

    def test_is_enterprise_true(self):
        with self._patch_enterprise():
            assert is_enterprise() is True

    def test_is_enterprise_false(self):
        with self._patch_community():
            assert is_enterprise() is False

    def test_check_feature_enterprise(self):
        key = generate_license_key("enterprise", "Feat Test", features=["ldap", "oidc"])
        with patch("services.license._load_stored_key", return_value=key):
            assert check_feature("ldap") is True
            assert check_feature("oidc") is True
            assert check_feature("sbom") is False  # not in this licence's features

    def test_check_feature_community(self):
        with self._patch_community():
            assert check_feature("ldap") is False
            assert check_feature("oidc") is False

    def test_check_quota_unlimited(self):
        key = generate_license_key("enterprise", "Quota Test", max_packages=0)
        with patch("services.license._load_stored_key", return_value=key):
            result = check_quota("max_packages", 9999)
        assert result["allowed"] is True
        assert result["limit"] == 0

    def test_check_quota_within_limit(self):
        key = generate_license_key("enterprise", "Quota Test", max_packages=50)
        with patch("services.license._load_stored_key", return_value=key):
            result = check_quota("max_packages", 49)
        assert result["allowed"] is True
        assert result["current"] == 49
        assert result["limit"] == 50

    def test_check_quota_at_limit_blocked(self):
        key = generate_license_key("enterprise", "Quota Test", max_packages=50)
        with patch("services.license._load_stored_key", return_value=key):
            result = check_quota("max_packages", 50)
        assert result["allowed"] is False

    def test_check_quota_community_default(self):
        with self._patch_community():
            result = check_quota("max_packages", 49)
        assert result["edition"] == "community"
        assert result["limit"] == 50

    def test_check_quota_community_over_limit(self):
        with self._patch_community():
            result = check_quota("max_packages", 51)
        assert result["allowed"] is False


# ═════════════════════════════════════════════════════════════════════════════
# 6. TestGetLicenseSummary
# ═════════════════════════════════════════════════════════════════════════════

class TestGetLicenseSummary:
    def test_no_raw_key_in_summary(self):
        """La clé brute ne doit jamais apparaître dans la réponse API."""
        key = generate_license_key("enterprise", "Summary Test")
        with patch("services.license._load_stored_key", return_value=key):
            summary = get_license_summary()
        assert "key" not in summary

    def test_summary_contains_edition(self):
        with patch("services.license._load_stored_key", return_value=None):
            summary = get_license_summary()
        assert "edition" in summary

    def test_summary_enterprise_fields(self):
        key = generate_license_key(
            "enterprise", "Sum Corp",
            max_packages=100, features=["ldap"],
        )
        with patch("services.license._load_stored_key", return_value=key):
            summary = get_license_summary()
        assert summary["edition"] == "enterprise"
        assert summary["max_packages"] == 100
        assert "ldap" in summary["features"]
