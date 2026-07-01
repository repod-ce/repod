"""
Tests de couverture — Sprint 9.5
Objectif : ≥ 85% de couverture globale.

Modules ciblés :
  • services/indexer.py          — _extract_cve_summary, remove/list/sync
  • services/retention.py        — _purge_audit_logs, _purge_old_packages
  • services/validator.py        — ValidationResult, validate_checksum, validate_gpg,
                                   validate_provenance_sha256, validate_dependencies
  • services/distributions.py    — _reprepro_env, list/promote/migrate (subprocess mocké)
  • routers/settings_router.py   — _mask_secrets, endpoints (TestClient)
  • services/manifest.py         — branches SQLite non couvertes
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_sprint95_test_")
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
import json
import queue
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# 1. TestIndexerFunctions  (services/indexer.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractCveSummary:
    """_extract_cve_summary — parsing des steps de validation."""

    def _fn(self):
        from services.indexer import _extract_cve_summary
        return _extract_cve_summary

    def test_no_cve_step_returns_none(self):
        fn = self._fn()
        assert fn([]) is None
        assert fn([{"name": "format", "passed": True}]) is None

    def test_cve_step_returns_dict_with_keys(self):
        fn = self._fn()
        steps = [{"name": "cve", "passed": True, "message": "Grype — 0 CVE détectée", "detail": ""}]
        result = fn(steps)
        assert result is not None
        assert "critical" in result
        assert "high" in result
        assert result["scanned"] is True

    def test_parses_counts_from_message(self):
        fn = self._fn()
        # Format message : "Grype — 2 Critical | 1 High | 0 Medium"
        steps = [{"name": "cve", "passed": False,
                  "message": "Grype — CVE(s) bloquante(s) : 2 Critical | 1 High | 0 Medium",
                  "detail": ""}]
        result = fn(steps)
        assert result is not None
        assert result["critical"] == 2
        assert result["high"] == 1

    def test_passed_flag_carried_over(self):
        fn = self._fn()
        steps = [{"name": "cve", "passed": False, "message": "", "detail": ""}]
        result = fn(steps)
        assert result["passed"] is False

    def test_empty_message_returns_zero_counts(self):
        fn = self._fn()
        steps = [{"name": "cve", "passed": True, "message": "", "detail": ""}]
        result = fn(steps)
        for sev in ("critical", "high", "medium", "low", "negligible"):
            assert result[sev] == 0


class TestIndexerCRUD:
    """add_to_index / remove_from_index / get_index / list_packages_from_index."""

    @pytest.fixture(autouse=True)
    def clean_index(self, tmp_path):
        """Chaque test utilise un fichier index isolé."""
        import services.indexer as idx
        self._orig = idx.INDEX_PATH
        idx.INDEX_PATH = tmp_path / "index.json"
        yield
        idx.INDEX_PATH = self._orig

    def _manifest(self, name="nginx", version="1.0", arch="amd64"):
        return {
            "name": name,
            "version": version,
            "arch": arch,
            "filename": f"{name}_{version}_{arch}.deb",
            "integrity": {"sha256": "abc123"},
            "file_size_bytes": 1024,
            "source": {
                "imported_at": "2025-01-01T00:00:00+00:00",
                "imported_by": "test",
            },
            "status": "validated",
            "distribution": "jammy",
            "dependencies": [],
            "validation_steps": [],
            "description": "Test package",
            "section": "main",
        }

    def test_add_and_get(self):
        from services.indexer import add_to_index, get_index
        add_to_index(self._manifest())
        idx = get_index()
        assert "nginx" in idx["packages"]
        assert "1.0" in idx["packages"]["nginx"]["versions"]

    def test_remove_specific_version(self):
        from services.indexer import add_to_index, remove_from_index, get_index
        add_to_index(self._manifest(version="1.0"))
        add_to_index(self._manifest(version="2.0"))
        remove_from_index("nginx", "1.0")
        idx = get_index()
        assert "1.0" not in idx["packages"]["nginx"]["versions"]
        assert "2.0" in idx["packages"]["nginx"]["versions"]
        # latest is updated
        assert idx["packages"]["nginx"]["latest"] == "2.0"

    def test_remove_last_version_removes_package(self):
        from services.indexer import add_to_index, remove_from_index, get_index
        add_to_index(self._manifest(version="1.0"))
        remove_from_index("nginx", "1.0")
        idx = get_index()
        assert "nginx" not in idx["packages"]

    def test_remove_whole_package(self):
        from services.indexer import add_to_index, remove_from_index, get_index
        add_to_index(self._manifest(version="1.0"))
        remove_from_index("nginx")  # version=None → remove all
        idx = get_index()
        assert "nginx" not in idx["packages"]

    def test_remove_nonexistent_package_safe(self):
        from services.indexer import remove_from_index
        remove_from_index("nonexistent")  # Ne doit pas lever

    def test_list_packages_recalculates_deps_missing(self):
        from services.indexer import add_to_index, list_packages_from_index
        m = self._manifest(name="app")
        m["dependencies"] = [{"name": "libssl", "available_internally": False}]
        m["integrity"] = {"sha256": "xyz"}
        # Recalculate : libssl not in index → still missing
        add_to_index(m)
        packages = list_packages_from_index()
        app_pkg = next(p for p in packages if p["name"] == "app")
        assert "libssl" in app_pkg["deps_missing"]

    def test_list_packages_clears_dep_when_installed(self):
        from services.indexer import add_to_index, list_packages_from_index
        # Add libssl to index
        add_to_index(self._manifest(name="libssl", version="1.0"))
        # Add app that depends on libssl
        m = self._manifest(name="app")
        m["dependencies"] = [{"name": "libssl", "available_internally": False}]
        add_to_index(m)
        packages = list_packages_from_index()
        app_pkg = next(p for p in packages if p["name"] == "app")
        # libssl now IS in index → dep no longer missing
        assert "libssl" not in app_pkg["deps_missing"]

    def test_sync_index_from_pool(self, tmp_path):
        from services.indexer import sync_index_from_pool, get_index
        m = self._manifest(name="curl")
        # sync_index_from_pool uses "from services.manifest import list_manifests"
        with patch("services.manifest.list_manifests", return_value=[m]):
            count = sync_index_from_pool()
        assert count == 1
        idx = get_index()
        assert "curl" in idx["packages"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. TestRetentionFunctions  (services/retention.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestParseImportedAt:
    def _fn(self):
        from services.retention import _parse_imported_at
        return _parse_imported_at

    def test_valid_iso_date(self):
        fn = self._fn()
        m = {"source": {"imported_at": "2025-01-15T10:00:00+00:00"}}
        dt = fn(m)
        assert dt is not None
        assert dt.year == 2025

    def test_missing_imported_at(self):
        fn = self._fn()
        dt = fn({"source": {}})
        assert dt is None

    def test_missing_source_key(self):
        fn = self._fn()
        dt = fn({})
        assert dt is None

    def test_invalid_date_string(self):
        fn = self._fn()
        dt = fn({"source": {"imported_at": "not-a-date"}})
        assert dt is None


class TestPurgeAuditLogs:
    @pytest.fixture
    def audit_dir(self, tmp_path):
        import services.audit as _audit_mod
        orig = _audit_mod.AUDIT_DIR
        _audit_mod.AUDIT_DIR = tmp_path
        yield tmp_path
        _audit_mod.AUDIT_DIR = orig

    def _purge(self, days):
        import importlib
        import services.retention as ret
        importlib.reload(ret)  # Recharger pour que AUDIT_DIR soit frais
        # Appel direct avec le bon AUDIT_DIR via patch
        from services.retention import _purge_audit_logs
        return _purge_audit_logs(days)

    def test_zero_days_returns_empty(self, audit_dir):
        from services.retention import _purge_audit_logs
        result = _purge_audit_logs(0)
        assert result == {"deleted": 0, "kept": 0, "freed_bytes": 0}

    def test_negative_days_returns_empty(self, audit_dir):
        from services.retention import _purge_audit_logs
        result = _purge_audit_logs(-1)
        assert result == {"deleted": 0, "kept": 0, "freed_bytes": 0}

    def test_old_file_gets_deleted(self, audit_dir):
        import services.audit as _audit_mod
        import services.retention as ret
        # Patcher AUDIT_DIR dans le module retention
        old_date = (datetime.now(timezone.utc).date() - timedelta(days=100)).strftime("%Y-%m-%d")
        old_file = audit_dir / f"{old_date}.jsonl"
        old_file.write_text('{"action": "test"}\n')

        with patch.object(ret, "_purge_audit_logs") as mock_fn:
            # Patcher directement pour isoler
            pass

        # Test direct avec AUDIT_DIR patché dans le module
        orig_audit_dir = _audit_mod.AUDIT_DIR
        _audit_mod.AUDIT_DIR = audit_dir
        try:
            # Recréer le fichier puisqu'il a peut-être été supprimé
            old_file.write_text('{"action": "test"}\n')
            from services.retention import _purge_audit_logs as fn

            # Patch AUDIT_DIR in retention module directly
            import services.retention as ret_mod
            orig_ret = ret_mod.AUDIT_DIR
            ret_mod.AUDIT_DIR = audit_dir
            try:
                result = fn(30)  # 30 days cutoff, file is 100 days old
                assert result["deleted"] >= 1 or old_file.exists() is False
            finally:
                ret_mod.AUDIT_DIR = orig_ret
        finally:
            _audit_mod.AUDIT_DIR = orig_audit_dir

    def test_recent_file_is_kept(self, audit_dir):
        import services.audit as _audit_mod
        import services.retention as ret_mod
        today = datetime.now(timezone.utc).date().strftime("%Y-%m-%d")
        new_file = audit_dir / f"{today}.jsonl"
        new_file.write_text('{"action": "test"}\n')

        orig_ret = ret_mod.AUDIT_DIR
        ret_mod.AUDIT_DIR = audit_dir
        try:
            from services.retention import _purge_audit_logs as fn
            result = fn(30)
            assert result["kept"] >= 1
            assert new_file.exists()
        finally:
            ret_mod.AUDIT_DIR = orig_ret

    def test_non_date_filename_is_skipped(self, audit_dir):
        import services.retention as ret_mod
        bad_file = audit_dir / "not-a-date.jsonl"
        bad_file.write_text("data\n")

        orig_ret = ret_mod.AUDIT_DIR
        ret_mod.AUDIT_DIR = audit_dir
        try:
            from services.retention import _purge_audit_logs as fn
            result = fn(1)
            # The bad-named file should be in "kept" (ValueError → kept += 1)
            assert result["kept"] >= 1
            assert bad_file.exists()
        finally:
            ret_mod.AUDIT_DIR = orig_ret


class TestPurgeOldPackages:
    def test_zero_days_returns_empty(self):
        from services.retention import _purge_old_packages
        result = _purge_old_packages(0)
        assert result == {"deleted": 0, "freed_bytes": 0, "packages": []}

    def test_single_version_never_deleted(self):
        from services.retention import _purge_old_packages
        old_imported = (datetime.now(timezone.utc) - timedelta(days=999)).isoformat()
        manifests = [{
            "name": "nginx", "arch": "amd64", "distribution": "jammy",
            "version": "1.0",
            "source": {"imported_at": old_imported},
            "filename": "nginx_1.0_amd64.deb",
        }]
        with patch("services.retention.list_manifests", return_value=manifests):
            result = _purge_old_packages(30)
        # Single version — should NEVER be deleted
        assert result["deleted"] == 0

    def test_old_version_deleted_when_newer_exists(self, tmp_path):
        import services.retention as ret_mod
        from services.retention import _purge_old_packages

        old_imported = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        new_imported = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        manifests = [
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "7.0",
                "source": {"imported_at": old_imported},
                "filename": "curl_7.0_amd64.deb",
            },
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "8.0",
                "source": {"imported_at": new_imported},
                "filename": "curl_8.0_amd64.deb",
            },
        ]

        # Create the manifest file so it can be deleted
        manifest_path = tmp_path / "curl_7.0_amd64.manifest.json"
        manifest_path.write_text("{}")
        # Create the pool .deb file
        pool_path = tmp_path / "curl_7.0_amd64.deb"
        pool_path.write_bytes(b"fake deb")

        with patch("services.retention.list_manifests", return_value=manifests):
            with patch("services.retention.MANIFEST_DIR", tmp_path):
                with patch("services.retention.POOL_DIR", tmp_path):
                    result = _purge_old_packages(30)

        # Old version is old enough (60 days > 30 cutoff) and newer exists → deleted
        assert result["deleted"] == 1
        assert result["packages"][0]["version"] == "7.0"

    def test_version_too_recent_is_kept(self, tmp_path):
        from services.retention import _purge_old_packages

        recent_old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        new_imported = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()

        manifests = [
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "7.0",
                "source": {"imported_at": recent_old},
                "filename": "curl_7.0_amd64.deb",
            },
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "8.0",
                "source": {"imported_at": new_imported},
                "filename": "curl_8.0_amd64.deb",
            },
        ]

        with patch("services.retention.list_manifests", return_value=manifests):
            with patch("services.retention.MANIFEST_DIR", tmp_path):
                with patch("services.retention.POOL_DIR", tmp_path):
                    result = _purge_old_packages(30)

        # 10 days < 30 days cutoff → kept
        assert result["deleted"] == 0

    def test_no_imported_at_skips_version(self, tmp_path):
        from services.retention import _purge_old_packages

        manifests = [
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "7.0",
                "source": {},   # no imported_at
                "filename": "curl_7.0_amd64.deb",
            },
            {
                "name": "curl", "arch": "amd64", "distribution": "jammy",
                "version": "8.0",
                "source": {"imported_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()},
                "filename": "curl_8.0_amd64.deb",
            },
        ]

        with patch("services.retention.list_manifests", return_value=manifests):
            with patch("services.retention.MANIFEST_DIR", tmp_path):
                with patch("services.retention.POOL_DIR", tmp_path):
                    result = _purge_old_packages(30)

        # Skipped because no imported_at → 0 deleted
        assert result["deleted"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 3. TestValidatorFunctions  (services/validator.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestValidationResult:
    def test_add_step_warning_does_not_fail_overall(self):
        from services.validator import ValidationResult
        vr = ValidationResult()
        vr.add_step("test_step", False, "msg", warning=True)
        # warning=True → passed should still be True
        assert vr.passed is True
        # Entry has warning key
        assert vr.steps[-1]["warning"] is True

    def test_add_step_without_warning_fails_overall(self):
        from services.validator import ValidationResult
        vr = ValidationResult()
        vr.add_step("step", False, "fail")
        assert vr.passed is False

    def test_to_dict_includes_cve_status(self):
        from services.validator import ValidationResult
        vr = ValidationResult()
        vr.cve_status = "pending_review"
        d = vr.to_dict()
        assert d["cve_status"] == "pending_review"
        assert "steps" in d
        assert "passed" in d


class TestExtractCvss:
    def test_returns_score_when_present(self):
        from services.validator import _extract_cvss
        vuln = {"cvss": [{"metrics": {"baseScore": 7.5}}]}
        assert _extract_cvss(vuln) == 7.5

    def test_returns_none_when_no_cvss(self):
        from services.validator import _extract_cvss
        assert _extract_cvss({}) is None
        assert _extract_cvss({"cvss": []}) is None

    def test_returns_none_when_score_is_none(self):
        from services.validator import _extract_cvss
        vuln = {"cvss": [{"metrics": {"baseScore": None}}]}
        assert _extract_cvss(vuln) is None

    def test_skips_invalid_score(self):
        from services.validator import _extract_cvss
        vuln = {"cvss": [
            {"metrics": {"baseScore": "bad"}},
            {"metrics": {"baseScore": 5.0}},
        ]}
        result = _extract_cvss(vuln)
        assert result == 5.0


class TestValidateChecksum:
    def test_checksum_match_passes(self, tmp_path):
        from services.validator import validate_checksum, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"fake deb content")

        from services.manifest import compute_sha256
        real_sha = compute_sha256(str(f))

        vr = ValidationResult()
        validate_checksum(str(f), real_sha, vr)
        assert any(s["passed"] for s in vr.steps if s["name"] == "checksum")

    def test_checksum_mismatch_fails(self, tmp_path):
        from services.validator import validate_checksum, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"fake deb content")

        vr = ValidationResult()
        validate_checksum(str(f), "wrong_sha256_value", vr)
        assert any(not s["passed"] for s in vr.steps if s["name"] == "checksum")

    def test_no_expected_sha_always_passes(self, tmp_path):
        from services.validator import validate_checksum, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"content")
        vr = ValidationResult()
        validate_checksum(str(f), None, vr)
        assert any(s["passed"] for s in vr.steps if s["name"] == "checksum")


class TestValidateProvenanceSha256:
    def test_no_expected_sha256_passes_with_note(self, tmp_path):
        from services.validator import validate_provenance_sha256, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"data")
        vr = ValidationResult()
        validate_provenance_sha256(str(f), None, vr)
        step = next(s for s in vr.steps if s["name"] == "provenance")
        assert step["passed"] is True
        assert "manuel" in step["message"]

    def test_correct_sha256_passes(self, tmp_path):
        from services.validator import validate_provenance_sha256, ValidationResult
        from services.manifest import compute_sha256
        f = tmp_path / "test.deb"
        f.write_bytes(b"deb content")
        real_sha = compute_sha256(str(f))
        vr = ValidationResult()
        validate_provenance_sha256(str(f), real_sha, vr)
        step = next(s for s in vr.steps if s["name"] == "provenance")
        assert step["passed"] is True

    def test_wrong_sha256_fails(self, tmp_path):
        from services.validator import validate_provenance_sha256, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"deb content")
        vr = ValidationResult()
        validate_provenance_sha256(str(f), "aabbccdd" * 8, vr)
        step = next(s for s in vr.steps if s["name"] == "provenance")
        assert step["passed"] is False


class TestValidateGpg:
    def test_no_sig_file_passes_with_note(self, tmp_path):
        from services.validator import validate_gpg, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"data")
        vr = ValidationResult()
        validate_gpg(str(f), vr)
        step = next(s for s in vr.steps if s["name"] == "gpg")
        assert step["passed"] is True
        assert "optional" in step["message"].lower() or "signature" in step["message"].lower()

    def test_valid_sig_file_accepted(self, tmp_path):
        from services.validator import validate_gpg, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"data")
        sig = tmp_path / "test.deb.sig"
        sig.write_bytes(b"fake sig")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = "Good signature"

        with patch("subprocess.run", return_value=mock_result):
            vr = ValidationResult()
            validate_gpg(str(f), vr)

        step = next(s for s in vr.steps if s["name"] == "gpg")
        assert step["passed"] is True

    def test_invalid_sig_fails(self, tmp_path):
        from services.validator import validate_gpg, ValidationResult
        f = tmp_path / "test.deb"
        f.write_bytes(b"data")
        asc = tmp_path / "test.deb.asc"
        asc.write_bytes(b"bad sig")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "BAD signature"

        with patch("subprocess.run", return_value=mock_result):
            vr = ValidationResult()
            validate_gpg(str(f), vr)

        step = next(s for s in vr.steps if s["name"] == "gpg")
        assert step["passed"] is False


class TestValidateDependencies:
    def test_no_deps_passes(self, tmp_path):
        from services.validator import validate_dependencies, ValidationResult
        f = tmp_path / "no-deps.deb"
        f.write_bytes(b"deb")

        with patch("services.validator_apt._resolve_deps_recursive", return_value=[]):
            vr = ValidationResult()
            deps = validate_dependencies(str(f), vr)
        assert deps == []
        step = next(s for s in vr.steps if s["name"] == "dependencies")
        assert step["passed"] is True

    def test_all_deps_available_passes(self, tmp_path):
        from services.validator import validate_dependencies, ValidationResult
        f = tmp_path / "with-deps.deb"
        f.write_bytes(b"deb")

        fake_deps = [
            {"name": "libssl", "available_internally": True, "depth": 1},
            {"name": "libc6", "available_internally": True, "depth": 1},
        ]
        with patch("services.validator_apt._resolve_deps_recursive", return_value=fake_deps):
            vr = ValidationResult()
            deps = validate_dependencies(str(f), vr)
        step = next(s for s in vr.steps if s["name"] == "dependencies")
        assert step["passed"] is True

    def test_missing_deps_fails(self, tmp_path):
        from services.validator import validate_dependencies, ValidationResult
        f = tmp_path / "missing.deb"
        f.write_bytes(b"deb")

        fake_deps = [
            {"name": "libssl", "available_internally": False, "depth": 1},
            {"name": "libc6", "available_internally": True, "depth": 1},
        ]
        with patch("services.validator_apt._resolve_deps_recursive", return_value=fake_deps):
            vr = ValidationResult()
            validate_dependencies(str(f), vr)
        step = next(s for s in vr.steps if s["name"] == "dependencies")
        assert step["passed"] is False
        assert "libssl" in step["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# 4. TestDistributionsFunctions  (services/distributions.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestDistributionsModule:
    def test_detect_known_source(self):
        from services.distributions import detect_distribution_from_source
        assert detect_distribution_from_source("ubuntu-jammy") == "jammy"
        assert detect_distribution_from_source("ubuntu-noble") == "noble"
        assert detect_distribution_from_source("debian-bookworm") == "bookworm"
        assert detect_distribution_from_source("ubuntu-focal") == "focal"

    def test_detect_unknown_source_defaults_to_jammy(self):
        from services.distributions import detect_distribution_from_source
        assert detect_distribution_from_source("totally-unknown") == "jammy"
        assert detect_distribution_from_source("") == "jammy"

    def test_reprepro_env_contains_gnupghome(self):
        from services.distributions import _reprepro_env
        env = _reprepro_env()
        assert "GNUPGHOME" in env

    def test_list_packages_in_distrib_success(self):
        from services.distributions import list_packages_in_distrib

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "jammy|main|amd64: nginx 1.18.0-0ubuntu1\n"
            "jammy|main|amd64: curl 7.81.0-1ubuntu1.13\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            packages = list_packages_in_distrib("jammy")

        assert len(packages) == 2
        names = [p["name"] for p in packages]
        assert "nginx" in names
        assert "curl" in names

    def test_list_packages_in_distrib_failure_returns_empty(self):
        from services.distributions import list_packages_in_distrib

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch("subprocess.run", return_value=mock_result):
            packages = list_packages_in_distrib("jammy")

        assert packages == []

    def test_list_packages_deduplicates(self):
        from services.distributions import list_packages_in_distrib

        mock_result = MagicMock()
        mock_result.returncode = 0
        # Same package twice (e.g., different components)
        mock_result.stdout = (
            "jammy|main|amd64: nginx 1.18.0\n"
            "jammy|universe|amd64: nginx 1.18.0\n"
        )

        with patch("subprocess.run", return_value=mock_result):
            packages = list_packages_in_distrib("jammy")

        assert len(packages) == 1

    def test_promote_package_success(self):
        from services.distributions import promote_package

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "copied"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            ok, msg = promote_package("nginx", "jammy", "noble")

        assert ok is True
        assert "nginx" in msg

    def test_promote_package_already_present(self):
        from services.distributions import promote_package

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "already up-to-date"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            ok, msg = promote_package("nginx", "jammy", "noble")

        assert ok is True
        assert "déjà" in msg

    def test_promote_package_failure(self):
        from services.distributions import promote_package

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "gpg error"

        with patch("subprocess.run", return_value=mock_result):
            ok, msg = promote_package("nginx", "jammy", "noble")

        assert ok is False
        assert "gpg error" in msg

    def test_migrate_all_empty_distrib(self):
        from services.distributions import migrate_all

        with patch("services.distributions_apt.list_packages_in_distrib", return_value=[]):
            copied, c_list, errors = migrate_all("jammy", "noble")

        assert copied == 0
        assert c_list == []
        assert errors == []

    def test_migrate_all_mixed_results(self):
        from services.distributions import migrate_all

        packages = [{"name": "nginx"}, {"name": "broken"}]
        with patch("services.distributions_apt.list_packages_in_distrib", return_value=packages):
            def _fake_promote(name, frm, to):
                if name == "nginx":
                    return True, "ok"
                return False, "error"
            with patch("services.distributions_apt.promote_package", side_effect=_fake_promote):
                copied, c_list, errors = migrate_all("jammy", "noble")

        assert copied == 1
        assert "nginx" in c_list
        assert len(errors) == 1


# ─────────────────────────────────────────────────────────────────────────────
# 5. TestSettingsRouter  (routers/settings_router.py)
# ─────────────────────────────────────────────────────────────────────────────

def _load_settings_router_mod():
    """Charge settings_router via importlib pour éviter routers/__init__.py."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "settings_router_95_direct",
        Path(__file__).parent.parent / "routers" / "settings_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SR_MOD = _load_settings_router_mod()


class TestMaskSecrets:
    def test_masks_smtp_password(self):
        obj = {"email": {"smtp_password": "secret123", "host": "mail.example.com"}}
        result = _SR_MOD._mask_secrets(obj)
        assert result["email"]["smtp_password"] == "••••••••"
        assert result["email"]["host"] == "mail.example.com"

    def test_does_not_mask_empty_value(self):
        obj = {"smtp_password": ""}
        result = _SR_MOD._mask_secrets(obj)
        # Empty string is falsy → not masked
        assert result["smtp_password"] == ""

    def test_masks_in_list(self):
        obj = [{"smtp_password": "s3cr3t"}, {"host": "example.com"}]
        result = _SR_MOD._mask_secrets(obj)
        assert result[0]["smtp_password"] == "••••••••"
        assert result[1]["host"] == "example.com"

    def test_strip_masked_secrets_removes_placeholder(self):
        obj = {"smtp_password": "••••••••", "host": "mail.example.com"}
        result = _SR_MOD._strip_masked_secrets(obj)
        assert "smtp_password" not in result
        assert result["host"] == "mail.example.com"

    def test_strip_masked_secrets_keeps_real_password(self):
        obj = {"smtp_password": "real_password", "host": "mail.example.com"}
        result = _SR_MOD._strip_masked_secrets(obj)
        assert result["smtp_password"] == "real_password"

    def test_strip_masked_in_list(self):
        obj = [{"smtp_password": "••••••••"}, {"other": "value"}]
        result = _SR_MOD._strip_masked_secrets(obj)
        assert "smtp_password" not in result[0]
        assert result[1]["other"] == "value"


@pytest.fixture(scope="module")
def settings_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_admin_user

    mod = _SR_MOD  # déjà chargé ci-dessus via importlib

    app = FastAPI()
    app.include_router(mod.router)
    app.dependency_overrides[get_admin_user] = lambda: "admin"
    return TestClient(app), mod


class TestSettingsRouterHTTP:
    def test_get_settings_returns_200(self, settings_client):
        client, _ = settings_client
        resp = client.get("/settings/")
        assert resp.status_code == 200

    def test_get_settings_masks_passwords(self, settings_client):
        client, mod = settings_client
        with patch.object(mod, "get_settings", return_value={
            "email": {"smtp_password": "secret", "host": "smtp.example.com"},
        }):
            resp = client.get("/settings/")
        assert resp.status_code == 200
        body = resp.json()
        if "email" in body and "smtp_password" in body.get("email", {}):
            assert body["email"]["smtp_password"] == "••••••••"

    def test_patch_settings_returns_200(self, settings_client):
        client, _ = settings_client
        resp = client.patch("/settings/", json={"sync": {"enabled": False}})
        assert resp.status_code == 200

    def test_get_next_sync_no_scheduler(self, settings_client):
        client, mod = settings_client
        import services.scheduler_state as ss
        orig = ss.scheduler
        ss.scheduler = None
        try:
            resp = client.get("/settings/next-sync")
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        body = resp.json()
        assert body["next_run"] is None
        assert body["status"] == "scheduler_not_started"

    def test_run_retention_returns_ok(self, settings_client):
        client, _ = settings_client
        mock_result = {"ran_at": "2025-01-01T00:00:00+00:00", "audit_logs": {}, "packages": {}}
        with patch("services.retention.run_retention", return_value=mock_result):
            resp = client.post("/settings/run-retention")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_run_retention_exception_returns_500(self, settings_client):
        client, _ = settings_client
        with patch("services.retention.run_retention", side_effect=RuntimeError("fail")):
            resp = client.post("/settings/run-retention")
        assert resp.status_code == 500

    def test_test_email_success(self, settings_client):
        client, _ = settings_client
        with patch("services.email_notifications.send_test_email",
                   return_value={"ok": True, "message": "sent"}):
            resp = client.post("/settings/test-email")
        assert resp.status_code == 200

    def test_test_email_failure_returns_400(self, settings_client):
        client, _ = settings_client
        with patch("services.email_notifications.send_test_email",
                   return_value={"ok": False, "error": "SMTP failed"}):
            resp = client.post("/settings/test-email")
        assert resp.status_code == 400

    def test_auth_required_without_override(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(_SR_MOD.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/settings/")
        assert resp.status_code in (401, 403, 422)

    def test_get_gpg_info_subprocess_timeout(self, settings_client):
        client, _ = settings_client
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gpg", 10)):
            resp = client.get("/settings/gpg")
        assert resp.status_code == 504

    def test_get_gpg_info_success(self, settings_client):
        client, _ = settings_client
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        with patch("subprocess.run", return_value=mock_result):
            resp = client.get("/settings/gpg")
        assert resp.status_code == 200

# ─────────────────────────────────────────────────────────────────────────────
# 7. TestManifestUncovered  (services/manifest.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestManifestUncoveredPaths:
    """Couvre les branches non couvertes de services/manifest.py."""

    def test_parse_dependencies_empty_string(self):
        from services.manifest import parse_dependencies
        result = parse_dependencies("")
        assert result == []

    def test_parse_dependencies_with_version_constraint(self):
        from services.manifest import parse_dependencies
        result = parse_dependencies("libssl (>= 1.0), zlib1g")
        names = [d["name"] for d in result]
        assert "libssl" in names
        assert "zlib1g" in names
        ssl_dep = next(d for d in result if d["name"] == "libssl")
        assert ssl_dep.get("version_constraint") is not None

    def test_parse_deb_fields_non_deb_file(self, tmp_path):
        from services.manifest import parse_deb_fields
        f = tmp_path / "bad.deb"
        f.write_bytes(b"not a deb")
        # Should return {} or partial result without raising
        result = parse_deb_fields(str(f))
        assert isinstance(result, dict)

    def test_list_manifests_empty_dir(self, tmp_path):
        import services.manifest as mmod
        orig = mmod.MANIFEST_DIR
        mmod.MANIFEST_DIR = tmp_path
        try:
            from services.manifest import list_manifests
            result = list_manifests()
            assert result == []
        finally:
            mmod.MANIFEST_DIR = orig

    def test_compute_sha256_returns_hex_string(self, tmp_path):
        from services.manifest import compute_sha256
        f = tmp_path / "file.txt"
        f.write_bytes(b"hello world")
        sha = compute_sha256(str(f))
        assert len(sha) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in sha)

    def test_save_manifest_and_load_manifest(self, tmp_path):
        import services.manifest as mmod
        orig_dir = mmod.MANIFEST_DIR
        mmod.MANIFEST_DIR = tmp_path
        try:
            from services.manifest import save_manifest, load_manifest, invalidate_manifest_cache
            invalidate_manifest_cache()
            m = {
                "name": "testpkg",
                "version": "1.0",
                "arch": "amd64",
                "distribution": "jammy",
                "filename": "testpkg_1.0_amd64.deb",
                "integrity": {"sha256": "abc123"},
                "file_size_bytes": 512,
                "source": {
                    "imported_at": "2025-01-01T00:00:00+00:00",
                    "imported_by": "tester",
                },
                "dependencies": [],
                "validation_steps": [],
            }
            save_manifest(m)
            fetched = load_manifest("testpkg", "1.0")
            assert fetched is not None
            assert fetched["name"] == "testpkg"
        finally:
            mmod.MANIFEST_DIR = orig_dir
            invalidate_manifest_cache()


# ─────────────────────────────────────────────────────────────────────────────
# 8. TestValidateFormat  (subprocess mocké)
# ─────────────────────────────────────────────────────────────────────────────

class TestValidateFormat:
    def test_non_deb_extension_fails(self, tmp_path):
        from services.validator import validate_format, ValidationResult
        f = tmp_path / "bad.tar.gz"
        vr = ValidationResult()
        validate_format(str(f), vr)
        step = next(s for s in vr.steps if s["name"] == "format")
        assert step["passed"] is False

    def test_valid_deb_passes(self, tmp_path):
        from services.validator import validate_format, ValidationResult
        f = tmp_path / "pkg.deb"
        f.write_bytes(b"!<arch>")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            vr = ValidationResult()
            validate_format(str(f), vr)

        step = next(s for s in vr.steps if s["name"] == "format")
        assert step["passed"] is True

    def test_corrupt_deb_fails(self, tmp_path):
        from services.validator import validate_format, ValidationResult
        f = tmp_path / "bad.deb"
        f.write_bytes(b"corrupted")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "dpkg-deb: error"

        with patch("subprocess.run", return_value=mock_result):
            vr = ValidationResult()
            validate_format(str(f), vr)

        step = next(s for s in vr.steps if s["name"] == "format")
        assert step["passed"] is False
