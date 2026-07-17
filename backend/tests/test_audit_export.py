"""
Tests unitaires — Sprint 5.3 : export du journal d'audit (CSV + GPG)

Couverture :
  • TestFilterEntries      (8)  — start/end, package, action, result, user, combinés
  • TestToCSV              (5)  — entête, colonnes, valeurs manquantes, encodage, BOM
  • TestToJSON             (3)  — structure JSON, ordre, champs extra
  • TestGzipCompress       (2)  — compressé décompressable, taille réduite
  • TestSignExport         (4)  — gpg OK, gpg absent, gpg timeout, gpg erreur returncode
  • TestExportAuditLogs    (8)  — format csv/json, filtres, compress, sign, count
  • TestGetExportFilename  (4)  — noms générés
  • TestExportEndpoint     (8)  — HTTP 200, formats, filtres, compress, auth, 400 format invalide
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_audit_export_test_")
os.environ.setdefault("MANIFEST_DIR",   _TMP)
os.environ.setdefault("MANIFEST_DB",    os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",       _TMP)
os.environ.setdefault("AUDIT_DIR",      _TMP)
os.environ.setdefault("AUDIT_LOG_PATH", os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",     os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",  os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",           os.path.join(_TMP, "users.db"))
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))

# ── Imports ───────────────────────────────────────────────────────────────────
import csv
import gzip
import importlib.util
import io
import json
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import services.audit_export as exp_mod
from services.audit_export import (
    _filter_entries,
    _to_csv,
    _to_json,
    _gzip_compress,
    sign_export,
    export_audit_logs,
    get_export_filename,
    CSV_COLUMNS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _days_ago_iso(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _make_entry(
    action="UPLOAD", user="alice", result="SUCCESS",
    package="nginx", version="1.0", detail="ok",
    timestamp: str | None = None,
) -> dict:
    return {
        "timestamp": timestamp or _now_iso(),
        "action":    action,
        "user":      user,
        "result":    result,
        "package":   package,
        "version":   version,
        "detail":    detail,
    }

def _sample_entries() -> list[dict]:
    return [
        _make_entry("UPLOAD", "alice", "SUCCESS", "nginx",  "1.0", timestamp=_days_ago_iso(5)),
        _make_entry("DELETE", "bob",   "SUCCESS", "nginx",  "0.9", timestamp=_days_ago_iso(3)),
        _make_entry("LOGIN",  "alice", "SUCCESS", "nginx",  None,  timestamp=_days_ago_iso(1)),
        _make_entry("UPLOAD", "carol", "FAILURE", "apache", "2.4", timestamp=_days_ago_iso(2)),
    ]


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestFilterEntries
# ═════════════════════════════════════════════════════════════════════════════

class TestFilterEntries:
    def test_no_filter_returns_all(self):
        entries = _sample_entries()
        assert len(_filter_entries(entries)) == 4

    def test_filter_by_package(self):
        result = _filter_entries(_sample_entries(), package="nginx")
        assert all(e["package"] == "nginx" for e in result)
        assert len(result) == 3

    def test_filter_by_action_case_insensitive(self):
        result = _filter_entries(_sample_entries(), action="upload")
        assert all(e["action"] == "UPLOAD" for e in result)
        assert len(result) == 2

    def test_filter_by_result(self):
        result = _filter_entries(_sample_entries(), result="FAILURE")
        assert len(result) == 1
        assert result[0]["user"] == "carol"

    def test_filter_by_user(self):
        result = _filter_entries(_sample_entries(), user="alice")
        assert len(result) == 2

    def test_filter_by_start(self):
        # Garder seulement les entrées des 2 derniers jours
        cutoff = _days_ago_iso(2)
        result = _filter_entries(_sample_entries(), start=cutoff)
        for e in result:
            dt = datetime.fromisoformat(e["timestamp"])
            cutoff_dt = datetime.fromisoformat(cutoff)
            assert dt >= cutoff_dt

    def test_filter_by_end(self):
        # Garder seulement les entrées de plus de 2 jours
        cutoff = _days_ago_iso(2)
        result = _filter_entries(_sample_entries(), end=cutoff)
        for e in result:
            dt = datetime.fromisoformat(e["timestamp"])
            cutoff_dt = datetime.fromisoformat(cutoff)
            assert dt <= cutoff_dt

    def test_combined_filters(self):
        result = _filter_entries(_sample_entries(), user="alice", action="UPLOAD")
        assert len(result) == 1
        assert result[0]["package"] == "nginx"


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestToCSV
# ═════════════════════════════════════════════════════════════════════════════

class TestToCSV:
    def _parse_csv(self, data: bytes) -> list[dict]:
        text = data.decode("utf-8-sig")  # strip BOM
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)

    def test_header_present(self):
        raw = _to_csv([_make_entry()])
        text = raw.decode("utf-8-sig")
        first_line = text.split("\r\n")[0]
        for col in CSV_COLUMNS:
            assert col in first_line

    def test_one_row_per_entry(self):
        entries = _sample_entries()
        rows = self._parse_csv(_to_csv(entries))
        assert len(rows) == len(entries)

    def test_missing_fields_become_empty(self):
        entry = {"timestamp": _now_iso(), "action": "LOGIN", "user": "bob", "result": "SUCCESS"}
        rows = self._parse_csv(_to_csv([entry]))
        assert rows[0]["package"] == ""
        assert rows[0]["version"] == ""

    def test_output_is_bytes(self):
        result = _to_csv([_make_entry()])
        assert isinstance(result, bytes)

    def test_bom_present(self):
        raw = _to_csv([_make_entry()])
        # BOM UTF-8 : EF BB BF
        assert raw[:3] == b"\xef\xbb\xbf"


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestToJSON
# ═════════════════════════════════════════════════════════════════════════════

class TestToJSON:
    def test_valid_json(self):
        data = _to_json(_sample_entries())
        parsed = json.loads(data)
        assert isinstance(parsed, list)
        assert len(parsed) == 4

    def test_extra_fields_preserved(self):
        entry = _make_entry()
        entry["custom_field"] = "extra_value"
        data = _to_json([entry])
        parsed = json.loads(data)
        assert parsed[0]["custom_field"] == "extra_value"

    def test_output_is_bytes(self):
        assert isinstance(_to_json([]), bytes)


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestGzipCompress
# ═════════════════════════════════════════════════════════════════════════════

class TestGzipCompress:
    def test_decompressable(self):
        data = b"hello world " * 100
        compressed = _gzip_compress(data)
        assert gzip.decompress(compressed) == data

    def test_smaller_than_original(self):
        data = b"repeated content " * 1000
        compressed = _gzip_compress(data)
        assert len(compressed) < len(data)


# ═════════════════════════════════════════════════════════════════════════════
# 5. TestSignExport
# ═════════════════════════════════════════════════════════════════════════════

class TestSignExport:
    def test_gpg_success_returns_signature(self):
        mock_run = MagicMock()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"-----BEGIN PGP SIGNATURE-----\nABCD\n-----END PGP SIGNATURE-----\n"
        with patch("subprocess.run", mock_run):
            sig = sign_export(b"data to sign")
        assert sig is not None
        assert "PGP SIGNATURE" in sig

    def test_gpg_absent_returns_none(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            sig = sign_export(b"data")
        assert sig is None

    def test_gpg_timeout_returns_none(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gpg", 15)):
            sig = sign_export(b"data")
        assert sig is None

    def test_gpg_nonzero_returns_none(self):
        mock_run = MagicMock()
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = b"gpg error"
        mock_run.return_value.stdout = b""
        with patch("subprocess.run", mock_run):
            sig = sign_export(b"data")
        assert sig is None


# ═════════════════════════════════════════════════════════════════════════════
# 6. TestExportAuditLogs
# ═════════════════════════════════════════════════════════════════════════════

class TestExportAuditLogs:
    def _patches(self, entries=None):
        return patch("services.audit.get_recent_logs",
                     return_value=entries or _sample_entries())

    def test_csv_format(self):
        with self._patches():
            result = export_audit_logs(fmt="csv")
        assert result["format"] == "csv"
        text = result["data"].decode("utf-8-sig")
        assert "timestamp" in text.split("\r\n")[0]

    def test_json_format(self):
        with self._patches():
            result = export_audit_logs(fmt="json")
        assert result["format"] == "json"
        parsed = json.loads(result["data"])
        assert isinstance(parsed, list)

    def test_count_matches_entries(self):
        with self._patches():
            result = export_audit_logs()
        assert result["count"] == 4

    def test_filters_applied(self):
        with self._patches():
            result = export_audit_logs(fmt="json", user="alice")
        parsed = json.loads(result["data"])
        assert all(e["user"] == "alice" for e in parsed)
        assert result["count"] == 2

    def test_compress_flag(self):
        with self._patches():
            result = export_audit_logs(compress=True)
        assert result["compressed"] is True
        # Doit être un gzip valide
        decompressed = gzip.decompress(result["data"])
        assert len(decompressed) > 0

    def test_no_compress_by_default(self):
        with self._patches():
            result = export_audit_logs()
        assert result["compressed"] is False

    def test_sign_true_calls_sign_export(self):
        mock_sign = MagicMock(return_value="-----BEGIN PGP SIGNATURE-----\n...\n")
        with self._patches():
            with patch.object(exp_mod, "sign_export", mock_sign):
                result = export_audit_logs(sign=True)
        mock_sign.assert_called_once()
        assert result["signature"] is not None

    def test_sign_false_no_signature(self):
        with self._patches():
            result = export_audit_logs(sign=False)
        assert result["signature"] is None


# ═════════════════════════════════════════════════════════════════════════════
# 7. TestGetExportFilename
# ═════════════════════════════════════════════════════════════════════════════

class TestGetExportFilename:
    def test_csv_extension(self):
        name = get_export_filename("csv", compress=False)
        assert name.endswith(".csv")

    def test_json_extension(self):
        name = get_export_filename("json", compress=False)
        assert name.endswith(".json")

    def test_gz_suffix_when_compressed(self):
        name = get_export_filename("json", compress=True)
        assert name.endswith(".json.gz")

    def test_contains_timestamp(self):
        name = get_export_filename("csv", compress=False)
        assert "audit_export_" in name


# ═════════════════════════════════════════════════════════════════════════════
# 8. TestExportEndpoint
# ═════════════════════════════════════════════════════════════════════════════

def _load_artifacts_router():
    spec = importlib.util.spec_from_file_location(
        "artifacts_isolated_export",
        Path(__file__).parent.parent / "routers" / "artifacts.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def artifacts_mod():
    return _load_artifacts_router()


@pytest.fixture(scope="module")
def export_client(artifacts_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_auditor_user, get_admin_user

    app = FastAPI()
    app.include_router(artifacts_mod.router)
    app.dependency_overrides[get_auditor_user] = lambda: "auditor"
    app.dependency_overrides[get_admin_user]   = lambda: "admin"

    return TestClient(app)


_MOCK_EXPORT_JSON = {
    "data":       b'[{"action": "UPLOAD"}]',
    "signature":  None,
    "count":      1,
    "format":     "json",
    "compressed": False,
}

_MOCK_EXPORT_CSV = {
    "data":       b"\xef\xbb\xbftimestamp,action\r\n2026-01-01,UPLOAD\r\n",
    "signature":  None,
    "count":      1,
    "format":     "csv",
    "compressed": False,
}


class TestExportEndpoint:
    def test_returns_200(self, export_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_audit_logs", return_value=_MOCK_EXPORT_JSON):
            resp = export_client.get("/artifacts/audit/export")
        assert resp.status_code == 200

    def test_json_content_type(self, export_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_audit_logs", return_value=_MOCK_EXPORT_JSON):
            resp = export_client.get("/artifacts/audit/export?format=json")
        assert "json" in resp.headers.get("content-type", "")

    def test_csv_content_type(self, export_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_audit_logs", return_value=_MOCK_EXPORT_CSV):
            resp = export_client.get("/artifacts/audit/export?format=csv")
        assert "csv" in resp.headers.get("content-type", "")

    def test_count_header(self, export_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_audit_logs", return_value=_MOCK_EXPORT_JSON):
            resp = export_client.get("/artifacts/audit/export")
        assert resp.headers.get("x-export-count") == "1"

    def test_content_disposition_header(self, export_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_audit_logs", return_value=_MOCK_EXPORT_JSON):
            resp = export_client.get("/artifacts/audit/export")
        assert "attachment" in resp.headers.get("content-disposition", "")

    def test_invalid_format_returns_400(self, export_client):
        resp = export_client.get("/artifacts/audit/export?format=xml")
        assert resp.status_code == 400

    def test_gpg_signature_in_header(self, export_client, artifacts_mod):
        mock_export = {**_MOCK_EXPORT_JSON, "signature": "-----BEGIN PGP SIGNATURE-----\nABC\n"}
        with patch.object(artifacts_mod, "export_audit_logs", return_value=mock_export):
            resp = export_client.get("/artifacts/audit/export?sign=true")
        assert "x-gpg-signature" in resp.headers

    def test_auth_required_without_override(self, artifacts_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(artifacts_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/artifacts/audit/export")
        assert resp.status_code in (401, 403, 422)
