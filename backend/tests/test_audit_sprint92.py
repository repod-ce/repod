"""
Tests unitaires — Sprint 9.2 : archive ZIP, export RGPD, intégrité des logs

Couverture :
  • TestBuildAuditArchive    (3)  — bytes, ZIP valide, contient les JSONL
  • TestExportUserData       (4)  — bytes, structure JSON, filtre user, user inconnu
  • TestCheckAuditIntegrity  (4)  — liste, champs, SHA-256 correct, zéro fichier
  • TestArchiveEndpoint      (3)  — HTTP 200, content-type ZIP, auth requise
  • TestUserExportEndpoint   (4)  — HTTP 200, content-type JSON, compress, auth
  • TestIntegrityEndpoint    (4)  — HTTP 200, structure, SHA-256 présent, auth
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_sprint92_test_")
os.environ.setdefault("MANIFEST_DIR",           _TMP)
os.environ.setdefault("MANIFEST_DB",            os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",               _TMP)
os.environ.setdefault("AUDIT_DIR",              _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",         os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",             os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",          os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",           os.path.join(_TMP, "users.db"))
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))

# ── Imports ───────────────────────────────────────────────────────────────────
import gzip
import hashlib
import importlib.util
import io
import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from services.audit_export import (
    build_audit_archive,
    export_user_data,
    check_audit_integrity,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures & helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_jsonl(directory: Path, filename: str, entries: list[dict]) -> Path:
    """Écrit un fichier JSONL dans directory et retourne son chemin."""
    p = directory / filename
    with p.open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return p


def _make_entry(user="alice", action="UPLOAD", package="nginx", timestamp="2026-01-01T10:00:00+00:00"):
    return {
        "timestamp": timestamp,
        "action":    action,
        "user":      user,
        "result":    "SUCCESS",
        "package":   package,
    }


@pytest.fixture
def audit_tmpdir(tmp_path):
    """Fournit un répertoire temporaire isolé et patche services.audit.AUDIT_DIR."""
    import services.audit as _audit_mod
    original = _audit_mod.AUDIT_DIR
    _audit_mod.AUDIT_DIR = tmp_path
    yield tmp_path
    _audit_mod.AUDIT_DIR = original


# ─────────────────────────────────────────────────────────────────────────────
# 1. TestBuildAuditArchive
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildAuditArchive:
    def test_returns_bytes(self, audit_tmpdir):
        result = build_audit_archive()
        assert isinstance(result, bytes)

    def test_valid_zip(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry()])
        result = build_audit_archive()
        buf = io.BytesIO(result)
        assert zipfile.is_zipfile(buf), "Le résultat doit être un ZIP valide"

    def test_contains_jsonl_files(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry()])
        _write_jsonl(audit_tmpdir, "2026-01-02.jsonl", [_make_entry(user="bob")])
        result = build_audit_archive()
        with zipfile.ZipFile(io.BytesIO(result)) as zf:
            names = zf.namelist()
        assert "2026-01-01.jsonl" in names
        assert "2026-01-02.jsonl" in names
        assert len(names) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 2. TestExportUserData
# ─────────────────────────────────────────────────────────────────────────────

class TestExportUserData:
    def test_returns_bytes(self, audit_tmpdir):
        result = export_user_data("alice")
        assert isinstance(result, bytes)

    def test_valid_json_structure(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry(user="alice")])
        result = export_user_data("alice")
        parsed = json.loads(result)
        assert parsed["username"] == "alice"
        assert "exported_at" in parsed
        assert "count" in parsed
        assert "entries" in parsed
        assert isinstance(parsed["entries"], list)

    def test_filters_by_user(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [
            _make_entry(user="alice", action="UPLOAD"),
            _make_entry(user="bob",   action="DELETE"),
            _make_entry(user="alice", action="LOGIN"),
        ])
        result = export_user_data("alice")
        parsed = json.loads(result)
        assert parsed["count"] == 2
        assert all(e["user"] == "alice" for e in parsed["entries"])

    def test_empty_for_unknown_user(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry(user="alice")])
        result = export_user_data("nobody")
        parsed = json.loads(result)
        assert parsed["count"] == 0
        assert parsed["entries"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 3. TestCheckAuditIntegrity
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckAuditIntegrity:
    def test_returns_list(self, audit_tmpdir):
        result = check_audit_integrity()
        assert isinstance(result, list)

    def test_empty_dir_returns_empty(self, audit_tmpdir):
        result = check_audit_integrity()
        assert result == []

    def test_file_info_fields(self, audit_tmpdir):
        _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry()])
        result = check_audit_integrity()
        assert len(result) == 1
        item = result[0]
        assert item["file"] == "2026-01-01.jsonl"
        assert "sha256" in item
        assert "size"   in item
        assert "lines"  in item

    def test_sha256_correct(self, audit_tmpdir):
        p = _write_jsonl(audit_tmpdir, "2026-01-01.jsonl", [_make_entry()])
        data = p.read_bytes()
        expected_sha256 = hashlib.sha256(data).hexdigest()
        result = check_audit_integrity()
        assert result[0]["sha256"] == expected_sha256


# ─────────────────────────────────────────────────────────────────────────────
# Chargement du router — partagé par les tests HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _load_artifacts_router():
    spec = importlib.util.spec_from_file_location(
        "artifacts_isolated_sprint92",
        Path(__file__).parent.parent / "routers" / "artifacts.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def artifacts_mod():
    return _load_artifacts_router()


@pytest.fixture(scope="module")
def admin_client(artifacts_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_admin_user

    app = FastAPI()
    app.include_router(artifacts_mod.router)
    app.dependency_overrides[get_admin_user] = lambda: "admin"
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 4. TestArchiveEndpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestArchiveEndpoint:
    def test_returns_200(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "build_audit_archive",
                          return_value=b"PK\x03\x04"):
            resp = admin_client.get("/artifacts/audit/export/archive")
        assert resp.status_code == 200

    def test_content_type_zip(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "build_audit_archive",
                          return_value=b"PK\x03\x04"):
            resp = admin_client.get("/artifacts/audit/export/archive")
        assert "zip" in resp.headers.get("content-type", "")

    def test_auth_required_without_override(self, artifacts_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(artifacts_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/artifacts/audit/export/archive")
        assert resp.status_code in (401, 403, 422)


# ─────────────────────────────────────────────────────────────────────────────
# 5. TestUserExportEndpoint
# ─────────────────────────────────────────────────────────────────────────────

_MOCK_USER_EXPORT = json.dumps({
    "username":    "alice",
    "exported_at": "2026-06-03T00:00:00+00:00",
    "count":       2,
    "entries":     [_make_entry(), _make_entry(action="LOGIN")],
}, ensure_ascii=False).encode("utf-8")


class TestUserExportEndpoint:
    def test_returns_200(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_user_data",
                          return_value=_MOCK_USER_EXPORT):
            resp = admin_client.get("/artifacts/audit/export/user/alice")
        assert resp.status_code == 200

    def test_content_type_json(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_user_data",
                          return_value=_MOCK_USER_EXPORT):
            resp = admin_client.get("/artifacts/audit/export/user/alice")
        assert "json" in resp.headers.get("content-type", "")

    def test_compress_flag(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "export_user_data",
                          return_value=_MOCK_USER_EXPORT):
            resp = admin_client.get("/artifacts/audit/export/user/alice?compress=true")
        assert resp.status_code == 200
        # Le corps doit être décompressable en gzip
        decompressed = gzip.decompress(resp.content)
        assert len(decompressed) > 0

    def test_auth_required_without_override(self, artifacts_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(artifacts_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/artifacts/audit/export/user/alice")
        assert resp.status_code in (401, 403, 422)


# ─────────────────────────────────────────────────────────────────────────────
# 6. TestIntegrityEndpoint
# ─────────────────────────────────────────────────────────────────────────────

_MOCK_INTEGRITY = [
    {
        "file":   "2026-06-01.jsonl",
        "sha256": "a" * 64,
        "size":   1024,
        "lines":  10,
    },
    {
        "file":   "2026-06-02.jsonl",
        "sha256": "b" * 64,
        "size":   2048,
        "lines":  20,
    },
]


class TestIntegrityEndpoint:
    def test_returns_200(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "check_audit_integrity",
                          return_value=_MOCK_INTEGRITY):
            resp = admin_client.get("/artifacts/audit/integrity")
        assert resp.status_code == 200

    def test_structure(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "check_audit_integrity",
                          return_value=_MOCK_INTEGRITY):
            resp = admin_client.get("/artifacts/audit/integrity")
        body = resp.json()
        assert "checked_at" in body
        assert "files"      in body
        assert "total"      in body
        assert body["total"] == 2

    def test_each_file_has_sha256(self, admin_client, artifacts_mod):
        with patch.object(artifacts_mod, "check_audit_integrity",
                          return_value=_MOCK_INTEGRITY):
            resp = admin_client.get("/artifacts/audit/integrity")
        for item in resp.json()["files"]:
            assert "sha256" in item
            assert len(item["sha256"]) == 64

    def test_auth_required_without_override(self, artifacts_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(artifacts_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/artifacts/audit/integrity")
        assert resp.status_code in (401, 403, 422)
