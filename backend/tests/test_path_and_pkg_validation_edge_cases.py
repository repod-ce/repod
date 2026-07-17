# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
tests/test_path_and_pkg_validation_edge_cases.py — Cas limites sécurité

Couvre, via des cas limites ciblés (path traversal, métacaractères shell,
Unicode) :

  - services/path_safety.py        → safe_path_join / safe_path_join_http
"""

import os
import tempfile
from pathlib import Path

import pytest

# ── Environnement AVANT tout import applicatif ────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="repod_path_pkg_it_")
os.environ.setdefault("MANIFEST_DIR",       _TMP)
os.environ.setdefault("POOL_DIR",           os.path.join(_TMP, "pool"))
os.environ.setdefault("STAGING_INCOMING",   os.path.join(_TMP, "staging", "incoming"))
os.environ.setdefault("STAGING_QUARANTINE", os.path.join(_TMP, "staging", "quarantine"))
os.environ.setdefault("INDEX_PATH",         os.path.join(_TMP, "index.json"))
os.environ.setdefault("AUDIT_DIR",          _TMP)
os.environ.setdefault("SECURITY_CACHE_DIR", os.path.join(_TMP, "security"))
os.environ.setdefault("JWT_SECRET_KEY",     "test-secret-path-pkg-edge-cases")

for _d in ("pool", os.path.join("staging", "incoming"), os.path.join("staging", "quarantine")):
    Path(os.path.join(_TMP, _d)).mkdir(parents=True, exist_ok=True)

from fastapi import HTTPException

from services.path_safety import PathTraversalError, safe_path_join, safe_path_join_http


# ═════════════════════════════════════════════════════════════════════════════
# 1. safe_path_join / safe_path_join_http
# ═════════════════════════════════════════════════════════════════════════════

class TestSafePathJoin:
    @pytest.fixture()
    def base_dir(self, tmp_path):
        d = tmp_path / "pool"
        d.mkdir()
        return d

    def test_normal_filename_ok(self, base_dir):
        result = safe_path_join(base_dir, "package_1.0_amd64.deb")
        assert result == (base_dir / "package_1.0_amd64.deb").resolve()

    def test_empty_filename_raises(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "")

    def test_none_filename_raises(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, None)

    def test_simple_traversal_raises(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "../../etc/passwd")

    def test_single_dotdot_raises(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "../secret.txt")

    def test_nested_traversal_raises(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "subdir/../../etc/shadow")

    def test_absolute_path_escapes(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "/etc/passwd")

    def test_absolute_path_inside_base_is_allowed(self, base_dir):
        # (base_dir / "/foo") == "/foo" en Path — mais si l'absolu pointe
        # à l'intérieur de base_dir, il reste un descendant valide.
        target = str(base_dir / "ok.deb")
        result = safe_path_join(base_dir, target)
        assert result == (base_dir / "ok.deb").resolve()

    def test_dot_filename_resolves_to_base_dir(self, base_dir):
        # "." résout vers base_dir lui-même, qui est is_relative_to(base_dir) == True
        result = safe_path_join(base_dir, ".")
        assert result == base_dir.resolve()

    def test_symlink_escape_raises(self, base_dir, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_text("top secret")

        link = base_dir / "evil_link"
        link.symlink_to(outside, target_is_directory=True)

        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "evil_link/secret.txt")

    def test_url_encoded_traversal_not_decoded_but_literal_dots_blocked(self, base_dir):
        # "%2e%2e/%2e%2e/etc/passwd" n'est PAS décodé par Path — traité comme
        # un nom de fichier littéral, donc reste sous base_dir (pas de levée).
        result = safe_path_join(base_dir, "%2e%2e/%2e%2e/etc/passwd")
        assert result.is_relative_to(base_dir.resolve())

    def test_null_byte_in_filename(self, base_dir):
        # Python lève ValueError sur les chemins contenant un octet nul ;
        # ce comportement protège déjà contre l'injection de null byte.
        with pytest.raises((PathTraversalError, ValueError)):
            safe_path_join(base_dir, "evil.deb\x00.txt")

    def test_unicode_filename_ok(self, base_dir):
        result = safe_path_join(base_dir, "pâquet_éà_1.0.deb")
        assert result.is_relative_to(base_dir.resolve())

    def test_deeply_nested_traversal_with_many_dotdots(self, base_dir):
        with pytest.raises(PathTraversalError):
            safe_path_join(base_dir, "../" * 20 + "etc/passwd")

    def test_windows_style_traversal_treated_as_filename_on_posix(self, base_dir):
        # "..\\..\\etc\\passwd" — sous POSIX, "\\" n'est pas un séparateur,
        # donc ce chemin reste un nom de fichier littéral sous base_dir.
        result = safe_path_join(base_dir, "..\\..\\etc\\passwd")
        assert result.is_relative_to(base_dir.resolve())


class TestSafePathJoinHttp:
    @pytest.fixture()
    def base_dir(self, tmp_path):
        d = tmp_path / "pool"
        d.mkdir()
        return d

    def test_normal_filename_ok(self, base_dir):
        result = safe_path_join_http(base_dir, "package.deb")
        assert result.is_relative_to(base_dir.resolve())

    def test_traversal_raises_http_exception_400(self, base_dir):
        with pytest.raises(HTTPException) as exc_info:
            safe_path_join_http(base_dir, "../../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_custom_status_code(self, base_dir):
        with pytest.raises(HTTPException) as exc_info:
            safe_path_join_http(base_dir, "../../etc/passwd", status_code=404)
        assert exc_info.value.status_code == 404

    def test_empty_filename_raises_http_exception(self, base_dir):
        with pytest.raises(HTTPException) as exc_info:
            safe_path_join_http(base_dir, "")
        assert exc_info.value.status_code == 400
