# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_package_index_apt_sync.py
Rôle   : services/package_index_apt.py:sync_source() — seule
         urllib.error.URLError persistait un échec dans sync_status ; toute
         autre exception (échec de vérification d'intégrité SHA256 via
         InRelease, échec de décompression/parsing) était renvoyée à
         l'appelant (donc bien visible dans le flux de logs du job) mais
         jamais écrite en base. Conséquence concrète : une source touchée
         par ce type d'erreur restait affichée "jamais synchronisée" dans
         l'UI (GET /import/sync-status), indéfiniment, même après plusieurs
         tentatives — get_sync_status() synthétise status="never" pour
         toute source absente de sync_status, ce qui est indiscernable
         d'une source qui n'a simplement encore jamais été synchronisée.

         Ces tests couvrent le comportement corrigé : _write_sync_error()
         est maintenant appelée pour TOUT type d'exception, pas seulement
         URLError.

Dépend : pytest, unittest.mock.patch, db_test_engine (fixture conftest.py,
         SQLite in-memory, autouse).
"""
import urllib.error
from unittest.mock import MagicMock, patch


def _source(source_id="ubuntu-jammy"):
    return {
        "id": source_id,
        "label": "Ubuntu 22.04 (Jammy) main",
        "url": "https://archive.ubuntu.com/ubuntu/dists/jammy/main/binary-amd64/Packages.gz",
        "distro": "jammy",
        "component": "main",
        "arch": "amd64",
    }


def _sync_status_row(source_id):
    from sqlalchemy import text

    from db.engine import db_conn
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM sync_status WHERE source_id = :sid"),
            {"sid": source_id},
        ).mappings().fetchone()
    return dict(row) if row else None


class TestSyncSourcePersistsEveryFailureType:

    def test_url_error_persists_status_error(self, db_test_engine):
        """Comportement déjà correct avant le correctif — non-régression."""
        import services.package_index_apt as pia

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connexion refusée")):
            result = pia.sync_source(_source())

        assert result["status"] == "error"
        row = _sync_status_row("ubuntu-jammy")
        assert row is not None, "aucune trace persistée pour une URLError"
        assert row["status"] == "error"
        assert "connexion refusée" in row["error"]

    def test_integrity_check_failure_persists_status_error(self, db_test_engine):
        """C'est le bug corrigé : _verify_packages_via_inrelease() qui
        échoue lève un ValueError, capturé par la branche générique
        `except Exception` — avant le correctif, rien n'était écrit."""
        import services.package_index_apt as pia

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"contenu falsifie"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch.object(pia, "_verify_packages_via_inrelease",
                           return_value=(False, "SHA256 invalide — possible attaque MitM")):
            result = pia.sync_source(_source())

        assert result["status"] == "error"
        assert "SHA256 invalide" in result["error"]

        row = _sync_status_row("ubuntu-jammy")
        assert row is not None, (
            "échec de vérification d'intégrité non persisté — la source "
            "resterait affichée 'jamais synchronisée' indéfiniment"
        )
        assert row["status"] == "error"
        assert "SHA256 invalide" in row["error"]

    def test_decompression_failure_persists_status_error(self, db_test_engine):
        """Même bug, autre déclencheur : _parse_packages_gz() qui échoue
        (ex. Packages.gz corrompu) doit aussi être persisté."""
        import services.package_index_apt as pia

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"pas du gzip valide"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch.object(pia, "_verify_packages_via_inrelease", return_value=(True, "ok")), \
             patch.object(pia, "_parse_packages_gz", side_effect=ValueError("Impossible de décompresser")):
            result = pia.sync_source(_source())

        assert result["status"] == "error"
        row = _sync_status_row("ubuntu-jammy")
        assert row is not None
        assert row["status"] == "error"
        assert "décompresser" in row["error"]

    def test_first_ever_attempt_failing_is_distinguishable_from_never_synced(self, db_test_engine):
        """Le symptôme observé en production : après le correctif, une
        source dont la toute première tentative échoue doit apparaître dans
        get_sync_status() avec status='error', pas 'never' — sinon elle est
        indiscernable d'une source jamais synchronisée."""
        import services.package_index_apt as pia

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")), \
             patch.object(pia, "DEFAULT_SOURCES", [_source("ubuntu-jammy")]):
            pia.sync_source(_source())
            statuses = pia.get_sync_status()

        entry = next(s for s in statuses if s["source_id"] == "ubuntu-jammy")
        assert entry["status"] == "error"
        assert entry["status"] != "never"

    def test_success_path_still_persists_status_ok(self, db_test_engine):
        """Non-régression du chemin nominal (inchangé par le correctif)."""
        import services.package_index_apt as pia

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"contenu"
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp), \
             patch.object(pia, "_verify_packages_via_inrelease", return_value=(True, "ok")), \
             patch.object(pia, "_parse_packages_gz", return_value=[]):
            result = pia.sync_source(_source())

        assert result["status"] == "ok"
        row = _sync_status_row("ubuntu-jammy")
        assert row["status"] == "ok"
        assert row["error"] is None

    def test_write_sync_error_itself_never_raises(self, db_test_engine):
        """_write_sync_error() est appelée depuis un bloc except — si la
        persistance elle-même échoue (ex. DB indisponible), elle ne doit
        jamais faire remonter une nouvelle exception par-dessus l'erreur
        d'origine qu'on est justement en train de rapporter."""
        import services.package_index_apt as pia

        with patch.object(pia, "db_conn", side_effect=RuntimeError("DB indisponible")):
            pia._write_sync_error("ubuntu-jammy", "Ubuntu 22.04 (Jammy) main", "erreur d'origine")
        # Aucune exception levée = test réussi.
