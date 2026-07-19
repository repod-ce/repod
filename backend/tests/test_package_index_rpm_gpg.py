# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_package_index_rpm_gpg.py
Rôle   : services/package_index_rpm.py:_verify_repomd_gpg() — authentification
         de repomd.xml via sa signature détachée repomd.xml.asc, absente
         jusqu'ici : seule l'intégrité de primary.xml (SHA-256 déclaré DANS
         repomd.xml) était vérifiée, jamais repomd.xml lui-même — un MITM
         pouvait servir un repomd.xml ET un primary.xml forgés ensemble.

         Utilise une paire de clés GPG jetable générée à la volée (pas de
         dépendance réseau). La couverture contre les vraies clés
         AlmaLinux/Rocky/CentOS Stream/openSUSE (et la confirmation que
         Fedora/EPEL/Oracle Linux ne publient aucun repomd.xml.asc) a été
         faite manuellement en direct contre les dépôts réels, documentée
         dans le message du commit — voir aussi scripts/gen-rpm-keyring.sh.

Dépend : pytest, un binaire `gpg` fonctionnel (même dépendance que
         test_package_index_apt_gpg.py).
"""
import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import services.package_index_rpm as pir


def _new_gnupghome(tmp_path, name="gnupghome"):
    gnupghome = tmp_path / name
    gnupghome.mkdir(mode=0o700)
    (gnupghome / "gpg-agent.conf").write_text("allow-loopback-pinentry\n")
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True)
    return gnupghome


def _quick_generate_key(gnupghome, uid, expire="never"):
    subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", uid, "ed25519", "sign", expire],
        capture_output=True, text=True, check=True, env={**os.environ, "GNUPGHOME": str(gnupghome)},
    )


def _export_keyring(gnupghome, out_path):
    subprocess.run(
        ["gpg", "--batch", "--export", "-o", str(out_path)],
        capture_output=True, text=True, check=True, env={**os.environ, "GNUPGHOME": str(gnupghome)},
    )


def _detach_sign(gnupghome, data: bytes, tmp_path) -> bytes:
    data_path = tmp_path / "data.bin"
    data_path.write_bytes(data)
    sig_path = tmp_path / "data.bin.asc"
    subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--detach-sign", "--armor", "-o", str(sig_path), str(data_path)],
        capture_output=True, text=True, check=True, env={**os.environ, "GNUPGHOME": str(gnupghome)},
    )
    return sig_path.read_bytes()


@pytest.fixture
def throwaway_rpm_keyring(tmp_path, monkeypatch):
    """Clé jetable (ed25519, expiration 'never') + trousseau exporté, bascule
    package_index_rpm._RPM_KEYRING_PATH dessus pour la durée du test."""
    gnupghome = _new_gnupghome(tmp_path)
    monkeypatch.setenv("GNUPGHOME", str(gnupghome))
    _quick_generate_key(gnupghome, "Repod RPM Test Signer <rpm-test@example.invalid>")

    keyring_path = tmp_path / "throwaway-rpm-keyring.gpg"
    _export_keyring(gnupghome, keyring_path)
    monkeypatch.setattr(pir, "_RPM_KEYRING_PATH", str(keyring_path))

    class _Signer:
        def sign(self, data: bytes) -> bytes:
            return _detach_sign(gnupghome, data, tmp_path)

    return _Signer()


class TestVerifyRepomdGpg:
    def test_valid_signature_from_known_key_passes(self, throwaway_rpm_keyring):
        data = b"<repomd><data type='primary'>fake</data></repomd>"
        sig = throwaway_rpm_keyring.sign(data)
        with patch.object(pir, "fetch_url", return_value=sig):
            ok, msg = pir._verify_repomd_gpg(data, "https://example.test/repodata/repomd.xml")
        assert ok is True
        assert msg == ""

    def test_tampered_repomd_after_signing_fails(self, throwaway_rpm_keyring):
        data = b"<repomd><data type='primary'>fake</data></repomd>"
        sig = throwaway_rpm_keyring.sign(data)
        tampered = data.replace(b"fake", b"forged")
        with patch.object(pir, "fetch_url", return_value=sig):
            ok, msg = pir._verify_repomd_gpg(tampered, "https://example.test/repodata/repomd.xml")
        assert ok is False
        assert "invalide" in msg.lower() or "badsig" in msg.lower()

    def test_signature_from_unknown_key_fails(self, tmp_path, monkeypatch, throwaway_rpm_keyring):
        data = b"<repomd>fake</repomd>"
        sig = throwaway_rpm_keyring.sign(data)
        empty_keyring = tmp_path / "empty-keyring.gpg"
        empty_keyring.touch()
        monkeypatch.setattr(pir, "_RPM_KEYRING_PATH", str(empty_keyring))
        with patch.object(pir, "fetch_url", return_value=sig):
            ok, msg = pir._verify_repomd_gpg(data, "https://example.test/repodata/repomd.xml")
        assert ok is False
        assert "inconnue" in msg.lower()

    def test_missing_keyring_file_fails_gracefully(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pir, "_RPM_KEYRING_PATH", str(tmp_path / "does-not-exist.gpg"))
        with patch.object(pir, "fetch_url", return_value=b"whatever signature bytes"):
            ok, msg = pir._verify_repomd_gpg(b"<repomd>fake</repomd>", "https://example.test/repodata/repomd.xml")
        assert ok is False
        assert "introuvable" in msg.lower()

    def test_no_asc_published_warns_but_does_not_fail(self, throwaway_rpm_keyring):
        """Fedora/EPEL/Oracle Linux ne publient aucun repomd.xml.asc (confirmé
        en direct : HTTP 404 sur les 3) — ça ne doit jamais bloquer leur sync."""
        with patch.object(pir, "fetch_url", side_effect=Exception("404 not found")):
            ok, msg = pir._verify_repomd_gpg(b"<repomd>fake</repomd>", "https://example.test/repodata/repomd.xml")
        assert ok is True
        assert "aucun" in msg.lower() and "repomd.xml.asc" in msg.lower()

    def test_expired_signing_key_passes_with_warning(self, tmp_path, monkeypatch):
        """Une signature valide faite par une clé depuis EXPIRÉE (EXPKEYSIG)
        n'est pas une falsification — confirmé en direct que la vraie clé de
        signature openSUSE (keyid 29B700A4) est réellement expirée en
        production. Échouer fermé sur ce cas casserait sa sync en permanence."""
        gnupghome = _new_gnupghome(tmp_path, name="gnupghome-exp")
        monkeypatch.setenv("GNUPGHOME", str(gnupghome))
        _quick_generate_key(gnupghome, "Repod RPM Expiring Signer <rpm-exp@example.invalid>", expire="seconds=2")

        keyring_path = tmp_path / "expiring-keyring.gpg"
        _export_keyring(gnupghome, keyring_path)
        monkeypatch.setattr(pir, "_RPM_KEYRING_PATH", str(keyring_path))

        data = b"<repomd>fake</repomd>"
        sig = _detach_sign(gnupghome, data, tmp_path)  # signé AVANT expiration

        time.sleep(3)  # laisse la clé expirer réellement avant la vérification

        with patch.object(pir, "fetch_url", return_value=sig):
            ok, msg = pir._verify_repomd_gpg(data, "https://example.test/repodata/repomd.xml")
        assert ok is True
        assert "expir" in msg.lower()
