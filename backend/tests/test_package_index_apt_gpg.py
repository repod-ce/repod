# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_package_index_apt_gpg.py
Rôle   : services/package_index_apt.py:_verify_inrelease_gpg() /
         _verify_packages_via_inrelease() — vérification GPG réelle
         d'InRelease, absente jusqu'ici malgré le commentaire du code qui
         la revendiquait déjà ("InRelease (signé GPG par Ubuntu/Debian)").

         Avant ce correctif : le code comparait le SHA256 déclaré par
         InRelease avec celui de Packages.gz, mais ne vérifiait JAMAIS que
         InRelease lui-même était authentique — un MITM pouvait servir un
         InRelease ET un Packages.gz forgés ensemble, le SHA256
         "correspondant" par construction. De plus, une InRelease
         injoignable ou un SHA256 absent ne produisaient qu'un
         avertissement (ok=True) — la vérification n'était donc, dans les
         faits, jamais réellement obligatoire.

         Ces tests utilisent une paire de clés GPG jetable générée à la
         volée (pas de dépendance réseau, pas de clé réelle Ubuntu/Debian
         nécessaire ici — celles-ci sont couvertes séparément par une
         vérification manuelle contre de vrais fichiers InRelease
         Ubuntu/Debian récupérés en direct, documentée dans le message du
         commit).

Dépend : pytest, un binaire `gpg` fonctionnel (déjà requis par
         validate_gpg() dans validator_apt.py — même dépendance).
"""
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import services.package_index_apt as pia


@pytest.fixture
def throwaway_keyring(tmp_path, monkeypatch):
    """
    Génère une paire de clés GPG jetable (ed25519, sans phrase de passe,
    génération instantanée) dans un GNUPGHOME temporaire, exporte la clé
    publique dans un trousseau, et bascule
    package_index_apt._UPSTREAM_KEYRING_PATH dessus pour la durée du test.

    Retourne un objet avec .keyring_path et .clearsign(text) -> str.
    """
    gnupghome = tmp_path / "gnupghome"
    gnupghome.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(gnupghome))
    (gnupghome / "gpg-agent.conf").write_text("allow-loopback-pinentry\n")
    subprocess.run(["gpgconf", "--kill", "gpg-agent"], capture_output=True)

    subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", "Repod Test Signer <test@example.invalid>",
         "ed25519", "sign", "never"],
        capture_output=True, text=True, check=True, env={**os.environ, "GNUPGHOME": str(gnupghome)},
    )

    keyring_path = tmp_path / "throwaway-keyring.gpg"
    subprocess.run(
        ["gpg", "--batch", "--export", "-o", str(keyring_path)],
        capture_output=True, text=True, check=True, env={**os.environ, "GNUPGHOME": str(gnupghome)},
    )

    class _Signer:
        def clearsign(self, text: str) -> str:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write(text)
                plain_path = f.name
            signed_path = plain_path + ".signed"
            try:
                subprocess.run(
                    ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                     "--clearsign", "-o", signed_path, plain_path],
                    capture_output=True, text=True, check=True,
                    env={**os.environ, "GNUPGHOME": str(gnupghome)},
                )
                return Path(signed_path).read_text()
            finally:
                os.unlink(plain_path)
                if os.path.exists(signed_path):
                    os.unlink(signed_path)

    monkeypatch.setattr(pia, "_UPSTREAM_KEYRING_PATH", str(keyring_path))
    return _Signer()


class TestVerifyInReleaseGpg:
    def test_valid_signature_from_known_key_passes(self, throwaway_keyring):
        signed = throwaway_keyring.clearsign("Origin: Test\nSuite: testsuite\n")
        ok, msg = pia._verify_inrelease_gpg(signed)
        assert ok is True
        assert "vérifiée" in msg

    def test_tampered_content_after_signing_fails(self, throwaway_keyring):
        signed = throwaway_keyring.clearsign("Origin: Test\nSuite: testsuite\n")
        tampered = signed.replace("testsuite", "testsuiteXXXX")
        ok, msg = pia._verify_inrelease_gpg(tampered)
        assert ok is False
        assert "invalide" in msg.lower() or "altération" in msg.lower()

    def test_signature_from_unknown_key_fails(self, tmp_path, monkeypatch, throwaway_keyring):
        signed = throwaway_keyring.clearsign("Origin: Test\nSuite: testsuite\n")
        # Pointe vers un trousseau VIDE (ne contient pas la clé qui a signé) :
        empty_keyring = tmp_path / "empty-keyring.gpg"
        empty_keyring.touch()
        monkeypatch.setattr(pia, "_UPSTREAM_KEYRING_PATH", str(empty_keyring))
        ok, msg = pia._verify_inrelease_gpg(signed)
        assert ok is False
        assert "aucune signature" in msg.lower()

    def test_missing_keyring_file_fails_gracefully(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pia, "_UPSTREAM_KEYRING_PATH", str(tmp_path / "does-not-exist.gpg"))
        ok, msg = pia._verify_inrelease_gpg("irrelevant content")
        assert ok is False
        assert "introuvable" in msg.lower()


class TestVerifyPackagesViaInRelease:
    """_verify_packages_via_inrelease() — la fonction appelée par sync_source()."""

    def _mock_urlopen_returning(self, text: str):
        mock_resp = type("R", (), {
            "read": lambda self: text.encode("utf-8"),
            "__enter__": lambda self: self,
            "__exit__": lambda self, *a: None,
        })()
        return mock_resp

    def test_gpg_failure_blocks_before_sha256_check(self, throwaway_keyring):
        """Un échec GPG doit faire échouer la fonction SANS même regarder le
        SHA256 — avant ce correctif, un SHA256 absent/non-vérifié tombait
        sur une simple alerte (ok=True)."""
        signed = throwaway_keyring.clearsign("Origin: Test\nSuite: testsuite\n")
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen_returning(signed)), \
             patch.object(pia, "_verify_inrelease_gpg", return_value=(False, "Signature GPG invalide")):
            ok, msg = pia._verify_packages_via_inrelease(
                "https://example.test/dists/testsuite/main/binary-amd64/Packages.gz",
                b"fake gz data",
            )
        assert ok is False
        assert "signature gpg invalide" in msg.lower()

    def test_valid_gpg_and_matching_sha256_passes(self, throwaway_keyring):
        gz_data = b"fake package data"
        import hashlib
        real_sha = hashlib.sha256(gz_data).hexdigest()
        inrelease_plain = (
            "Origin: Test\nSuite: testsuite\nSHA256:\n"
            f" {real_sha} {len(gz_data)} main/binary-amd64/Packages.gz\n"
        )
        signed = throwaway_keyring.clearsign(inrelease_plain)
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen_returning(signed)):
            ok, msg = pia._verify_packages_via_inrelease(
                "https://example.test/dists/testsuite/main/binary-amd64/Packages.gz",
                gz_data,
            )
        assert ok is True
        assert "authentifié" in msg.lower()

    def test_valid_gpg_but_mismatched_sha256_fails(self, throwaway_keyring):
        inrelease_plain = (
            "Origin: Test\nSuite: testsuite\nSHA256:\n"
            " 0000000000000000000000000000000000000000000000000000000000000000 5 main/binary-amd64/Packages.gz\n"
        )
        signed = throwaway_keyring.clearsign(inrelease_plain)
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen_returning(signed)):
            ok, msg = pia._verify_packages_via_inrelease(
                "https://example.test/dists/testsuite/main/binary-amd64/Packages.gz",
                b"actual different data",
            )
        assert ok is False
        assert "sha256" in msg.lower()

    def test_inrelease_unreachable_now_fails_closed(self):
        """Changement de comportement délibéré : avant, une InRelease
        injoignable ne produisait qu'un avertissement (ok=True) et laissait
        passer un Packages.gz jamais authentifié. Désormais ça bloque le
        sync de cette source. Patch time.sleep : cet appel retente 2 fois
        (services/http_retry.py) avant d'abandonner."""
        with patch("urllib.request.urlopen", side_effect=OSError("connexion refusée")), \
             patch("services.http_retry.time.sleep"):
            ok, msg = pia._verify_packages_via_inrelease(
                "https://example.test/dists/testsuite/main/binary-amd64/Packages.gz",
                b"data",
            )
        assert ok is False
        assert "injoignable" in msg.lower()

    def test_missing_sha256_entry_now_fails_closed(self, throwaway_keyring):
        """Idem : SHA256 absent de InRelease (mais InRelease authentique)
        bloque désormais le sync, au lieu d'un simple avertissement."""
        signed = throwaway_keyring.clearsign("Origin: Test\nSuite: testsuite\n")  # pas de section SHA256
        with patch("urllib.request.urlopen", return_value=self._mock_urlopen_returning(signed)):
            ok, msg = pia._verify_packages_via_inrelease(
                "https://example.test/dists/testsuite/main/binary-amd64/Packages.gz",
                b"data",
            )
        assert ok is False
        assert "sha256" in msg.lower()
