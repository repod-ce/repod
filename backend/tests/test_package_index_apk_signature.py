# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_package_index_apk_signature.py
Rôle   : services/package_index_apk.py:_verify_apkindex_signature() —
         authentification d'APKINDEX.tar.gz, absente jusqu'ici : le fichier
         était parsé directement après téléchargement, sans jamais vérifier
         la signature RSA qu'Alpine embarque pourtant dans le fichier
         lui-même (concaténation de deux flux gzip — voir le docstring de
         _split_apk_signed_archive()).

         Utilise une paire de clés RSA jetable générée à la volée via
         openssl (pas de dépendance réseau, pas de clé Alpine réelle
         nécessaire ici). La couverture contre la vraie clé Alpine
         officielle (alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub,
         confirmée être la même sur les 8 sources DEFAULT_SOURCES) a été
         faite manuellement en direct contre de vrais APKINDEX.tar.gz
         récupérés sur dl-cdn.alpinelinux.org, documentée dans le message
         du commit — voir aussi scripts/gen-apk-keys.sh.

Dépend : pytest, un binaire `openssl` fonctionnel (même dépendance que
         validate_gpg()/_verify_repomd_gpg() ailleurs dans ce projet).
"""
import io
import subprocess
import tarfile

import pytest

import services.package_index_apk as pia


def _tar_gz_with_file(name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name=name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_signed_apkindex(tmp_path, content_gz: bytes, key_name: str = "test-signer.rsa.pub") -> bytes:
    """Construit un APKINDEX.tar.gz jetable : génère une paire RSA, signe
    content_gz (les octets COMPRESSÉS, comme le fait réellement abuild-sign —
    confirmé en direct), et colle le tar.gz de signature devant."""
    priv = tmp_path / "priv.pem"
    pub = tmp_path / f"{key_name}"
    subprocess.run(["openssl", "genrsa", "-out", str(priv), "2048"], capture_output=True, check=True)
    subprocess.run(["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)], capture_output=True, check=True)

    content_path = tmp_path / "content.tar.gz"
    content_path.write_bytes(content_gz)
    sig_path = tmp_path / "sig.bin"
    subprocess.run(
        ["openssl", "dgst", "-sha1", "-sign", str(priv), "-out", str(sig_path), str(content_path)],
        capture_output=True, check=True,
    )
    signature_bytes = sig_path.read_bytes()

    sig_gz = _tar_gz_with_file(f".SIGN.RSA.{key_name}", signature_bytes)
    return sig_gz + content_gz, pub.read_bytes()


@pytest.fixture
def signed_apkindex(tmp_path, monkeypatch):
    """Bascule package_index_apk._APK_KEYS_DIR sur un répertoire jetable et
    retourne une factory qui construit un APKINDEX.tar.gz signé valide,
    avec sa clé publique déjà installée dans ce répertoire."""
    keys_dir = tmp_path / "apk-keys"
    keys_dir.mkdir()
    monkeypatch.setattr(pia, "_APK_KEYS_DIR", str(keys_dir))

    def _build(content: bytes = b"P:test\nV:1.0\nA:x86_64\n\n", key_name: str = "test-signer.rsa.pub"):
        content_gz = _tar_gz_with_file("APKINDEX", content)
        gz_data, pub_bytes = _make_signed_apkindex(tmp_path, content_gz, key_name)
        (keys_dir / key_name).write_bytes(pub_bytes)
        return gz_data

    return _build


class TestVerifyApkindexSignature:
    def test_valid_signature_from_known_key_passes(self, signed_apkindex):
        gz_data = signed_apkindex()
        ok, msg = pia._verify_apkindex_signature(gz_data)
        assert ok is True
        assert msg == ""

    def test_tampered_content_after_signing_fails(self, signed_apkindex):
        gz_data = signed_apkindex()
        tampered = gz_data + b"\x00\x00\x00\x00"
        ok, msg = pia._verify_apkindex_signature(tampered)
        assert ok is False

    def test_signature_from_unknown_key_fails(self, signed_apkindex, tmp_path, monkeypatch):
        gz_data = signed_apkindex()
        empty_dir = tmp_path / "empty-apk-keys"
        empty_dir.mkdir()
        monkeypatch.setattr(pia, "_APK_KEYS_DIR", str(empty_dir))
        ok, msg = pia._verify_apkindex_signature(gz_data)
        assert ok is False
        assert "inconnue" in msg.lower()

    def test_unsigned_single_stream_archive_fails(self):
        """Un .tar.gz classique (un seul flux gzip, pas de signature
        concaténée devant) ne doit jamais passer silencieusement."""
        content_gz = _tar_gz_with_file("APKINDEX", b"P:test\nV:1.0\n\n")
        ok, msg = pia._verify_apkindex_signature(content_gz)
        assert ok is False

    def test_truncated_data_fails_gracefully(self):
        ok, msg = pia._verify_apkindex_signature(b"\x1f\x8b\x08not really gzip data")
        assert ok is False
