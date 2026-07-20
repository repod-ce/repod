# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_rpm_pool_path.py
Rôle   : services/distributions_rpm.py:add_rpm_to_distrib() cherchait le
         fichier source sous REPO_BASE/pool — REPO_BASE valant /repos/rpm en
         production (docker-compose.yaml, "répertoires createrepo_c"), donc
         /repos/rpm/pool/, alors que le pool RÉEL et partagé (utilisé par
         importer_rpm.py, routers/upload.py) est /repos/pool/, déjà fourni
         comme variable d'env séparée POOL_DIR par docker-compose.yaml mais
         jamais lue par ce module. Bug trouvé en direct sur .20 en vérifiant
         le support arm64 : le téléchargement/la validation réussissaient,
         mais createrepo_c échouait ensuite avec "Fichier introuvable dans
         pool/" — reproduit pour x86_64 ET aarch64, donc pas spécifique à
         l'architecture (confirmé aussi dans scripts/add-rpm.sh, le chemin
         réellement emprunté par l'import depuis internet).

Dépend : pytest, unittest.mock.patch — subprocess (createrepo_c/gpg) mocké,
         aucun binaire réel nécessaire.
"""
from unittest.mock import patch


class TestAddRpmToDistribUsesPoolDir:
    def test_finds_file_in_pool_dir_not_repo_base_pool(self, tmp_path, monkeypatch):
        """Le fichier existe UNIQUEMENT sous POOL_DIR (pas sous
        REPO_BASE/pool) — reproduit exactement la disposition réelle en
        production (REPO_BASE=/repos/rpm, POOL_DIR=/repos/pool, deux
        répertoires distincts)."""
        import services.distributions_rpm as d

        repo_base = tmp_path / "repo_base"
        pool_dir = tmp_path / "pool_dir"
        pool_dir.mkdir(parents=True)
        monkeypatch.setattr(d, "REPO_BASE", repo_base)
        monkeypatch.setattr(d, "POOL_DIR", pool_dir)

        rpm_file = pool_dir / "nano-5.6.1-7.el9.x86_64.rpm"
        rpm_file.write_bytes(b"fake rpm content")

        with patch.object(d, "_run_createrepo", return_value=(0, "", "")), \
             patch.object(d, "_sign_repomd", return_value=True):
            ok, msg = d.add_rpm_to_distrib("nano-5.6.1-7.el9.x86_64.rpm", "almalinux9")

        assert ok is True
        assert "introuvable" not in msg.lower()
        # Copié dans REPO_BASE/{codename}/{arch}/, jamais dans POOL_DIR/{codename}/...
        assert (repo_base / "almalinux9" / "x86_64" / "nano-5.6.1-7.el9.x86_64.rpm").exists()

    def test_missing_file_in_pool_dir_reports_error(self, tmp_path, monkeypatch):
        import services.distributions_rpm as d

        monkeypatch.setattr(d, "REPO_BASE", tmp_path / "repo_base")
        monkeypatch.setattr(d, "POOL_DIR", tmp_path / "pool_dir")

        ok, msg = d.add_rpm_to_distrib("does-not-exist.x86_64.rpm", "almalinux9")
        assert ok is False
        assert "introuvable" in msg.lower()

    def test_aarch64_file_resolved_from_pool_dir(self, tmp_path, monkeypatch):
        """Même vérification pour aarch64 — confirme que le bug n'était pas
        spécifique à une architecture."""
        import services.distributions_rpm as d

        repo_base = tmp_path / "repo_base"
        pool_dir = tmp_path / "pool_dir"
        pool_dir.mkdir(parents=True)
        monkeypatch.setattr(d, "REPO_BASE", repo_base)
        monkeypatch.setattr(d, "POOL_DIR", pool_dir)

        rpm_file = pool_dir / "nano-5.6.1-7.el9.aarch64.rpm"
        rpm_file.write_bytes(b"fake rpm content")

        with patch.object(d, "_run_createrepo", return_value=(0, "", "")), \
             patch.object(d, "_sign_repomd", return_value=True):
            ok, msg = d.add_rpm_to_distrib("nano-5.6.1-7.el9.aarch64.rpm", "almalinux9")

        assert ok is True
        assert (repo_base / "almalinux9" / "aarch64" / "nano-5.6.1-7.el9.aarch64.rpm").exists()
