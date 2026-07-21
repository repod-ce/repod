# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_reprepro.py
Rôle   : services/reprepro.py:remove_package() — aucun test dédié n'existait
         malgré son rôle central dans la suppression réelle des paquets APT.

         Bug réel trouvé en direct sur un déploiement (.20) : un paquet
         "supprimé" avec succès dans l'UI (notification de succès, disparu
         de "Paquets disponibles") restait pourtant détecté comme "déjà
         présent" ailleurs (page Importer). Root cause en deux temps :

         1. --delete manquant sur `reprepro remove` — sans lui, reprepro
            désindexe le paquet mais laisse son .deb orphelin dans le pool
            hiérarchique (pool/main/**/{name}_*.deb). Corrigé avec --delete
            sur remove + un sweep deleteunreferenced() après coup.

         2. Une fois --delete/deleteunreferenced ajoutés, testé en direct
            contre un vrai dépôt signé : aucun des deux ne passait jamais
            env=_gnupg_env() (GNUPGHOME) à son subprocess.run() — reprepro
            ne trouvait alors plus la clé de signature ("Could not find any
            key matching '<id>'!"), échouait à ré-exporter le Release file
            (code 255), et refusait explicitement de nettoyer le fichier
            orphelin ("Not deleting possibly left over files due to
            previous errors") — le tout masqué par le traitement
            best-effort de l'appelant, qui rapportait un succès malgré tout.

Dépend : pytest, unittest.mock (aucun subprocess/reprepro réel invoqué).
"""
import subprocess
from unittest.mock import MagicMock, patch

import services.reprepro as reprepro


class TestRemovePackage:

    def test_removes_from_all_default_distributions(self):
        mock_result = MagicMock(returncode=0, stdout="removed", stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = reprepro.remove_package("nginx", via_docker=False)
        assert result["all_ok"] is True
        assert set(result["distributions"]) == set(reprepro._DEFAULT_DISTS)
        # +1 : le sweep deleteunreferenced() appelé une fois après la boucle.
        assert mock_run.call_count == len(reprepro._DEFAULT_DISTS) + 1

    def test_delete_flag_present_on_every_remove_command(self):
        mock_result = MagicMock(returncode=0, stdout="removed", stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            reprepro.remove_package("nginx", distributions=["jammy", "noble"], via_docker=False)
        remove_calls = [c for c in mock_run.call_args_list if "remove" in c[0][0]]
        assert len(remove_calls) == 2
        for call in remove_calls:
            assert "--delete" in call[0][0]

    def test_deleteunreferenced_swept_after_removal(self):
        mock_result = MagicMock(returncode=0, stdout="removed", stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            reprepro.remove_package("nginx", distributions=["jammy"], via_docker=False)
        last_cmd = mock_run.call_args_list[-1][0][0]
        assert "deleteunreferenced" in last_cmd
        assert "--delete" in last_cmd

    def test_gnupghome_env_passed_to_remove_command(self):
        mock_result = MagicMock(returncode=0, stdout="removed", stderr="")
        with patch.dict("os.environ", {"GNUPG_HOME": "/custom/gnupg"}), \
             patch("subprocess.run", return_value=mock_result) as mock_run:
            reprepro.remove_package("nginx", distributions=["jammy"], via_docker=False)
        for call in mock_run.call_args_list:
            env = call.kwargs.get("env")
            assert env is not None, f"subprocess.run() appelé sans env= : {call.args[0]}"
            assert env["GNUPGHOME"] == "/custom/gnupg"

    def test_deleteunreferenced_failure_does_not_raise(self):
        """Best-effort : un échec du sweep deleteunreferenced() ne doit
        jamais faire échouer remove_package() dans son ensemble."""
        ok_result = MagicMock(returncode=0, stdout="removed", stderr="")

        def fake_run(cmd, **kwargs):
            if "deleteunreferenced" in cmd:
                raise subprocess.TimeoutExpired(cmd="reprepro", timeout=30)
            return ok_result

        with patch("subprocess.run", side_effect=fake_run):
            result = reprepro.remove_package("nginx", distributions=["jammy"], via_docker=False)
        assert result["all_ok"] is True

    def test_removes_only_from_specified_distributions(self):
        mock_result = MagicMock(returncode=0, stdout="removed", stderr="")
        with patch("subprocess.run", return_value=mock_result):
            result = reprepro.remove_package("nginx", distributions=["jammy"], via_docker=False)
        assert result["distributions"] == ["jammy"]
        assert result["results"]["jammy"]["ok"] is True

    def test_partial_failure_across_distributions_reported_accurately(self):
        ok_result = MagicMock(returncode=0, stdout="removed", stderr="")
        fail_result = MagicMock(returncode=1, stdout="", stderr="not found in noble")

        def fake_run(cmd, **kwargs):
            return fail_result if "noble" in cmd else ok_result

        with patch("subprocess.run", side_effect=fake_run):
            result = reprepro.remove_package("nginx", distributions=["jammy", "noble"], via_docker=False)

        assert result["all_ok"] is False
        assert result["results"]["jammy"]["ok"] is True
        assert result["results"]["noble"]["ok"] is False
        assert "not found" in result["results"]["noble"]["output"]

    def test_via_docker_wraps_command(self):
        mock_result = MagicMock(returncode=0, stdout="ok", stderr="")
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            reprepro.remove_package("nginx", distributions=["jammy"], via_docker=True)
        cmd = mock_run.call_args_list[0][0][0]
        assert cmd[:3] == ["docker", "exec", reprepro._CONTAINER]

    def test_timeout_on_one_distribution_does_not_abort_others(self):
        ok_result = MagicMock(returncode=0, stdout="removed", stderr="")

        def fake_run(cmd, **kwargs):
            if "jammy" in cmd:
                raise subprocess.TimeoutExpired(cmd="reprepro", timeout=30)
            return ok_result

        with patch("subprocess.run", side_effect=fake_run):
            result = reprepro.remove_package("nginx", distributions=["jammy", "noble"], via_docker=False)

        assert result["results"]["jammy"]["ok"] is False
        assert "timeout" in result["results"]["jammy"]["output"]
        assert result["results"]["noble"]["ok"] is True
        assert result["all_ok"] is False

    def test_missing_binary_reported_per_distribution(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("reprepro: not found")):
            result = reprepro.remove_package("nginx", distributions=["jammy"], via_docker=False)
        assert result["results"]["jammy"]["ok"] is False
        assert result["all_ok"] is False
