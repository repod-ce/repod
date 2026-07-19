# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_sync_manager.py
Rôle   : services/sync_manager.py:SyncManager — "un seul job actif par
         groupe" (all/apt/rpm/apk/source unique), documenté dans le
         docstring du module mais jamais réellement appliqué.

         Bug réel trouvé et corrigé : _active_job_for_group() reconstruisait
         le groupe d'un job en reparsant le premier mot de son LIBELLÉ
         D'AFFICHAGE (ex: _label("all") == "Toutes les sources" →
         "toutes" → _target_to_group("toutes") == "source:toutes", jamais
         "all") — vérifié pour les 5 cas (all/apt/rpm/apk/source unique) :
         aucun ne correspondait jamais. Deux appels à start_job("all")
         lancaient donc systématiquement DEUX jobs indépendants au lieu de
         renvoyer le job déjà actif — double téléchargement de ~20 sources
         upstream, double charge PostgreSQL, sans qu'aucun des deux jobs ne
         soit informé de l'autre.

         Fixé en stockant le groupe directement sur SyncJob à la création
         (job.group) plutôt qu'en le redérivant d'un texte destiné à
         l'affichage. Ces tests verrouillent le comportement corrigé.

Dépend : pytest, unittest.mock.patch (aucune DB — SyncManager ne touche
         PostgreSQL qu'à travers sync_source(), entièrement mocké ici).
"""
import time
from unittest.mock import patch

from services.sync_manager import SyncManager


def _slow_ok_sync(source, **kwargs):
    """Simule un sync_source() lent — garde le job 'running' assez
    longtemps pour que le test puisse observer la déduplication."""
    time.sleep(0.3)
    return {"source_id": source["id"], "status": "ok", "pkg_count": 1}


class TestGroupMutex:
    def test_second_call_for_same_group_returns_existing_job(self):
        mgr = SyncManager()
        with patch("services.package_index.sync_source", side_effect=_slow_ok_sync):
            job1 = mgr.start_job("all")
            job2 = mgr.start_job("all")
        assert job1.job_id == job2.job_id
        job1.cancel()
        time.sleep(0.5)  # laisse le thread daemon se terminer proprement

    def test_all_and_apt_and_rpm_and_apk_are_distinct_groups(self):
        mgr = SyncManager()
        with patch("services.package_index.sync_source", side_effect=_slow_ok_sync):
            jobs = {target: mgr.start_job(target) for target in ("all", "apt", "rpm", "apk")}
        job_ids = {j.job_id for j in jobs.values()}
        assert len(job_ids) == 4  # 4 groupes distincts -> 4 jobs distincts
        for target, job in jobs.items():
            assert job.group == target
            job.cancel()
        time.sleep(0.5)

    def test_single_source_target_is_its_own_group(self):
        mgr = SyncManager()
        with patch("services.package_index.sync_source", side_effect=_slow_ok_sync), \
             patch.object(SyncManager, "_sources_for_target", return_value=[
                 {"id": "ubuntu-jammy", "label": "Ubuntu 22.04 (Jammy) main"}
             ]):
            job1 = mgr.start_job("ubuntu-jammy")
            job2 = mgr.start_job("ubuntu-jammy")
        assert job1.job_id == job2.job_id
        assert job1.group == "source:ubuntu-jammy"
        job1.cancel()
        time.sleep(0.5)

    def test_new_job_can_start_once_previous_one_finished(self):
        mgr = SyncManager()
        with patch("services.package_index.sync_source",
                    return_value={"source_id": "x", "status": "ok", "pkg_count": 1}):
            job1 = mgr.start_job("apt")
            # Attend la fin réelle du job (sync instantané ici, pas de sleep)
            deadline = time.monotonic() + 5
            while job1.status == "running" and time.monotonic() < deadline:
                time.sleep(0.05)
            assert job1.status != "running"

            job2 = mgr.start_job("apt")
        # Le premier job est terminé : un nouveau job, distinct, doit démarrer.
        assert job2.job_id != job1.job_id
        assert job2.group == "apt"
