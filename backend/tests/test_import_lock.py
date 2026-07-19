# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_import_lock.py
Rôle   : services/import_lock.py:package_import_lock() — sérialise les
         imports concurrents d'un même (nom, distribution), branché dans
         import_one() des trois formats (APT/RPM/APK).

         Avant ce correctif : deux imports concurrents du même paquet
         (double-clic, le même paquet dans deux arbres de dépendances
         importés par deux utilisateurs différents, un mirroir qui
         chevauche un import manuel) pouvaient tous deux passer le
         contrôle "déjà présent ?", télécharger/scanner en double, et se
         disputer reprepro/createrepo_c/apk index en même temps — reprepro
         a son propre verrouillage interne, mais un import qui perd cette
         course échoue silencieusement ("indexé mais non publié") plutôt
         que d'attendre proprement son tour.

Dépend : pytest, threading (aucune DB, aucun réseau — la logique de
         verrouillage est testée isolément de import_one()).
"""
import threading
import time

from services.import_lock import package_import_lock


class TestPackageImportLock:
    def test_second_caller_waits_for_first_to_release(self):
        """Deux threads demandant le même (nom, distribution) doivent
        s'exécuter en série, jamais en même temps."""
        events: list[str] = []
        events_lock = threading.Lock()
        barrier_entered = threading.Event()

        def worker(label: str, hold_seconds: float):
            with package_import_lock("nginx", "jammy"):
                with events_lock:
                    events.append(f"{label}-start")
                if label == "first":
                    barrier_entered.set()
                time.sleep(hold_seconds)
                with events_lock:
                    events.append(f"{label}-end")

        t1 = threading.Thread(target=worker, args=("first", 0.3))
        t1.start()
        barrier_entered.wait(timeout=2)  # s'assure que "first" a bien démarré avant "second"
        t2 = threading.Thread(target=worker, args=("second", 0.0))
        t2.start()
        t1.join(timeout=2)
        t2.join(timeout=2)

        # "second" ne doit démarrer qu'APRÈS la fin de "first" — jamais entrelacé.
        assert events == ["first-start", "first-end", "second-start", "second-end"]

    def test_different_package_names_run_concurrently(self):
        """Deux noms de paquets différents ne doivent PAS se bloquer
        mutuellement — le verrou est scopé par paquet, pas global."""
        both_running = threading.Event()
        entered = {"nginx": False, "curl": False}
        entered_lock = threading.Lock()

        def worker(name: str):
            with package_import_lock(name, "jammy"):
                with entered_lock:
                    entered[name] = True
                    if all(entered.values()):
                        both_running.set()
                time.sleep(0.3)

        t1 = threading.Thread(target=worker, args=("nginx",))
        t2 = threading.Thread(target=worker, args=("curl",))
        t1.start()
        t2.start()
        # Si le verrou était global (pas par paquet), l'un des deux
        # attendrait l'autre et both_running ne serait jamais set() à temps.
        assert both_running.wait(timeout=1.0)
        t1.join(timeout=2)
        t2.join(timeout=2)

    def test_same_name_different_distribution_run_concurrently(self):
        """Le même nom de paquet dans deux distributions différentes
        (ex: import simultané pour jammy ET noble) ne doit pas se bloquer —
        la clé inclut la distribution."""
        both_running = threading.Event()
        entered = {"jammy": False, "noble": False}
        entered_lock = threading.Lock()

        def worker(distro: str):
            with package_import_lock("curl", distro):
                with entered_lock:
                    entered[distro] = True
                    if all(entered.values()):
                        both_running.set()
                time.sleep(0.3)

        t1 = threading.Thread(target=worker, args=("jammy",))
        t2 = threading.Thread(target=worker, args=("noble",))
        t1.start()
        t2.start()
        assert both_running.wait(timeout=1.0)
        t1.join(timeout=2)
        t2.join(timeout=2)

    def test_lock_released_even_if_body_raises(self):
        """Une exception dans le bloc protégé ne doit jamais laisser le
        verrou acquis indéfiniment (deadlock au prochain import du même paquet)."""
        try:
            with package_import_lock("broken-pkg", "jammy"):
                raise ValueError("boom")
        except ValueError:
            pass

        acquired = threading.Event()

        def worker():
            with package_import_lock("broken-pkg", "jammy"):
                acquired.set()

        t = threading.Thread(target=worker)
        t.start()
        assert acquired.wait(timeout=1.0), "le verrou est resté bloqué après une exception"
        t.join(timeout=2)
