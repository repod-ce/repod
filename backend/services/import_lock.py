# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
services/import_lock.py — verrou par paquet pendant l'import, partagé par
les trois formats (APT/RPM/APK) et tous les points d'entrée existants
(import direct POST /import/fetch, import par lot POST /import/batch,
dépendances auto-importées à l'upload manuel — routers/upload.py, mirroir
planifié — services/mirror_manager.py).

Pourquoi c'est nécessaire : sans lui, deux imports concurrents du même
paquet — double-clic sur "Importer", le même paquet apparaissant dans deux
arbres de dépendances importés par deux utilisateurs différents au même
moment, ou un mirroir planifié qui chevauche un import manuel — peuvent
tous les deux passer le contrôle "déjà présent dans le pool ?", télécharger
et scanner (ClamAV + Grype) en double, puis se disputer reprepro/
createrepo_c/apk index en même temps. reprepro a son propre verrouillage
interne, mais un import qui perd cette course échoue silencieusement
("indexé mais non publié", un simple avertissement) plutôt que d'attendre
proprement son tour.

Où c'est branché : à l'intérieur même de import_one() dans chacun des
trois modules format-spécifiques (importer_apt.py/importer_rpm.py/
importer_apk.py), pas seulement au niveau du dispatcher services/importer.py
— le chemin le plus emprunté (import_package_stream() résolvant tout un
arbre de dépendances) appelle le import_one() LOCAL de son propre module
directement, sans jamais passer par le dispatcher.
"""
import threading
from contextlib import contextmanager

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _get_lock(key: str) -> threading.Lock:
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _locks[key] = lock
        return lock


@contextmanager
def package_import_lock(name: str, distribution: str | None):
    """
    Sérialise les imports concurrents d'un même (nom, distribution) — le
    second appelant ATTEND que le premier termine (téléchargement +
    validation + publication) au lieu de se disputer reprepro en parallèle.
    Une fois le premier terminé, le paquet est déjà présent : le second
    appelant reprend normalement et voit "déjà présent" au contrôle qui
    suit l'acquisition du verrou — aucun changement de comportement pour
    lui au-delà de l'attente.

    Clé délibérément jamais nettoyée : un dict de threading.Lock ne coûte
    que quelques dizaines d'octets par entrée distincte — même plusieurs
    dizaines de milliers de paquets importés au fil du temps restent
    négligeables. Pas de mécanisme d'éviction ajouté pour un coût mémoire
    qui n'a jamais été démontré réel, pour éviter la classe de bug bien
    plus sérieuse d'une éviction mal synchronisée créant deux verrous
    concurrents pour la même clé.
    """
    key = f"{name}:{distribution or ''}"
    lock = _get_lock(key)
    with lock:
        yield
