# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
services/http_retry.py — retry avec backoff court pour les fetchs réseau
du sync d'index (package_index_apt.py/package_index_rpm.py/package_index_apk.py).

Avant ce module : un timeout ou une erreur 5xx ponctuelle sur UNE seule
requête marquait directement la source "error" jusqu'au prochain cron/
déclenchement manuel — aucune distinction entre "source déplacée
définitivement" (404/403, réessayer ne changera rien) et "aléa réseau
transitoire" (souvent résolu en réessayant quelques secondes après). Une
source qui échoue systématiquement au même moment du cron (ex: fenêtre de
maintenance upstream, pic de charge du mirroir) restait en erreur toute la
journée pour un blip qui aurait pu se résoudre au 2ᵉ essai.

Portée délibérément limitée aux petits fichiers (InRelease, repomd.xml,
APKINDEX.tar.gz — quelques Ko à quelques Mo) : le téléchargement volumineux
et annulable de primary.xml.gz RPM (jusqu'à 600 Mo, streaming avec support
d'un stop_event) n'est PAS retenté ici — retenter un flux de plusieurs
centaines de Mo interrompu à mi-chemin poserait des questions de reprise
partielle hors du périmètre de ce correctif ; son premier appel réseau
(récupérer repomd.xml lui-même, un petit fichier XML) est en revanche
couvert.
"""
import logging
import time
import urllib.error
import urllib.request

logger = logging.getLogger("http_retry")

# Codes HTTP pour lesquels réessayer ne changera rien : la ressource n'existe
# pas/plus ou l'accès est refusé — ce n'est jamais un aléa réseau transitoire.
_NON_RETRYABLE_HTTP_CODES = frozenset({400, 401, 403, 404, 410})


def fetch_url(
    url: str,
    headers: dict | None = None,
    timeout: int = 30,
    max_retries: int = 2,
    backoff_seconds: tuple[float, ...] = (2.0, 5.0),
    _sleep=None,
) -> bytes:
    """
    Télécharge `url`, avec jusqu'à `max_retries` nouvelles tentatives sur
    erreur réseau transitoire (timeout, connexion refusée/réinitialisée,
    DNS temporairement indisponible, ou HTTP 5xx/429) — jamais sur une
    erreur HTTP 4xx qui indique que la ressource elle-même a un problème
    (404/403/401/410 : la réessayer ne changera rien).

    `_sleep` est injectable pour les tests (évite d'attendre réellement
    backoff_seconds en secondes réelles) — résolu à CHAQUE appel (`time.sleep`
    par défaut si non fourni), jamais capturé comme valeur par défaut de
    paramètre : un défaut `_sleep=time.sleep` figerait la référence à
    l'import du module, avant qu'un `patch("services.http_retry.time.sleep")`
    dans un test n'ait pu s'appliquer.

    Lève la dernière exception rencontrée si toutes les tentatives échouent.
    """
    sleep_fn = _sleep or time.sleep
    req = urllib.request.Request(url, headers=headers or {})
    last_exc: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in _NON_RETRYABLE_HTTP_CODES:
                raise
            last_exc = exc
        except urllib.error.URLError as exc:
            last_exc = exc
        except OSError as exc:
            # socket.timeout (Python < 3.10 alias) et autres erreurs bas niveau
            # non enveloppées par urllib dans une URLError selon la plateforme.
            last_exc = exc

        if attempt < max_retries:
            delay = backoff_seconds[min(attempt, len(backoff_seconds) - 1)]
            logger.warning(
                "[http_retry] Échec réseau transitoire pour %s (essai %d/%d) : %s — nouvelle tentative dans %ss",
                url, attempt + 1, max_retries + 1, last_exc, delay,
            )
            sleep_fn(delay)

    raise last_exc
