"""
services/sse_bus.py — Bus d'événements en mémoire pour les Server-Sent Events.

Architecture
------------
Le bus est un singleton en mémoire. N'importe quel code synchrone peut publier
un événement via publish_event(). Les abonnés SSE lisent depuis des queues
queue.Queue(maxsize) — thread-safe, put_nowait non-bloquant.

Thread safety
-------------
Ajout/suppression d'abonnés protégés par un verrou. Les publications sont
non-bloquantes (put_nowait) : les queues pleines perdent l'événement sans
bloquer l'appelant.

Garantie
--------
publish_event() ne lève JAMAIS d'exception — toute erreur est loggée et avalée.

Événements connus
-----------------
  audit_log        — nouvelle entrée d'audit (action, user, result, package)
  notification     — notification envoyée (event_type, ok_count, total)
  package_upload   — nouveau paquet importé (package, version)
  pending_review   — promotion en attente créée/mise à jour
  heartbeat        — keepalive périodique (émis par le générateur SSE)
"""

import json
import logging
import queue
import threading
from typing import Any

logger = logging.getLogger("sse_bus")

# Capacité max par queue d'abonné (événements)
QUEUE_MAXSIZE: int = 100


class EventBus:
    """Bus d'événements thread-safe pour diffuser des événements aux clients SSE."""

    def __init__(self):
        self._subscribers: list[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        """
        Crée une queue pour un nouvel abonné SSE.
        L'appelant DOIT appeler unsubscribe() à la déconnexion (cleanup).
        """
        q: queue.Queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
        with self._lock:
            self._subscribers.append(q)
        logger.debug("[sse_bus] Nouvel abonné (%d total)", len(self._subscribers))
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Supprime la queue de l'abonné. Appelé à la déconnexion du client SSE."""
        with self._lock:
            try:
                self._subscribers.remove(q)
                logger.debug("[sse_bus] Abonné supprimé (%d restants)",
                             len(self._subscribers))
            except ValueError:
                pass  # déjà supprimé

    def publish(self, event_type: str, data: dict[str, Any]) -> int:
        """
        Diffuse un événement à tous les abonnés actifs. Non-bloquant.

        Retourne le nombre d'abonnés atteints.
        Les queues pleines perdent l'événement (put_nowait → QueueFull ignoré).
        """
        event = {"type": event_type, "data": data}
        with self._lock:
            queues = list(self._subscribers)

        sent = 0
        for q in queues:
            try:
                q.put_nowait(event)
                sent += 1
            except queue.Full:
                logger.debug("[sse_bus] Queue pleine — événement perdu pour un abonné")
            except Exception as exc:
                logger.debug("[sse_bus] put_nowait failed : %s", type(exc).__name__)
        return sent

    @property
    def subscriber_count(self) -> int:
        """Nombre d'abonnés SSE actifs."""
        with self._lock:
            return len(self._subscribers)


# ── Singleton ─────────────────────────────────────────────────────────────────

_bus = EventBus()


def get_bus() -> EventBus:
    """Retourne le bus SSE singleton."""
    return _bus


def publish_event(event_type: str, data: dict[str, Any]) -> int:
    """
    Publie un événement sur le bus SSE global. Ne lève JAMAIS d'exception.

    Retourne le nombre d'abonnés atteints (0 si aucun abonné ou erreur).
    """
    try:
        return _bus.publish(event_type, data)
    except Exception as exc:
        logger.warning("[sse_bus] publish_event erreur inattendue : %s",
                       type(exc).__name__)
        return 0


# ── Formatage SSE ─────────────────────────────────────────────────────────────

def sse_format(event: dict[str, Any]) -> str:
    """
    Formate un événement en ligne SSE standard.

    Exemple de sortie :
      data: {"type": "audit_log", "data": {...}}\n\n
    """
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
