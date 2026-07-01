"""
Logging JSON structuré (P2-2).

Fournit :
  • setup_logging()    — configure le logger racine avec JsonFormatter
  • request_id_var     — ContextVar propagé dans chaque log via _RequestIdFilter
  • get_log_buffer()   — retourne les N derniers log records (ring buffer)
  • subscribe_logs()   — s'abonne au flux temps réel (retourne une asyncio.Queue)
  • unsubscribe_logs() — se désabonne

Usage dans main.py :
    from services.logging_config import setup_logging
    setup_logging()

Usage dans les services (inchangé — les getLogger() existants héritent du root) :
    import logging
    logger = logging.getLogger("mon_service")
    logger.info("message")   # → {"timestamp": "...", "level": "INFO",
                             #    "name": "mon_service", "message": "...",
                             #    "request_id": "<uuid|->"}

Le champ request_id vaut "-" hors contexte de requête HTTP.
Il est positionné par RequestIdMiddleware via contextvars.
"""
import asyncio
import logging
import sys
import threading
import time
from collections import deque
from contextvars import ContextVar
from typing import IO

from pythonjsonlogger import jsonlogger

# ── ContextVar de corrélation ─────────────────────────────────────────────────
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

# ── Ring buffer en mémoire (2 000 entrées max) ────────────────────────────────
_LOG_BUFFER: deque[dict] = deque(maxlen=2000)
_LOG_SUBSCRIBERS: list[asyncio.Queue] = []
_SUBS_LOCK = threading.Lock()   # protège les modifications de _LOG_SUBSCRIBERS


def get_log_buffer() -> list[dict]:
    """Retourne une copie des N derniers logs backend."""
    return list(_LOG_BUFFER)


def subscribe_logs() -> asyncio.Queue:
    """Crée et enregistre une queue pour recevoir les nouveaux logs en temps réel."""
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    with _SUBS_LOCK:
        _LOG_SUBSCRIBERS.append(q)
    return q


def unsubscribe_logs(q: asyncio.Queue) -> None:
    """Supprime la queue de la liste des abonnés."""
    with _SUBS_LOCK:
        try:
            _LOG_SUBSCRIBERS.remove(q)
        except ValueError:
            pass


# ── Filtre d'injection du request_id ─────────────────────────────────────────

class _RequestIdFilter(logging.Filter):
    """
    Lit request_id_var et l'injecte dans chaque LogRecord.
    Compatible avec tous les handlers ajoutés au root logger.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


# ── Handler ring-buffer + diffusion temps réel ───────────────────────────────

class _MemoryHandler(logging.Handler):
    """
    Capture chaque log record dans _LOG_BUFFER et notifie les abonnés SSE.
    Filtre les logs de monitoring (healthcheck, métriques) pour réduire le bruit.
    """

    _NOISE_PREFIXES = (
        "GET /health/",
        "GET /metrics",
    )

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            # Filtre les healthchecks et métriques (trop fréquents)
            if any(p in msg for p in self._NOISE_PREFIXES):
                return

            entry: dict = {
                "ts":      time.time(),
                "level":   record.levelname,
                "name":    record.name,
                "message": msg,
                "service": "backend",
            }
            _LOG_BUFFER.append(entry)

            # Snapshot thread-safe de la liste des abonnés
            with _SUBS_LOCK:
                subscribers = list(_LOG_SUBSCRIBERS)

            if not subscribers:
                return

            # Diffusion vers les asyncio.Queue des abonnés SSE.
            # emit() peut être appelé depuis n'importe quel thread (y compris le main
            # thread ou un thread daemon) — asyncio.Queue.put_nowait() n'est pas
            # thread-safe, on passe donc par call_soon_threadsafe() pour planifier
            # l'envoi dans la boucle asyncio.
            def _push_to_queues() -> None:
                for q in subscribers:
                    try:
                        q.put_nowait(entry)
                    except asyncio.QueueFull:
                        pass  # abonné trop lent — on perd l'entrée plutôt que bloquer

            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(_push_to_queues)
            except RuntimeError:
                # Aucune boucle asyncio active (ex : démarrage / tests sync)
                # On tente un put direct — risque faible hors contexte multi-thread
                _push_to_queues()
        except Exception:
            self.handleError(record)


# ── Configuration principale ──────────────────────────────────────────────────

def setup_logging(
    level: int = logging.INFO,
    stream: IO[str] | None = None,
) -> None:
    """
    Configure le logger racine avec un JsonFormatter (python-json-logger).

    Paramètres
    ----------
    level  : niveau de log (défaut : INFO)
    stream : flux de sortie (défaut : sys.stderr) — passez un StringIO en test
             pour capturer la sortie sans polluer stderr.

    Après appel, tout logger obtenu par logging.getLogger("x") émet du JSON :
        {"timestamp": "...", "level": "INFO", "name": "x",
         "message": "...", "request_id": "-"}
    """
    formatter = jsonlogger.JsonFormatter(
        fmt="%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        rename_fields={"levelname": "level", "asctime": "timestamp"},
    )

    stream_handler = logging.StreamHandler(stream or sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(_RequestIdFilter())

    memory_handler = _MemoryHandler()
    memory_handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(stream_handler)
    root.addHandler(memory_handler)
    root.setLevel(level)

    # Expose l'instance pour pouvoir l'attacher aux loggers uvicorn plus tard
    # (uvicorn configure ses loggers avec propagate=False via dictConfig — on doit
    # les brancher directement après que uvicorn a fini sa configuration)
    setup_logging._memory_handler = memory_handler
