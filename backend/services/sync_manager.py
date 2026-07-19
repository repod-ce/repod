"""
Gestionnaire de jobs de synchronisation en arrière-plan.

Chaque job tourne dans un thread daemon et accumule ses logs en mémoire.
Les clients SSE peuvent se (re)connecter à n'importe quel moment et recevoir
tous les logs depuis le début du job + les futurs logs.

Architecture :
  - SyncJob   : état d'un job (logs, compteurs, status, threading.Event)
  - SyncManager : singleton gérant les jobs actifs + historique (1h)
  - Un seul job actif par groupe (all/apt/rpm/apk) pour éviter les collisions

Concurrence par format :
  - APT : semaphore(2)  — téléchargement Packages.gz (< 20 Mo chacun)
  - RPM : semaphore(1)  — streaming primary.xml.gz (jusqu'à 600 Mo par source)
  - APK : semaphore(3)  — APKINDEX.tar.gz très légers (< 2 Mo)
"""
import threading
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional


class SyncJob:
    """État complet d'un job de synchronisation."""

    def __init__(self, job_id: str, label: str, sources: list, group: str = ""):
        self.job_id = job_id
        self.label = label
        self.group = group  # "all"|"apt"|"rpm"|"apk"|"source:<id>" — voir SyncManager._active_job_for_group()
        self.sources = sources
        self.total = len(sources)
        self.done_count = 0
        self.error_count = 0
        self.status = "running"      # "running" | "done" | "error" | "cancelled"
        self.logs: list[str] = []    # format "level|message"
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.finished_at: Optional[str] = None
        self._lock = threading.Lock()
        self._new_log = threading.Event()
        self._stop = threading.Event()  # set() pour demander l'arrêt

    def cancel(self) -> bool:
        """Demande l'arrêt propre du job. Retourne True si le job était actif."""
        if self.status == "running":
            self._stop.set()
            self._new_log.set()  # débloquer les SSE en attente
            self.emit("warning", "⏹️ Arrêt demandé — la source en cours sera la dernière...")
            return True
        return False

    def emit(self, level: str, msg: str) -> None:
        line = f"{level}|{msg}"
        with self._lock:
            self.logs.append(line)
        self._new_log.set()

    def iter_stream(self, from_index: int = 0):
        """
        Générateur SSE reconnectable.
        Yield tous les logs depuis from_index, puis attend les futurs logs.
        Se termine quand le job est fini et tous les logs ont été émis.
        """
        idx = from_index
        while True:
            with self._lock:
                while idx < len(self.logs):
                    yield f"data: {self.logs[idx]}\n\n"
                    idx += 1
                is_done = self.status != "running"

            if is_done:
                yield "data: done|DONE\n\n"
                return

            # Attente du prochain log (timeout 1 s pour détecter la fin)
            self._new_log.wait(timeout=1.0)
            self._new_log.clear()

    def to_dict(self) -> dict:
        return {
            "job_id":        self.job_id,
            "label":         self.label,
            "status":        self.status,
            "total":         self.total,
            "done_count":    self.done_count,
            "error_count":   self.error_count,
            "started_at":    self.started_at,
            "finished_at":   self.finished_at,
            "log_count":     len(self.logs),
            "cancelling":    self._stop.is_set() and self.status == "running",
        }


class SyncManager:
    """Singleton gérant tous les jobs de synchronisation."""

    # Concurrence par format (nombre de sources en parallèle)
    _CONCURRENCY = {"apt": 2, "rpm": 1, "apk": 3}

    def __init__(self):
        self._jobs: Dict[str, SyncJob] = {}
        self._lock = threading.Lock()

    # ─── Gestion des jobs ─────────────────────────────────────────────────────

    def start_job(
        self,
        target: str,
        user: str = "system",
        enabled_filter=None,
    ) -> SyncJob:
        """
        Démarre un job de sync en arrière-plan.

        target : "all" | "apt" | "rpm" | "apk" | <source_id>
        enabled_filter : callable(source_id) → bool pour filtrer les sources actives
        Retourne le job existant si un job pour ce groupe est déjà actif.
        """
        group = self._target_to_group(target)

        with self._lock:
            # Retourner le job actif existant si présent
            existing = self._active_job_for_group(group)
            if existing:
                return existing

            sources = self._sources_for_target(target)
            if enabled_filter:
                sources = [s for s in sources if enabled_filter(s["id"])]

            if not sources:
                # Créer un job vide immédiatement terminé
                job_id = str(uuid.uuid4())[:8]
                job = SyncJob(job_id, self._label(target), [], group=group)
                job.emit("warning", "Aucune source active pour cette sélection")
                job.status = "done"
                job.finished_at = datetime.now(timezone.utc).isoformat()
                self._jobs[job_id] = job
                return job

            job_id = str(uuid.uuid4())[:8]
            job = SyncJob(job_id, self._label(target), sources, group=group)
            self._jobs[job_id] = job
            self._cleanup_old_jobs()

        thread = threading.Thread(
            target=self._run_job,
            args=(job, user),
            daemon=True,
            name=f"sync-{job_id}",
        )
        thread.start()
        return job

    def get_job(self, job_id: str) -> Optional[SyncJob]:
        return self._jobs.get(job_id)

    def cancel_job(self, job_id: str) -> bool:
        """Annule un job actif. Retourne True si le job existait et était actif."""
        job = self._jobs.get(job_id)
        if job:
            return job.cancel()
        return False

    def list_jobs(self, limit: int = 20) -> list[dict]:
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.started_at,
                reverse=True,
            )[:limit]
        return [j.to_dict() for j in jobs]

    def active_jobs(self) -> list[dict]:
        with self._lock:
            jobs = [j for j in self._jobs.values() if j.status == "running"]
        return [j.to_dict() for j in jobs]

    # ─── Corps du job ─────────────────────────────────────────────────────────

    def _run_job(self, job: SyncJob, user: str) -> None:
        try:
            from services.package_index import sync_source as _sync_one

            # Séparer les sources par format
            apt_srcs = [s for s in job.sources
                        if "apkindex_url" not in s and "repomd_url" not in s]
            rpm_srcs = [s for s in job.sources if "repomd_url" in s]
            apk_srcs = [s for s in job.sources if "apkindex_url" in s]

            # Lancer les 3 groupes en parallèle (threads format-level)
            fmt_threads = []
            for srcs, fmt_label, fmt_key in [
                (apt_srcs, "APT — Debian/Ubuntu", "apt"),
                (rpm_srcs, "RPM — RHEL/Fedora/SUSE", "rpm"),
                (apk_srcs, "APK — Alpine Linux", "apk"),
            ]:
                if not srcs or job._stop.is_set():
                    continue
                t = threading.Thread(
                    target=self._run_format_group,
                    args=(job, srcs, fmt_label, fmt_key, _sync_one),
                    daemon=True,
                )
                fmt_threads.append(t)
                t.start()

            for t in fmt_threads:
                t.join()

            # Résumé final
            if job._stop.is_set():
                job.emit("warning",
                         f"⏹️ Sync annulée — {job.done_count}/{job.total} source(s) traitées")
                job.status = "cancelled"
            elif job.error_count == 0:
                job.emit("success",
                         f"✅ Synchronisation terminée — {job.total} source(s)")
                job.status = "done"
            else:
                job.emit("warning",
                         f"Synchronisation terminée avec {job.error_count} erreur(s) "
                         f"sur {job.total} source(s)")
                job.status = "done"

            # Audit
            try:
                from services.audit import log as audit_log
                from services.format_router import FORMAT_LABEL
                audit_log("SYNC", user, job.status.upper(),
                          detail=f"Sync {FORMAT_LABEL} ({job.total} sources, "
                                 f"{job.error_count} erreurs)")
            except Exception:
                pass

        except Exception as exc:
            job.emit("error", f"Erreur inattendue : {exc}")
            job.status = "error"
        finally:
            job.finished_at = datetime.now(timezone.utc).isoformat()
            job._new_log.set()

    def _run_format_group(
        self, job: SyncJob, sources: list, fmt_label: str, fmt_key: str, sync_fn
    ) -> None:
        """Exécute un groupe de sources avec concurrence limitée."""
        concurrency = self._CONCURRENCY.get(fmt_key, 1)
        semaphore = threading.Semaphore(concurrency)
        fmt_errors = 0
        cancelled_count = 0
        threads_lock = threading.Lock()

        job.emit("info", f"📦 {fmt_label} ({len(sources)} source(s))...")

        def _sync_one(source):
            nonlocal fmt_errors, cancelled_count
            with semaphore:
                if job._stop.is_set():
                    with threads_lock:
                        cancelled_count += 1
                        job.done_count += 1
                    return
                job.emit("info", f"  ↳ {source['label']}...")
                try:
                    # Passer le stop_event aux sources RPM (qui supportent l'annulation mid-stream)
                    if "repomd_url" in source:
                        result = sync_fn(source, stop_event=job._stop)
                    else:
                        result = sync_fn(source)
                    with threads_lock:
                        job.done_count += 1
                    status = result.get("status", "error")
                    if status == "ok":
                        job.emit(
                            "success",
                            f"  ✅ {source['label']} — {result['pkg_count']:,} paquets",
                        )
                    elif status == "cancelled":
                        with threads_lock:
                            cancelled_count += 1
                    else:
                        err = result.get("error", "Erreur inconnue")[:200]
                        job.emit("error", f"  ❌ {source['label']} — {err}")
                        with threads_lock:
                            fmt_errors += 1
                            job.error_count += 1
                except Exception as exc:
                    with threads_lock:
                        fmt_errors += 1
                        job.error_count += 1
                        job.done_count += 1
                    job.emit("error", f"  ❌ {source['label']} — {exc}")

        workers = []
        for src in sources:
            t = threading.Thread(target=_sync_one, args=(src,), daemon=True)
            workers.append(t)
            t.start()

        for t in workers:
            t.join()

        if job._stop.is_set():
            return  # Le résumé sera fait dans _run_job

        ok_count = len(sources) - fmt_errors - cancelled_count
        if fmt_errors == 0:
            job.emit("success", f"  ✅ {fmt_label} : {ok_count}/{len(sources)} OK")
        else:
            job.emit("warning",
                     f"  ⚠️ {fmt_label} : {ok_count}/{len(sources)} OK, "
                     f"{fmt_errors} erreur(s)")

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _target_to_group(target: str) -> str:
        if target in ("all", "apt", "rpm", "apk"):
            return target
        return f"source:{target}"

    @staticmethod
    def _label(target: str) -> str:
        return {
            "all": "Toutes les sources",
            "apt": "Sources APT — Debian/Ubuntu",
            "rpm": "Sources RPM — RHEL/Fedora/SUSE",
            "apk": "Sources APK — Alpine Linux",
        }.get(target, f"Source {target}")

    @staticmethod
    def _sources_for_target(target: str) -> list:
        from services.package_index import DEFAULT_SOURCES
        if target == "all":
            return list(DEFAULT_SOURCES)
        if target == "apt":
            return [s for s in DEFAULT_SOURCES
                    if "apkindex_url" not in s and "repomd_url" not in s]
        if target == "rpm":
            return [s for s in DEFAULT_SOURCES if "repomd_url" in s]
        if target == "apk":
            return [s for s in DEFAULT_SOURCES if "apkindex_url" in s]
        # Source unique par ID
        src = next((s for s in DEFAULT_SOURCES if s["id"] == target), None)
        return [src] if src else []

    def _active_job_for_group(self, group: str) -> Optional[SyncJob]:
        """
        Retourne le job actif pour ce groupe, ou None.

        Bug réel trouvé et corrigé ici : cette méthode reconstruisait le
        groupe en reparsant le premier mot du LIBELLÉ D'AFFICHAGE du job
        (ex: "Toutes les sources" → "toutes" → _target_to_group("toutes")
        → "source:toutes", jamais "all") — vérifié mathématiquement pour
        les 5 cas (all/apt/rpm/apk/source unique) : AUCUN ne correspondait
        jamais. Le mutex "un seul job actif par groupe" documenté dans le
        docstring du module était donc un no-op total depuis toujours.
        Fixé en comparant directement job.group (stocké tel quel à la
        création, voir start_job()), plus aucune reconstruction depuis un
        texte destiné à l'affichage.
        """
        return next(
            (j for j in self._jobs.values()
             if j.status == "running"
             and j.group == group),
            None,
        )

    def _cleanup_old_jobs(self) -> None:
        """Supprime les jobs terminés depuis > 1h (appelé sous _lock)."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        to_del = []
        for jid, job in self._jobs.items():
            if job.status != "running" and job.finished_at:
                try:
                    if datetime.fromisoformat(job.finished_at) < cutoff:
                        to_del.append(jid)
                except Exception:
                    pass
        for jid in to_del:
            del self._jobs[jid]


# Singleton global
sync_manager = SyncManager()
