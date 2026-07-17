/**
 * SyncJobContext.js
 * =================
 * Contexte global pour le suivi des jobs de synchronisation.
 *
 * - Poll GET /import/sync/jobs/active toutes les 3s si jobs actifs
 * - Stocke les job_id récents en mémoire (survit à la navigation)
 * - Expose : jobs actifs, startSync(target), isRunning(target)
 * - Toast automatique à la fin de chaque job
 */
import {
  createContext, useContext, useEffect, useRef, useState, useCallback,
} from "react";
import toast from "react-hot-toast";
import { getApiBaseUrl } from "../api";

const API_URL = getApiBaseUrl();
const SyncJobContext = createContext(null);

const POLL_ACTIVE_MS = 2500;   // intervalle quand jobs actifs
const POLL_IDLE_MS   = 15000;  // intervalle quand aucun job actif

async function apiFetch(path, opts = {}) {
  const token = localStorage.getItem("token");
  const res = await fetch(`${API_URL}${path}`, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(opts.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export function SyncJobProvider({ children }) {
  const [jobs, setJobs]       = useState([]);   // liste enrichie {job_id, label, status, target, …}
  const [activeCount, setAct] = useState(0);
  const notifiedRef  = useRef(new Set());
  const timerRef     = useRef(null);
  const errorCount   = useRef(0);

  // Mapping job_id → target (pour retrouver le groupe d'un job)
  const jobTargetRef = useRef({});

  const poll = useCallback(async () => {
    try {
      const data = await apiFetch("/import/sync/jobs");
      const allJobs = data.jobs || [];
      errorCount.current = 0;

      setJobs(allJobs);
      const running = allJobs.filter(j => j.status === "running").length;
      setAct(running);

      // Notifications automatiques pour les jobs qui viennent de se terminer
      allJobs.forEach(j => {
        if (notifiedRef.current.has(j.job_id)) return;
        if (j.status === "done" && j.finished_at) {
          notifiedRef.current.add(j.job_id);
          const errs = j.error_count || 0;
          if (errs === 0) {
            toast.success(`Sync terminée — ${j.label}\n${j.total} sources`, { duration: 5000 });
          } else {
            toast.error(`Sync avec erreurs — ${j.label}\n${errs}/${j.total} échecs`, { duration: 7000 });
          }
        }
        if (j.status === "error") {
          notifiedRef.current.add(j.job_id);
          toast.error(`Sync échouée — ${j.label}`, { duration: 7000 });
        }
      });
    } catch {
      errorCount.current += 1;
    } finally {
      const delay = activeCount > 0 ? POLL_ACTIVE_MS : POLL_IDLE_MS;
      timerRef.current = setTimeout(poll, delay);
    }
  }, [activeCount]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    poll();
    return () => clearTimeout(timerRef.current);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * Démarre un job de sync.
   * target : "all" | "apt" | "rpm" | "apk" | <source_id>
   * Retourne { job_id, label, status }
   */
  const startSync = useCallback(async (target = "all") => {
    const path = target === "all"
      ? "/import/sync/start"
      : `/import/sync/start/${target}`;
    const data = await apiFetch(path, { method: "POST" });
    jobTargetRef.current[data.job_id] = target;
    // Forcer un poll immédiat
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(poll, 300);
    return data;
  }, [poll]);

  /**
   * Retourne true si un job pour ce target est actif.
   */
  const isRunning = useCallback((target) => {
    if (target === "all") return activeCount > 0;
    return jobs.some(j =>
      j.status === "running" &&
      (jobTargetRef.current[j.job_id] === target || j.label?.toLowerCase().includes(target))
    );
  }, [jobs, activeCount]);

  /**
   * Retourne le dernier job pour un target donné.
   */
  const getLatestJob = useCallback((target) => {
    if (target === "all") return jobs[0] || null;
    return jobs.find(j =>
      jobTargetRef.current[j.job_id] === target ||
      j.label?.toLowerCase().includes(target === "apk" ? "alpine" : target)
    ) || null;
  }, [jobs]);

  /**
   * Annule un job en cours par son job_id.
   * Retourne { job_id, cancelled, status, message }
   */
  const cancelJob = useCallback(async (jobId) => {
    const data = await apiFetch(`/import/sync/jobs/${jobId}/cancel`, { method: "POST" });
    clearTimeout(timerRef.current);
    timerRef.current = setTimeout(poll, 300);
    return data;
  }, [poll]);

  return (
    <SyncJobContext.Provider value={{ jobs, activeCount, startSync, cancelJob, isRunning, getLatestJob }}>
      {children}
    </SyncJobContext.Provider>
  );
}

export function useSyncJobs() {
  const ctx = useContext(SyncJobContext);
  if (!ctx) throw new Error("useSyncJobs must be used inside <SyncJobProvider>");
  return ctx;
}
