import { useState, useEffect, useRef, useCallback, Fragment } from "react";
import toast from "react-hot-toast";
import {
  FiPackage,
  FiCheckCircle,
  FiAlertTriangle,
  FiXCircle,
  FiStopCircle,
} from "react-icons/fi";
import { SiAlpinelinux } from "react-icons/si";
import {
  getImportSyncStatus,
  getApiBaseUrl,
  getMirrorSources,
  updateMirrorSources,
  getMirrorSchedule,
  updateMirrorSchedule,
  startMirrorJob,
  getMirrorJobs,
  cancelMirrorJob,
} from "../api";
import { useSyncJobs } from "../context/SyncJobContext";
import { useAuth } from "../context/AuthContext";

const API_URL = getApiBaseUrl();

// ─── Helpers ─────────────────────────────────────────────────────────────────

function Badge({ children, color = "gray" }) {
  const colors = {
    gray: "bg-gray-100 text-gray-600",
    green: "bg-green-100 text-green-700",
    yellow: "bg-yellow-100 text-yellow-700",
    red: "bg-red-100 text-red-700",
    blue: "bg-blue-100 text-blue-700",
    orange: "bg-orange-100 text-orange-700",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors[color]}`}>
      {children}
    </span>
  );
}

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");

  const styles = {
    info: "text-gray-300",
    success: "text-green-400",
    error: "text-red-400",
    warning: "text-yellow-400",
    skip: "text-gray-500",
    done: "text-blue-400 font-semibold",
  };

  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

// ─── SyncJobPanel : logs persistants pour un job ─────────────────────────────

function SyncJobPanel({ jobId, onClose }) {
  const [logs, setLogs] = useState([]);
  const [jobInfo, setJobInfo] = useState(null);
  const [connected, setConnected] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const logsRef = useRef(null);
  const indexRef = useRef(0);
  const abortRef = useRef(null);
  const { cancelJob } = useSyncJobs();

  const connect = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const token = localStorage.getItem("token");
    const fromIdx = indexRef.current;
    fetch(`${API_URL}/import/sync/jobs/${jobId}/stream?from_index=${fromIdx}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: ctrl.signal,
    }).then(async (resp) => {
      if (!resp.ok) return;
      setConnected(true);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() || "";
        for (const part of parts) {
          const line = part.replace(/^data: /, "").trim();
          if (!line) continue;
          if (line === "done|DONE") {
            setConnected(false);
            return;
          }
          setLogs((prev) => [...prev, line]);
          indexRef.current += 1;
        }
      }
      setConnected(false);
    }).catch(() => setConnected(false));
  }, [jobId]);

  // Polling du statut du job
  useEffect(() => {
    connect();
    const token = localStorage.getItem("token");
    const poll = async () => {
      try {
        const r = await fetch(`${API_URL}/import/sync/jobs/${jobId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (r.ok) {
          const d = await r.json();
          setJobInfo(d);
          if (d.status === "running" && !connected) connect();
        }
      } catch {}
    };
    const timer = setInterval(poll, 2500);
    poll();
    return () => {
      clearInterval(timer);
      if (abortRef.current) abortRef.current.abort();
    };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const isDone = jobInfo?.status !== "running";
  const isCancelling = cancelling || jobInfo?.cancelling;

  const handleStop = async () => {
    if (!jobInfo?.job_id || isCancelling) return;
    setCancelling(true);
    try {
      await cancelJob(jobInfo.job_id);
    } catch {
      toast.error("Impossible d'annuler la synchronisation");
      setCancelling(false);
    }
  };

  return (
    <div className="border border-gray-800 rounded-lg bg-gray-950 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-900 border-b border-gray-700">
        <div className="flex items-center gap-3">
          {!isDone && !isCancelling && (
            <span className="flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-yellow-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span>
            </span>
          )}
          {isCancelling && !isDone && (
            <span className="flex h-2 w-2">
              <span className="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span>
            </span>
          )}
          <p className="text-xs font-semibold text-gray-300">
            {jobInfo?.label || "Synchronisation"}
            {jobInfo && (
              <span className="ml-2 text-gray-500 font-normal">
                {jobInfo.done_count}/{jobInfo.total} sources
                {jobInfo.error_count > 0 && (
                  <span className="text-red-400 ml-1">· {jobInfo.error_count} erreur(s)</span>
                )}
              </span>
            )}
          </p>
          {isDone && jobInfo?.status === "cancelled" && (
            <span className="flex items-center gap-1 text-xs text-orange-400"><FiStopCircle className="w-3.5 h-3.5" /> Annulée</span>
          )}
          {isDone && jobInfo?.status === "done" && jobInfo?.error_count === 0 && (
            <span className="flex items-center gap-1 text-xs text-green-400"><FiCheckCircle className="w-3.5 h-3.5" /> Terminé</span>
          )}
          {isDone && jobInfo?.status === "done" && jobInfo?.error_count > 0 && (
            <span className="flex items-center gap-1 text-xs text-yellow-400"><FiAlertTriangle className="w-3.5 h-3.5" /> Terminé avec erreurs</span>
          )}
          {isCancelling && !isDone && (
            <span className="text-xs text-orange-400 animate-pulse">Arrêt en cours...</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {/* Bouton Stop — visible uniquement quand le job tourne */}
          {!isDone && (
            <button
              onClick={handleStop}
              disabled={isCancelling}
              title="Arrêter la synchronisation"
              className="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded bg-red-900/40 text-red-400 hover:bg-red-900/70 hover:text-red-300 disabled:opacity-40 transition-colors border border-red-800/50"
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                <rect x="5" y="5" width="14" height="14" rx="1" />
              </svg>
              {isCancelling ? "Arrêt..." : "Stop"}
            </button>
          )}
          {isDone && (
            <span className="text-xs text-gray-500">
              {jobInfo?.finished_at
                ? new Date(jobInfo.finished_at).toLocaleTimeString("fr-FR")
                : ""}
            </span>
          )}
          {onClose && (
            <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      </div>
      <div ref={logsRef} className="max-h-56 overflow-y-auto p-3 space-y-px">
        {logs.length === 0 ? (
          <p className="text-xs text-gray-600">En attente des logs...</p>
        ) : (
          logs.map((line, i) => <LogLine key={i} line={line} />)
        )}
      </div>
    </div>
  );
}

// ─── SyncTab ──────────────────────────────────────────────────────────────────

function SyncTab() {
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  // jobPanels : { all, apt, rpm, apk, [source_id] } → job_id | null
  const [jobPanels, setJobPanels] = useState({});
  const { startSync, cancelJob, jobs, activeCount } = useSyncJobs();

  const loadStatus = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getImportSyncStatus();
      setSources(data.sources || []);
    } catch {
      toast.error("Impossible de charger le statut de synchronisation");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadStatus(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Rafraîchir le statut quand un job se termine
  useEffect(() => {
    const hadActive = jobs.some(j => j.status === "running");
    if (!hadActive && activeCount === 0) loadStatus();
  }, [activeCount]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSync = async (target) => {
    try {
      const data = await startSync(target);
      setJobPanels(prev => ({ ...prev, [target]: data.job_id }));
      // Pour les syncs de source individuelle, mettre à jour aussi la clé source
      if (target !== "all" && target !== "apt" && target !== "rpm" && target !== "apk") {
        setJobPanels(prev => ({ ...prev, [target]: data.job_id }));
      }
    } catch {
      toast.error("Impossible de démarrer la synchronisation");
    }
  };

  const closePanel = (target) => {
    setJobPanels(prev => { const n = { ...prev }; delete n[target]; return n; });
    loadStatus();
  };

  const totalPackages = sources.reduce((acc, s) => acc + (s.pkg_count || 0), 0);
  const aptSources = sources.filter((s) => s.format === "apt" || (!s.format && !s.repomd_url && !s.apkindex_url));
  const rpmSources = sources.filter((s) => s.format === "rpm");
  const apkSources = sources.filter((s) => s.format === "apk");

  const formatLabel = [
    aptSources.length > 0 && "APT",
    rpmSources.length > 0 && "RPM",
    apkSources.length > 0 && "APK",
  ].filter(Boolean).join(" + ") || "—";

  const globalRunning = jobs.some(j => j.status === "running");

  const statusBadge = (s) => {
    if (s.status === "ok") return <Badge color="green">OK</Badge>;
    if (s.status === "error") return <Badge color="red">Erreur</Badge>;
    return <Badge color="gray">—</Badge>;
  };

  const SyncIcon = ({ spinning = false, size = "w-3.5 h-3.5" }) => (
    <svg className={`${size} ${spinning ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
        d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  );

  const GroupSection = ({ srcs, target, label, icon: Icon, headerClass }) => {
    if (srcs.length === 0) return null;
    const ok = srcs.filter((s) => s.status === "ok").length;
    const pkgs = srcs.reduce((a, s) => a + (s.pkg_count || 0), 0);
    const runningJob = jobs.find(
      j => j.status === "running" &&
        (j.label?.toLowerCase().includes(target === "apk" ? "alpine" : target) ||
         j.label?.toLowerCase().includes(target))
    );
    const groupRunning = !!runningJob;
    const panelJobId = jobPanels[target];

    return (
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        {/* Header avec boutons sync + stop */}
        <div className={`px-4 py-2.5 border-b border-gray-200 flex items-center justify-between ${headerClass}`}>
          <div>
            <span className="inline-flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider">
              {Icon && <Icon className="w-3.5 h-3.5" />}
              {label}
            </span>
            <span className="ml-3 text-xs opacity-70">
              {ok}/{srcs.length} synchro. · {pkgs.toLocaleString()} paquets
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            {groupRunning && runningJob && (
              <button
                onClick={() => cancelJob(runningJob.job_id).catch(() => {})}
                title="Arrêter cette synchronisation"
                className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-white/60 hover:bg-red-50 border border-red-300 text-red-600 transition-colors"
              >
                <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                  <rect x="5" y="5" width="14" height="14" rx="1" />
                </svg>
                Stop
              </button>
            )}
            <button
              onClick={() => handleSync(target)}
              disabled={groupRunning}
              title={`Synchroniser toutes les sources ${label}`}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-medium bg-white/60 hover:bg-white border border-current/20 disabled:opacity-50 transition-colors"
            >
              <SyncIcon spinning={groupRunning} />
              {groupRunning ? "En cours..." : "Synchroniser"}
            </button>
          </div>
        </div>

        {/* Logs du job en cours */}
        {panelJobId && (
          <div className="border-b border-gray-200">
            <SyncJobPanel jobId={panelJobId} onClose={() => closePanel(target)} />
          </div>
        )}

        {/* Tableau des sources */}
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Source</th>
              <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Paquets</th>
              <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Dernière sync</th>
              <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Statut</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {srcs.map((s, i) => {
              const srcRunning = jobs.some(
                j => j.status === "running" &&
                  (j.label?.includes(s.source_id) || j.label?.includes(s.label))
              );
              const srcPanel = jobPanels[s.source_id];
              return (
                <>
                  <tr key={i} className={`hover:bg-gray-50 ${s.security ? "bg-red-50/20" : ""}`}>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        {s.security && (
                          <svg className="w-3 h-3 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <rect x="3" y="11" width="18" height="11" rx="2"/>
                            <path d="M7 11V7a5 5 0 0110 0v4"/>
                          </svg>
                        )}
                        <div>
                          <p className="text-sm font-medium text-gray-900">{s.label}</p>
                          <p className="text-xs text-gray-400">{s.source_id}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-sm text-gray-700">{(s.pkg_count || 0).toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-xs text-gray-500">
                      {s.last_sync ? new Date(s.last_sync).toLocaleString("fr-FR") : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1 flex-wrap">
                        {statusBadge(s)}
                        {s.security && <Badge color="red">Sécu.</Badge>}
                      </div>
                      {s.error && (
                        <p className="text-xs text-red-500 mt-0.5 max-w-xs truncate" title={s.error}>{s.error}</p>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => {
                          handleSync(s.source_id);
                          setJobPanels(prev => ({...prev, [s.source_id]: "__pending__"}));
                        }}
                        disabled={srcRunning}
                        title="Synchroniser cette source"
                        className="p-1 rounded text-gray-400 hover:text-blue-600 hover:bg-blue-50 disabled:opacity-30 transition-colors"
                      >
                        <SyncIcon spinning={srcRunning} />
                      </button>
                    </td>
                  </tr>
                  {srcPanel && srcPanel !== "__pending__" && (
                    <tr key={`${i}-panel`}>
                      <td colSpan={5} className="px-0 py-0">
                        <SyncJobPanel jobId={srcPanel} onClose={() => closePanel(s.source_id)} />
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div className="space-y-5 p-6">
      {/* Résumé global */}
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Sources</p>
          <p className="text-xl font-bold text-gray-900 mt-0.5">{sources.length}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Paquets indexés</p>
          <p className="text-xl font-bold text-gray-900 mt-0.5">{totalPackages.toLocaleString()}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Statut global</p>
          <p className="text-xl font-bold mt-0.5">
            {(() => {
              const synced = sources.filter((s) => s.status && s.status !== "never");
              if (synced.length === 0) return <span className="text-gray-400">—</span>;
              if (synced.every((s) => s.status === "ok")) return <span className="text-green-600">OK</span>;
              if (synced.some((s) => s.status === "ok")) return <span className="text-yellow-600">Partiel</span>;
              return <span className="text-red-600">Erreur</span>;
            })()}
          </p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Jobs actifs</p>
          <p className="text-xl font-bold mt-0.5 text-blue-600">{activeCount}</p>
        </div>
      </div>

      {/* Bouton sync globale + format label */}
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-gray-700">Sources ({formatLabel})</p>
        <div className="flex items-center gap-2">
          {/* Bouton Stop global — visible si des jobs tournent */}
          {globalRunning && (
            <button
              onClick={() => {
                const runningJobs = jobs.filter(j => j.status === "running");
                runningJobs.forEach(j => cancelJob(j.job_id).catch(() => {}));
              }}
              className="flex items-center gap-1.5 px-3 py-2 bg-red-50 border border-red-200 text-red-600 text-sm font-medium rounded-lg hover:bg-red-100 transition-colors"
              title="Arrêter toutes les synchronisations en cours"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <rect x="5" y="5" width="14" height="14" rx="1" />
              </svg>
              Tout arrêter
            </button>
          )}
          <button
            onClick={() => handleSync("all")}
            disabled={globalRunning}
            className="flex items-center gap-2 px-3.5 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
          >
            <SyncIcon spinning={globalRunning} size="w-4 h-4" />
            {globalRunning ? "En cours..." : "Tout synchroniser"}
          </button>
        </div>
      </div>

      {/* Panel global si lancé */}
      {jobPanels["all"] && (
        <SyncJobPanel jobId={jobPanels["all"]} onClose={() => closePanel("all")} />
      )}

      {loading ? (
        <div className="text-center text-gray-400 text-sm py-10">Chargement...</div>
      ) : (
        <div className="space-y-4">
          <GroupSection srcs={aptSources} target="apt" label="APT — Debian / Ubuntu" icon={FiPackage}
            headerClass="bg-blue-50 text-blue-800" />
          <GroupSection srcs={rpmSources} target="rpm" label="RPM — RHEL / Fedora / SUSE" icon={FiPackage}
            headerClass="bg-orange-50 text-orange-800" />
          <GroupSection srcs={apkSources} target="apk" label="APK — Alpine Linux" icon={SiAlpinelinux}
            headerClass="bg-emerald-50 text-emerald-800" />
        </div>
      )}
    </div>
  );
}

// ─── Tab: Mirroir planifié sécurisé ───────────────────────────────────────────

function MirrorJobPanel({ jobId, onClose, onDone }) {
  const [logs, setLogs] = useState([]);
  const [jobInfo, setJobInfo] = useState(null);
  const [connected, setConnected] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const logsRef = useRef(null);
  const indexRef = useRef(0);
  const abortRef = useRef(null);
  const doneNotifiedRef = useRef(false);

  const connect = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const token = localStorage.getItem("token");
    const fromIdx = indexRef.current;
    fetch(`${API_URL}/import/mirror/jobs/${jobId}/stream?from_index=${fromIdx}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: ctrl.signal,
    }).then(async (resp) => {
      if (!resp.ok) return;
      setConnected(true);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() || "";
        for (const part of parts) {
          const line = part.replace(/^data: /, "").trim();
          if (!line) continue;
          if (line === "done|DONE") {
            setConnected(false);
            return;
          }
          setLogs((prev) => [...prev, line]);
          indexRef.current += 1;
        }
      }
      setConnected(false);
    }).catch(() => setConnected(false));
  }, [jobId]);

  // Polling du statut du job
  useEffect(() => {
    connect();
    const token = localStorage.getItem("token");
    const poll = async () => {
      try {
        const r = await fetch(`${API_URL}/import/mirror/jobs/${jobId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (r.ok) {
          const d = await r.json();
          setJobInfo(d);
          if (d.status === "running" && !connected) connect();
          if (d.status !== "running" && !doneNotifiedRef.current) {
            doneNotifiedRef.current = true;
            onDone && onDone();
          }
        }
      } catch {}
    };
    const timer = setInterval(poll, 2500);
    poll();
    return () => {
      clearInterval(timer);
      if (abortRef.current) abortRef.current.abort();
    };
  }, [jobId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const isDone = jobInfo?.status !== "running";
  const isCancelling = cancelling || jobInfo?.cancelling;

  const handleStop = async () => {
    if (!jobInfo?.job_id || isCancelling) return;
    setCancelling(true);
    try {
      await cancelMirrorJob(jobInfo.job_id);
    } catch {
      toast.error("Impossible d'annuler le mirroir");
      setCancelling(false);
    }
  };

  return (
    <div className="border border-gray-800 rounded-lg bg-gray-950 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-900 border-b border-gray-700">
        <div className="flex items-center gap-3">
          {!isDone && !isCancelling && (
            <span className="flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-yellow-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500"></span>
            </span>
          )}
          {isCancelling && !isDone && (
            <span className="flex h-2 w-2">
              <span className="relative inline-flex rounded-full h-2 w-2 bg-orange-500"></span>
            </span>
          )}
          <p className="text-xs font-semibold text-gray-300">
            {jobInfo?.label || "Mirroir"}
            {jobInfo && (
              <span className="ml-2 text-gray-500 font-normal">
                {jobInfo.done_count}/{jobInfo.total} paquets
                {jobInfo.added_count > 0 && (
                  <span className="text-green-400 ml-1">· {jobInfo.added_count} ajouté(s)</span>
                )}
                {jobInfo.pending_count > 0 && (
                  <span className="text-yellow-400 ml-1">· {jobInfo.pending_count} en revue</span>
                )}
                {jobInfo.blocked_count > 0 && (
                  <span className="text-red-400 ml-1">· {jobInfo.blocked_count} bloqué(s)</span>
                )}
                {jobInfo.error_count > 0 && (
                  <span className="text-red-400 ml-1">· {jobInfo.error_count} erreur(s)</span>
                )}
              </span>
            )}
          </p>
          {isDone && jobInfo?.status === "cancelled" && (
            <span className="flex items-center gap-1 text-xs text-orange-400"><FiStopCircle className="w-3.5 h-3.5" /> Annulé</span>
          )}
          {isDone && jobInfo?.status === "done" && jobInfo?.error_count === 0 && jobInfo?.blocked_count === 0 && (
            <span className="flex items-center gap-1 text-xs text-green-400"><FiCheckCircle className="w-3.5 h-3.5" /> Terminé</span>
          )}
          {isDone && jobInfo?.status === "done" && (jobInfo?.error_count > 0 || jobInfo?.blocked_count > 0) && (
            <span className="flex items-center gap-1 text-xs text-yellow-400"><FiAlertTriangle className="w-3.5 h-3.5" /> Terminé avec alertes</span>
          )}
          {isDone && jobInfo?.status === "error" && (
            <span className="flex items-center gap-1 text-xs text-red-400"><FiXCircle className="w-3.5 h-3.5" /> Erreur</span>
          )}
          {isCancelling && !isDone && (
            <span className="text-xs text-orange-400 animate-pulse">Arrêt en cours...</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!isDone && (
            <button
              onClick={handleStop}
              disabled={isCancelling}
              title="Arrêter le mirroir"
              className="flex items-center gap-1 px-2 py-1 text-xs font-medium rounded bg-red-900/40 text-red-400 hover:bg-red-900/70 hover:text-red-300 disabled:opacity-40 transition-colors border border-red-800/50"
            >
              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24">
                <rect x="5" y="5" width="14" height="14" rx="1" />
              </svg>
              {isCancelling ? "Arrêt..." : "Stop"}
            </button>
          )}
          {isDone && jobInfo?.finished_at && (
            <span className="text-xs text-gray-500">
              {new Date(jobInfo.finished_at).toLocaleTimeString("fr-FR")}
            </span>
          )}
          {onClose && (
            <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>
      </div>
      <div ref={logsRef} className="max-h-56 overflow-y-auto p-3 space-y-px">
        {logs.length === 0 ? (
          <p className="text-xs text-gray-600">En attente des logs...</p>
        ) : (
          logs.map((line, i) => <LogLine key={i} line={line} />)
        )}
      </div>
    </div>
  );
}

function MirrorTab() {
  const { isAdmin, isMaintainer } = useAuth();
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(true);
  const [schedule, setSchedule] = useState(null);
  const [scheduleForm, setScheduleForm] = useState(null);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [jobPanels, setJobPanels] = useState({});
  const [jobs, setJobs] = useState([]);
  const [togglingId, setTogglingId] = useState(null);

  const loadSources = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getMirrorSources();
      setSources(data.sources || []);
    } catch {
      toast.error("Impossible de charger les sources du mirroir");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSchedule = useCallback(async () => {
    try {
      const data = await getMirrorSchedule();
      setSchedule(data);
      setScheduleForm(data);
    } catch {
      toast.error("Impossible de charger la planification du mirroir");
    }
  }, []);

  const loadJobs = useCallback(async () => {
    try {
      const data = await getMirrorJobs();
      setJobs(data.jobs || []);
    } catch {}
  }, []);

  useEffect(() => {
    loadSources();
    loadSchedule();
    loadJobs();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleToggle = async (sourceId, enabled) => {
    setSources((prev) => prev.map((s) => (s.id === sourceId ? { ...s, enabled } : s)));
    setTogglingId(sourceId);
    try {
      await updateMirrorSources({ [sourceId]: enabled });
      toast.success(enabled ? "Source activée" : "Source désactivée", { duration: 1500 });
    } catch {
      setSources((prev) => prev.map((s) => (s.id === sourceId ? { ...s, enabled: !enabled } : s)));
      toast.error("Impossible de mettre à jour la source");
    } finally {
      setTogglingId(null);
    }
  };

  const handleStart = async (sourceId) => {
    try {
      const data = await startMirrorJob(sourceId);
      setJobPanels((prev) => ({ ...prev, [sourceId]: data.job_id }));
      if (data.already_running) {
        toast("Un mirroir est déjà en cours — affichage du job actif.", { icon: "ℹ️" });
      }
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Impossible de démarrer le mirroir");
    }
  };

  const closePanel = (sourceId) => {
    setJobPanels((prev) => { const n = { ...prev }; delete n[sourceId]; return n; });
    loadSources();
    loadJobs();
  };

  const handleScheduleSave = async () => {
    if (!scheduleForm) return;
    setSavingSchedule(true);
    try {
      const updated = await updateMirrorSchedule({
        enabled: scheduleForm.enabled,
        hour: Number(scheduleForm.hour),
        minute: Number(scheduleForm.minute),
        timezone: scheduleForm.timezone,
        max_packages_per_run: Number(scheduleForm.max_packages_per_run),
        max_runtime_minutes: Number(scheduleForm.max_runtime_minutes),
        min_free_disk_gb: Number(scheduleForm.min_free_disk_gb),
      });
      setSchedule(updated);
      setScheduleForm(updated);
      // reschedule_warning : les paramètres sont bien enregistrés côté serveur,
      // mais la replanification à chaud du job APScheduler a échoué — sans ce
      // toast, l'utilisateur croirait le nouvel horaire actif immédiatement.
      if (updated.reschedule_warning) {
        toast(updated.reschedule_warning, { icon: "⚠️", duration: 8000 });
      } else {
        toast.success("Planification du mirroir mise à jour");
      }
    } catch {
      toast.error("Impossible de mettre à jour la planification");
    } finally {
      setSavingSchedule(false);
    }
  };

  const formatBadge = (fmt) => {
    if (fmt === "rpm") return <Badge color="orange">RPM</Badge>;
    if (fmt === "apk") return <Badge color="blue">APK</Badge>;
    return <Badge color="blue">DEB</Badge>;
  };

  const enabledCount = sources.filter((s) => s.enabled).length;

  return (
    <div className="space-y-5 p-6">
      {/* Description */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-800">
        <p className="font-semibold mb-1">Mirroir planifié sécurisé</p>
        <p>
          Activez une source pour que repod télécharge périodiquement{" "}
          <strong>tous les paquets indexés</strong> de cette source, les fasse passer
          par le pipeline complet (ClamAV + Grype + GPG + dépendances), puis les ajoute
          au dépôt interne (reprepro / createrepo_c / APK). Le mirroir est{" "}
          <strong>désactivé par défaut</strong> (impact disque/bande passante) — c&apos;est
          un opt-in par source.
        </p>
      </div>

      {/* Résumé */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Sources mirroirables</p>
          <p className="text-xl font-bold text-gray-900 mt-0.5">{sources.length}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Sources activées</p>
          <p className="text-xl font-bold mt-0.5 text-blue-600">{enabledCount}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-3">
          <p className="text-xs text-gray-400 uppercase tracking-wider">Planification</p>
          <p className="text-xl font-bold mt-0.5">
            {schedule?.enabled
              ? <span className="text-green-600">{String(schedule.hour).padStart(2, "0")}:{String(schedule.minute).padStart(2, "0")} {schedule.timezone}</span>
              : <span className="text-gray-400">Désactivée</span>}
          </p>
        </div>
      </div>

      {/* Planification (admin uniquement) */}
      {isAdmin && scheduleForm && (
        <div className="bg-white border border-gray-200 rounded-lg p-4 space-y-3">
          <p className="text-sm font-semibold text-gray-700">Planification & limites de sécurité</p>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <label className="flex items-center gap-2 text-sm text-gray-700 col-span-2">
              <input
                type="checkbox"
                checked={!!scheduleForm.enabled}
                onChange={(e) => setScheduleForm((p) => ({ ...p, enabled: e.target.checked }))}
              />
              Mirroir planifié actif
            </label>
            <label className="text-xs text-gray-500">
              Heure
              <input
                type="number" min="0" max="23"
                value={scheduleForm.hour}
                onChange={(e) => setScheduleForm((p) => ({ ...p, hour: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
            <label className="text-xs text-gray-500">
              Minute
              <input
                type="number" min="0" max="59"
                value={scheduleForm.minute}
                onChange={(e) => setScheduleForm((p) => ({ ...p, minute: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
            <label className="text-xs text-gray-500">
              Fuseau horaire
              <input
                type="text"
                value={scheduleForm.timezone}
                onChange={(e) => setScheduleForm((p) => ({ ...p, timezone: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
            <label className="text-xs text-gray-500">
              Max paquets / run
              <input
                type="number" min="1"
                value={scheduleForm.max_packages_per_run}
                onChange={(e) => setScheduleForm((p) => ({ ...p, max_packages_per_run: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
            <label className="text-xs text-gray-500">
              Durée max (min)
              <input
                type="number" min="1"
                value={scheduleForm.max_runtime_minutes}
                onChange={(e) => setScheduleForm((p) => ({ ...p, max_runtime_minutes: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
            <label className="text-xs text-gray-500">
              Espace disque min (Go)
              <input
                type="number" min="1"
                value={scheduleForm.min_free_disk_gb}
                onChange={(e) => setScheduleForm((p) => ({ ...p, min_free_disk_gb: e.target.value }))}
                className="mt-0.5 w-full border border-gray-300 rounded px-2 py-1 text-sm"
              />
            </label>
          </div>
          <div className="flex justify-end">
            <button
              onClick={handleScheduleSave}
              disabled={savingSchedule}
              className="px-3.5 py-1.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {savingSchedule ? "Enregistrement..." : "Enregistrer"}
            </button>
          </div>
        </div>
      )}

      {/* Tableau des sources */}
      {loading ? (
        <div className="text-center text-gray-400 text-sm py-10">Chargement...</div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Format</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Dernier job</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Activé</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sources.map((s) => {
                const lastJob = s.last_job;
                const panel = jobPanels[s.id];
                const running = panel || (lastJob && lastJob.status === "running");
                return (
                  <Fragment key={s.id}>
                    <tr className="hover:bg-gray-50">
                      <td className="px-4 py-2.5">
                        <p className="text-sm font-medium text-gray-900">{s.label}</p>
                        <p className="text-xs text-gray-400">{s.id}</p>
                      </td>
                      <td className="px-4 py-2.5">{formatBadge(s.format)}</td>
                      <td className="px-4 py-2.5 text-xs text-gray-500">
                        {lastJob ? (
                          <>
                            {lastJob.added_count} ajouté(s), {lastJob.pending_count} en revue,{" "}
                            {lastJob.blocked_count} bloqué(s), {lastJob.error_count} erreur(s)
                            <br />
                            <span className="text-gray-400">
                              {lastJob.finished_at
                                ? new Date(lastJob.finished_at).toLocaleString("fr-FR")
                                : "en cours..."}
                            </span>
                          </>
                        ) : "—"}
                      </td>
                      <td className="px-4 py-2.5">
                        <label className="inline-flex items-center cursor-pointer">
                          <input
                            type="checkbox"
                            checked={!!s.enabled}
                            disabled={!isMaintainer || togglingId === s.id}
                            onChange={(e) => handleToggle(s.id, e.target.checked)}
                            className="sr-only peer"
                          />
                          <div className="relative w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600 peer-disabled:opacity-50"></div>
                        </label>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {isMaintainer && (
                          <button
                            onClick={() => handleStart(s.id)}
                            disabled={!!running}
                            title="Lancer le mirroir maintenant"
                            className="px-2.5 py-1 rounded text-xs font-medium bg-blue-50 text-blue-600 hover:bg-blue-100 disabled:opacity-40 transition-colors border border-blue-200"
                          >
                            {running ? "En cours..." : "Lancer maintenant"}
                          </button>
                        )}
                      </td>
                    </tr>
                    {panel && (
                      <tr>
                        <td colSpan={5} className="px-0 py-0">
                          <MirrorJobPanel jobId={panel} onClose={() => closePanel(s.id)} onDone={loadJobs} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {sources.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-sm text-gray-400">
                    Aucune source mirroirable disponible.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Historique des jobs */}
      {jobs.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <div className="px-4 py-2.5 border-b border-gray-200">
            <p className="text-xs font-bold uppercase tracking-wider text-gray-500">Historique des jobs (1h)</p>
          </div>
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Statut</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Résultat</th>
                <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Terminé</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {jobs.map((j) => (
                <tr key={j.job_id} className="hover:bg-gray-50">
                  <td className="px-4 py-2.5 text-sm text-gray-900">{j.label}</td>
                  <td className="px-4 py-2.5">
                    {j.status === "running" && <Badge color="yellow">En cours</Badge>}
                    {j.status === "done" && <Badge color="green">Terminé</Badge>}
                    {j.status === "cancelled" && <Badge color="gray">Annulé</Badge>}
                    {j.status === "error" && <Badge color="red">Erreur</Badge>}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-500">
                    {j.added_count} ajouté(s), {j.pending_count} en revue,{" "}
                    {j.blocked_count} bloqué(s), {j.error_count} erreur(s) sur {j.total}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-gray-500">
                    {j.finished_at ? new Date(j.finished_at).toLocaleString("fr-FR") : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

const TABS = [
  { id: "sync", label: "Synchronisation", icon: "M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" },
  { id: "mirror", label: "Mirroir", icon: "M5 12h14M5 12a2 2 0 01-2-2V7a2 2 0 012-2h14a2 2 0 012 2v3a2 2 0 01-2 2M5 12a2 2 0 00-2 2v3a2 2 0 002 2h14a2 2 0 002-2v-3a2 2 0 00-2-2m-2-4h.01M7 16h.01" },
];

export default function SourcesPage() {
  const [activeTab, setActiveTab] = useState("sync");

  return (
    <div className="space-y-6 p-6">
      {/* En-tête */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Sources</h1>
        <p className="text-sm text-gray-500 mt-1">
          Gérez la synchronisation des index de paquets et le mirroir planifié sécurisé de vos sources externes.
        </p>
      </div>

      {/* Onglets */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Contenu des onglets */}
      <div>
        {activeTab === "sync" && <SyncTab />}
        {activeTab === "mirror" && <MirrorTab />}
      </div>
    </div>
  );
}
