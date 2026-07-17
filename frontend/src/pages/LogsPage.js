/**
 * LogsPage — Console de logs unifiée de la stack repod.
 *
 * Sources :
 *  • backend   — logs Python applicatifs (ring buffer SSE)
 *  • apt-repo  — logs nginx (access, downloads, error) via tail SSE
 *
 * Fonctionnalités :
 *  • Flux temps réel via SSE (bouton Play/Pause)
 *  • Filtre service (backend, apt-repo, all)
 *  • Filtre niveau (ALL / DEBUG / INFO / WARNING / ERROR)
 *  • Recherche texte en direct
 *  • Auto-scroll vers le bas
 *  • Effacer l'écran
 *  • Télécharger les logs affichés (.txt)
 *  • Compteur de lignes
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { getLogs } from "../api";

// ── Constantes ────────────────────────────────────────────────────────────────
const MAX_DISPLAY = 2000;          // lignes max dans la vue
const API_BASE = import.meta.env.REACT_APP_API_URL || "";
const STREAM_URL = (service, level) => {
  const params = new URLSearchParams();
  if (service && service !== "all") params.set("service", service);
  if (level   && level   !== "ALL")  params.set("level",   level);
  return `${API_BASE}/api/v1/logs/stream?${params}`;
};

const LEVELS = ["ALL", "DEBUG", "INFO", "WARNING", "ERROR"];
const SERVICES = [
  { id: "all",      label: "Tous les services" },
  { id: "backend",  label: "Backend (API)"     },
  { id: "apt-repo", label: "APT-Repo (nginx)"  },
];

// ── Couleurs par niveau ───────────────────────────────────────────────────────
const LEVEL_COLOR = {
  DEBUG:   "text-slate-400",
  INFO:    "text-emerald-400",
  WARNING: "text-amber-400",
  ERROR:   "text-red-400",
};
const LEVEL_BG = {
  DEBUG:   "bg-slate-700/40",
  INFO:    "bg-emerald-900/20",
  WARNING: "bg-amber-900/25",
  ERROR:   "bg-red-900/30",
};
const LEVEL_BADGE = {
  DEBUG:   "bg-slate-700 text-slate-300",
  INFO:    "bg-emerald-800/70 text-emerald-300",
  WARNING: "bg-amber-800/70 text-amber-300",
  ERROR:   "bg-red-800/70 text-red-400",
};

// ── Formatage timestamp ───────────────────────────────────────────────────────
// Retourne { date, time } pour affichage en deux lignes compactes
function fmtTs(ts) {
  if (!ts) return { date: "—", time: "--:--:--.---" };
  const d = new Date(ts * 1000);
  const DD = String(d.getDate()).padStart(2, "0");
  const MM = String(d.getMonth() + 1).padStart(2, "0");
  const YYYY = d.getFullYear();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return {
    date: `${DD}/${MM}/${YYYY}`,
    time: `${hh}:${mm}:${ss}.${ms}`,
  };
}

// ── Icônes SVG ────────────────────────────────────────────────────────────────
const PlayIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <polygon points="5 3 19 12 5 21 5 3"/>
  </svg>
);
const PauseIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <rect x="6" y="4" width="4" height="16"/>
    <rect x="14" y="4" width="4" height="16"/>
  </svg>
);
const TrashIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/>
    <path d="M10 11v6"/><path d="M14 11v6"/>
    <path d="M9 6V4h6v2"/>
  </svg>
);
const DownloadIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
    <polyline points="7 10 12 15 17 10"/>
    <line x1="12" y1="15" x2="12" y2="3"/>
  </svg>
);
const ArrowDownIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <line x1="12" y1="5" x2="12" y2="19"/>
    <polyline points="19 12 12 19 5 12"/>
  </svg>
);
const SearchIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
    strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
    <circle cx="11" cy="11" r="8"/>
    <line x1="21" y1="21" x2="16.65" y2="16.65"/>
  </svg>
);
const TerminalIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7}
    strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
    <polyline points="4 17 10 11 4 5"/>
    <line x1="12" y1="19" x2="20" y2="19"/>
  </svg>
);

// ── Composant principal ───────────────────────────────────────────────────────
export default function LogsPage() {
  const [entries, setEntries]       = useState([]);   // toutes les entrées chargées
  const [service, setService]       = useState("all");
  const [level, setLevel]           = useState("ALL");
  const [search, setSearch]         = useState("");
  const [streaming, setStreaming]   = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [loading, setLoading]       = useState(false);
  const [sseStatus, setSseStatus]   = useState("idle"); // idle | connected | error | polling

  const bottomRef  = useRef(null);
  const abortRef   = useRef(null);   // AbortController pour fetch SSE

  // ── Chargement initial (historique) ────────────────────────────────────────
  const loadHistory = useCallback(async () => {
    setLoading(true);
    try {
      const params = { lines: 500 };
      if (service !== "all") params.service = service;
      if (level   !== "ALL") params.level   = level;
      const data = await getLogs(params);
      const sorted = (data.entries || []).sort((a, b) => (a.ts || 0) - (b.ts || 0));
      setEntries(sorted);
    } catch {
      // silencieux
    } finally {
      setLoading(false);
    }
  }, [service, level]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  // ── Streaming SSE via fetch + ReadableStream ───────────────────────────────
  // (EventSource ne supporte pas les headers Authorization)
  const startStream = useCallback(() => {
    if (abortRef.current) abortRef.current.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const url   = STREAM_URL(service !== "all" ? service : null, level !== "ALL" ? level : null);
    const token = localStorage.getItem("token") || "";

    setSseStatus("connected");

    fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      signal: ctrl.signal,
    }).then(async (resp) => {
      if (!resp.ok) { setSseStatus("error"); return; }
      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop();
        for (const part of parts) {
          const dataLine = part.split("\n").find(l => l.startsWith("data:"));
          if (!dataLine) continue;
          const payload = dataLine.slice(5).trim();
          try {
            const entry = JSON.parse(payload);
            setEntries(prev => {
              const next = [...prev, entry];
              return next.length > MAX_DISPLAY ? next.slice(-MAX_DISPLAY) : next;
            });
          } catch { /* malformed */ }
        }
      }
      setSseStatus("idle");
    }).catch(e => {
      if (e.name !== "AbortError") setSseStatus("error");
    });
  }, [service, level]);

  const stopStream = useCallback(() => {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null; }
    setSseStatus("idle");
  }, []);

  useEffect(() => {
    if (streaming) {
      startStream();
    } else {
      stopStream();
    }
    return () => stopStream();
  }, [streaming, startStream, stopStream]);

  // ── Auto-scroll ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [entries, autoScroll]);

  // ── Filtrage local ─────────────────────────────────────────────────────────
  const filtered = entries.filter(e => {
    if (search) {
      const q = search.toLowerCase();
      if (!e.message?.toLowerCase().includes(q) && !e.name?.toLowerCase().includes(q)) {
        return false;
      }
    }
    return true;
  });

  // ── Actions ────────────────────────────────────────────────────────────────
  const handleClear = () => setEntries([]);

  const handleDownload = () => {
    const text = filtered.map(e =>
      `[${fmtTs(e.ts)}] [${e.level?.padEnd(7)}] [${(e.service || "").padEnd(8)}] ${e.name || ""}: ${e.message || ""}`
    ).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `repod-logs-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Status SSE badge ───────────────────────────────────────────────────────
  const StatusDot = () => {
    if (!streaming) return null;
    if (sseStatus === "connected") return (
      <span className="flex items-center gap-1.5 text-xs text-emerald-400">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"/>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400"/>
        </span>
        Live
      </span>
    );
    if (sseStatus === "polling") return (
      <span className="flex items-center gap-1.5 text-xs text-amber-400">
        <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse"/>
        Polling
      </span>
    );
    return (
      <span className="flex items-center gap-1.5 text-xs text-red-400">
        <span className="w-2 h-2 rounded-full bg-red-400"/>
        Erreur SSE
      </span>
    );
  };

  // ── Rendu ──────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col flex-1 min-h-0 bg-slate-950 text-slate-100 overflow-hidden">

      {/* ── Topbar ── */}
      <div className="shrink-0 flex items-center gap-3 px-4 py-2.5 bg-slate-900 border-b border-slate-800">

        {/* Titre */}
        <div className="flex items-center gap-2 text-slate-300 mr-2 shrink-0">
          <span className="text-violet-400"><TerminalIcon /></span>
          <span className="text-sm font-semibold">Console des logs</span>
        </div>

        {/* Séparateur */}
        <div className="w-px h-5 bg-slate-700 shrink-0" />

        {/* Filtre service */}
        <select
          value={service}
          onChange={e => { setService(e.target.value); if (streaming) setStreaming(false); }}
          className="text-xs bg-slate-800 border border-slate-700 text-slate-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-violet-500"
        >
          {SERVICES.map(s => (
            <option key={s.id} value={s.id}>{s.label}</option>
          ))}
        </select>

        {/* Filtre niveau */}
        <div className="flex items-center gap-1">
          {LEVELS.map(l => (
            <button
              key={l}
              onClick={() => setLevel(l)}
              className={`text-[11px] px-2.5 py-1 rounded-md font-semibold transition-all ${
                level === l
                  ? l === "ALL"
                    ? "bg-slate-600 text-white"
                    : `${LEVEL_BADGE[l]} ring-1 ring-white/20`
                  : "text-slate-500 hover:text-slate-300 hover:bg-slate-800"
              }`}
            >
              {l}
            </button>
          ))}
        </div>

        {/* Séparateur */}
        <div className="w-px h-5 bg-slate-700 shrink-0" />

        {/* Recherche */}
        <div className="relative flex-1 min-w-0 max-w-xs">
          <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500">
            <SearchIcon />
          </span>
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filtrer les messages…"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-violet-500"
          />
          {search && (
            <button onClick={() => setSearch("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs">
              ✕
            </button>
          )}
        </div>

        {/* Spacer */}
        <div className="flex-1" />

        {/* Status dot */}
        <StatusDot />

        {/* Compteur */}
        <span className="text-xs text-slate-500 font-mono shrink-0">
          {filtered.length.toLocaleString()} ligne{filtered.length !== 1 ? "s" : ""}
        </span>

        {/* Séparateur */}
        <div className="w-px h-5 bg-slate-700 shrink-0" />

        {/* Bouton Play/Pause */}
        <button
          onClick={() => setStreaming(s => !s)}
          className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg transition-all ${
            streaming
              ? "bg-violet-600 hover:bg-violet-700 text-white"
              : "bg-slate-700 hover:bg-slate-600 text-slate-200"
          }`}
        >
          {streaming ? <PauseIcon /> : <PlayIcon />}
          {streaming ? "Pause" : "Live"}
        </button>

        {/* Auto-scroll */}
        <button
          onClick={() => setAutoScroll(v => !v)}
          title={autoScroll ? "Désactiver l'auto-scroll" : "Activer l'auto-scroll"}
          className={`p-1.5 rounded-lg transition-colors ${
            autoScroll ? "text-violet-400 bg-violet-900/30" : "text-slate-500 hover:text-slate-300 hover:bg-slate-800"
          }`}
        >
          <ArrowDownIcon />
        </button>

        {/* Télécharger */}
        <button
          onClick={handleDownload}
          title="Télécharger les logs affichés"
          className="p-1.5 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors"
        >
          <DownloadIcon />
        </button>

        {/* Effacer */}
        <button
          onClick={handleClear}
          title="Effacer l'écran"
          className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-900/20 transition-colors"
        >
          <TrashIcon />
        </button>
      </div>

      {/* ── Zone de logs ── */}
      <div
        className="flex-1 overflow-y-auto font-mono text-xs leading-relaxed"
        style={{ background: "#0a0e1a" }}
      >
        {loading && entries.length === 0 && (
          <div className="flex items-center justify-center h-32 text-slate-500 gap-2">
            <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
            </svg>
            Chargement de l'historique…
          </div>
        )}

        {!loading && filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 text-slate-600 gap-2">
            <TerminalIcon />
            <p className="text-xs">Aucun log{search ? " correspondant à la recherche" : ""}</p>
            {!streaming && (
              <button onClick={() => setStreaming(true)}
                className="mt-2 text-xs text-violet-400 hover:text-violet-300 flex items-center gap-1">
                <PlayIcon /> Démarrer le flux live
              </button>
            )}
          </div>
        )}

        <table className="w-full border-collapse">
          <tbody>
            {filtered.map((e, i) => {
              const lvl = e.level || "INFO";
              return (
                <tr
                  key={i}
                  className={`border-b border-slate-800/40 hover:bg-slate-800/30 transition-colors ${LEVEL_BG[lvl] || ""}`}
                >
                  {/* Timestamp — date + heure sur deux lignes */}
                  <td className="pl-3 pr-2 py-[3px] text-slate-500 whitespace-nowrap select-all align-top w-36">
                    {(() => {
                      const { date, time } = fmtTs(e.ts);
                      return (
                        <span className="flex flex-col leading-tight">
                          <span className="text-slate-600 text-[10px]">{date}</span>
                          <span>{time}</span>
                        </span>
                      );
                    })()}
                  </td>

                  {/* Niveau */}
                  <td className="px-2 py-[3px] whitespace-nowrap align-top w-16">
                    <span className={`text-[10px] font-bold ${LEVEL_COLOR[lvl] || "text-slate-300"}`}>
                      {lvl}
                    </span>
                  </td>

                  {/* Service */}
                  <td className="px-2 py-[3px] whitespace-nowrap align-top w-28">
                    <span className="text-slate-500 text-[10px]">{e.service || "?"}</span>
                  </td>

                  {/* Logger name */}
                  <td className="px-2 py-[3px] whitespace-nowrap align-top max-w-[180px] w-36">
                    <span className="text-violet-500/70 text-[10px] truncate block" title={e.name}>
                      {e.name || ""}
                    </span>
                  </td>

                  {/* Message */}
                  <td className="px-2 pr-4 py-[3px] text-slate-300 align-top break-all">
                    <HighlightedMsg message={e.message || ""} query={search} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        <div ref={bottomRef} />
      </div>
    </div>
  );
}

// ── Surlignage de la recherche ────────────────────────────────────────────────
function HighlightedMsg({ message, query }) {
  if (!query) return <span>{message}</span>;
  const idx = message.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return <span>{message}</span>;
  return (
    <span>
      {message.slice(0, idx)}
      <mark className="bg-amber-500/40 text-amber-200 rounded px-0.5">
        {message.slice(idx, idx + query.length)}
      </mark>
      {message.slice(idx + query.length)}
    </span>
  );
}
