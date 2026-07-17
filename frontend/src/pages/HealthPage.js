import { useState, useEffect, useCallback, useRef } from "react";
import {
  getHealth, getBaseUrl,
  getGrypeStatus, getFeedsStatus, getClamavStatus,
  getGrypeUpdateUrl, getFeedsRefreshUrl, getClamavUpdateUrl,
} from "../api";
import { useAuth } from "../context/AuthContext";

function StatusBadge({ status }) {
  const cfg = {
    healthy:  { bg: "bg-green-100",  text: "text-green-800",  dot: "bg-green-500",  label: "Opérationnel" },
    degraded: { bg: "bg-orange-100", text: "text-orange-800", dot: "bg-orange-500", label: "Dégradé"       },
    error:    { bg: "bg-red-100",    text: "text-red-800",    dot: "bg-red-500",    label: "Erreur"        },
    unknown:  { bg: "bg-gray-100",   text: "text-gray-600",   dot: "bg-gray-400",   label: "Inconnu"       },
  }[status] ?? { bg: "bg-gray-100", text: "text-gray-600", dot: "bg-gray-400", label: status };

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold ${cfg.bg} ${cfg.text}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot} ${status === "healthy" ? "animate-pulse" : ""}`} />
      {cfg.label}
    </span>
  );
}

function CheckCard({ title, icon, check, children }) {
  const ok = check?.ok !== false;
  return (
    <div className={`bg-white rounded-xl border ${ok ? "border-gray-200" : "border-red-200"} p-4 space-y-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 text-gray-500 shrink-0">{icon}</span>
          <span className="text-sm font-semibold text-gray-800">{title}</span>
        </div>
        <StatusBadge status={check?.ok ? "healthy" : check === null ? "unknown" : "error"} />
      </div>
      {children}
    </div>
  );
}

function MetaRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between items-center text-xs">
      <span className="text-gray-500">{label}</span>
      <span className={`font-medium text-gray-700 ${mono ? "font-mono" : ""}`}>{value ?? "—"}</span>
    </div>
  );
}

function DiskBar({ usedPct }) {
  if (usedPct == null) return null;
  const color = usedPct > 90 ? "bg-red-500" : usedPct > 75 ? "bg-orange-400" : "bg-green-500";
  return (
    <div className="mt-2">
      <div className="flex justify-between text-xs text-gray-500 mb-1">
        <span>Utilisation disque</span>
        <span className={usedPct > 90 ? "text-red-600 font-semibold" : ""}>{usedPct}%</span>
      </div>
      <div className="w-full bg-gray-100 rounded-full h-2">
        <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${usedPct}%` }} />
      </div>
    </div>
  );
}

// ─── Indicateur de service 2D (ping Tailwind) ────────────────────────────────
function ServiceDot({ online, size = 28 }) {
  const bg = online
    ? "radial-gradient(circle at 38% 35%, #86efac, #16a34a 70%)"
    : "radial-gradient(circle at 38% 35%, #fca5a5, #dc2626 70%)";
  const pingColor = online ? "bg-green-400" : "bg-red-400";
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <div className="w-full h-full rounded-full" style={{ background: bg }} />
      {online && (
        <div className={`absolute inset-0 rounded-full opacity-50 animate-ping ${pingColor}`} />
      )}
    </div>
  );
}

// ─── Arc gauge compact ────────────────────────────────────────────────────────
function ArcGauge({ pct, small = false }) {
  const R  = small ? 54 : 72;
  const sw = small ? 10 : 13;
  const W  = (R + sw + 6) * 2;
  const cx = W / 2;
  const cy = R + sw + 3;
  const H  = cy + 3;

  const circ    = Math.PI * R;
  const clamped = Math.max(0, Math.min(100, pct ?? 0));
  const dash    = (clamped / 100) * circ;
  const color   = clamped >= 90 ? "#ef4444" : clamped >= 75 ? "#f97316" : "#22c55e";
  const arcD    = `M ${cx - R},${cy} A ${R},${R} 0 0,1 ${cx + R},${cy}`;

  const zone = (from, to, fill) => {
    const len = ((to - from) / 100) * circ;
    return (
      <path d={arcD} fill="none" stroke={fill} strokeWidth={sw} strokeLinecap="butt"
        strokeDasharray={`${len} ${circ - len + 1}`}
        strokeDashoffset={-((from / 100) * circ)} />
    );
  };
  const tick = (p) => {
    const a = Math.PI * (1 - p / 100);
    return {
      x1: cx + (R - sw) * Math.cos(a), y1: cy - (R - sw) * Math.sin(a),
      x2: cx + (R + 4)  * Math.cos(a), y2: cy - (R + 4)  * Math.sin(a),
    };
  };

  return (
    <div className="w-full">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="auto">
        {zone(0, 75, "#bbf7d0")} {zone(75, 90, "#fed7aa")} {zone(90, 100, "#fecaca")}
        <path d={arcD} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round"
          strokeDasharray={`${dash} ${circ + sw}`} />
        <line {...tick(75)} stroke="white" strokeWidth="2" strokeLinecap="round" />
        <line {...tick(90)} stroke="white" strokeWidth="2" strokeLinecap="round" />
      </svg>
      <div className="text-center" style={{ marginTop: small ? "-14px" : "-18px" }}>
        <p className={`font-bold leading-none`}
           style={{ fontSize: small ? 22 : 28, color }}>{clamped}%</p>
        <p className="text-xs text-gray-400 mt-0.5">utilisé</p>
      </div>
      <div className="flex justify-between text-xs text-gray-300 px-1 mt-1.5 select-none">
        <span>0%</span>
        <span className="text-green-500">75%</span>
        <span className="text-orange-400">90%</span>
        <span>100%</span>
      </div>
    </div>
  );
}

// ─── Card : Stockage ─────────────────────────────────────────────────────────
function StorageCard({ storage }) {
  const ok  = storage?.ok !== false;
  const pct = storage?.used_pct ?? 0;
  const accent = pct >= 90 ? "border-red-200 bg-red-50/30" : pct >= 75 ? "border-orange-200 bg-orange-50/20" : "border-gray-200";

  const dirs = storage?.dirs ?? {};
  const rows = [
    { key: "grype_db",  label: "Grype DB (CVE)", color: "#6366f1" },
    { key: "pool",      label: "Pool paquets",    color: "#0891b2" },
    { key: "clamav_db", label: "ClamAV DB",       color: "#059669" },
    { key: "manifests", label: "Manifests",        color: "#d97706" },
    { key: "audit",     label: "Audit logs",       color: "#94a3b8" },
  ].map(r => ({ ...r, mb: dirs[r.key]?.size_mb ?? null })).filter(r => r.mb !== null);

  const total = rows.reduce((s, r) => s + r.mb, 0);

  return (
    <div className={`bg-white rounded-xl border ${accent} p-4 flex flex-col gap-3 h-full`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-gray-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 12H2"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/>
            <line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>
          </svg>
          <span className="text-sm font-semibold text-gray-700">Stockage <span className="font-mono text-gray-400 text-xs">/repos</span></span>
        </div>
        <StatusBadge status={!ok ? "error" : pct >= 90 ? "error" : pct >= 75 ? "degraded" : "healthy"} />
      </div>

      {/* Gauge compacte */}
      <ArcGauge pct={pct} />

      {/* Libre / Total */}
      <div className="grid grid-cols-2 gap-2 -mt-1">
        {[
          ["Libre", storage?.free_gb != null ? `${storage.free_gb} Go` : "—", pct >= 90 ? "text-red-600" : pct >= 75 ? "text-orange-500" : "text-green-600"],
          ["Total", storage?.total_gb != null ? `${storage.total_gb} Go` : "—", "text-gray-700"],
        ].map(([lbl, val, cls]) => (
          <div key={lbl} className="bg-gray-50 rounded-lg px-3 py-2 text-center">
            <p className="text-xs text-gray-400">{lbl}</p>
            <p className={`text-sm font-bold ${cls}`}>{val}</p>
          </div>
        ))}
      </div>

      {/* Barres par répertoire */}
      <div className="space-y-2 border-t border-gray-100 pt-2 flex-1">
        {rows.map(r => {
          const barPct = total > 0 ? Math.max(2, Math.round((r.mb / total) * 100)) : 0;
          const lbl = r.mb >= 1024 ? `${(r.mb / 1024).toFixed(1)} Go` : `${Math.round(r.mb)} Mo`;
          return (
            <div key={r.key}>
              <div className="flex justify-between text-xs mb-0.5">
                <span className="text-gray-600 font-medium">{r.label}</span>
                <span className="font-mono font-semibold text-gray-500">{lbl}</span>
              </div>
              <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all"
                  style={{ width: `${barPct}%`, background: `linear-gradient(90deg, ${r.color}cc, ${r.color})` }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Card : Services (ClamAV + Reprepro + GPG) ───────────────────────────────
function ServicesCard({ clamav, reprepro, gpg }) {
  const allOk = [clamav, reprepro, gpg].every(s => s?.ok !== false);

  // Parse "1.4.3/28026/Tue" → { version: "1.4.3 / base 28026", day: "Tue" }
  const rawVer = clamav?.version ?? "";
  const vParts = rawVer.split("/");
  const clamVersionLabel = vParts.length >= 2 ? `${vParts[0]} / base ${vParts[1]}` : rawVer;
  const clamDay          = vParts.length >= 3 ? vParts[2] : "";

  const reproproVer = reprepro?.version
    ?.replace("reprepro: This is reprepro version ", "")
    ?.split(" ")[0] ?? "—";

  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-5 flex flex-col gap-3 h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center shrink-0">
            <GridIcon className="w-4 h-4 text-gray-500" />
          </div>
          <span className="text-xs font-bold tracking-widest text-gray-500 uppercase">Services système</span>
        </div>
        <SquareBadge ok={allOk} labelKo="Dégradé" />
      </div>

      {/* ── ClamAV ── */}
      <div className={`rounded-xl p-3.5 flex items-center gap-3.5
        ${clamav?.ok ? "bg-green-50" : "bg-red-50"}`}>
        <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0
          ${clamav?.ok ? "bg-green-600" : "bg-red-500"}`}>
          <GridIcon className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold text-gray-800">ClamAV</p>
          <p className="text-xs font-mono text-gray-500 truncate leading-snug mt-0.5">{clamVersionLabel || "—"}</p>
        </div>
        <div className="text-right shrink-0 leading-snug">
          <p className={`text-xs font-bold ${clamav?.ok ? "text-green-600" : "text-red-500"}`}>
            {clamav?.ok ? "Opérationnel" : "Hors ligne"}
          </p>
          {clamDay && <p className="text-xs text-gray-400">{clamDay}</p>}
        </div>
      </div>

      {/* ── reprepro ── */}
      <div className="rounded-xl border border-gray-100 p-3.5 flex items-center gap-3.5">
        <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0
          ${reprepro?.ok ? "bg-teal-100" : "bg-red-100"}`}>
          <GridIcon className={`w-5 h-5 ${reprepro?.ok ? "text-teal-700" : "text-red-500"}`} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold text-gray-800">reprepro</p>
          <p className="text-xs text-gray-400 leading-snug mt-0.5">Dépôt Debian</p>
        </div>
        <span className="font-mono text-sm font-semibold text-gray-500 shrink-0">{reproproVer}</span>
      </div>

      {/* ── GPG signing ── */}
      <div className="rounded-xl border border-gray-100 p-3.5 flex items-center gap-3.5">
        <div className={`w-11 h-11 rounded-xl flex items-center justify-center shrink-0
          ${gpg?.ok ? "bg-violet-100" : "bg-red-100"}`}>
          <GridIcon className={`w-5 h-5 ${gpg?.ok ? "text-violet-600" : "text-red-500"}`} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold text-gray-800">GPG signing</p>
          <p className="text-xs text-gray-400 leading-snug mt-0.5">Signature des paquets</p>
        </div>
        <span className="font-mono text-sm font-semibold text-gray-500 shrink-0">
          {gpg?.fingerprint ? `···${gpg.fingerprint.slice(-8)}` : "—"}
        </span>
      </div>
    </div>
  );
}

// ─── Card : Scheduler ────────────────────────────────────────────────────────
function SchedulerCard({ scheduler }) {
  const jobs = scheduler?.jobs ?? [];
  const ok   = scheduler?.ok !== false;

  return (
    <div className={`bg-white rounded-xl border ${ok ? "border-gray-200" : "border-red-200"} p-4 space-y-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <svg className="w-4 h-4 text-gray-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
          </svg>
          <span className="text-sm font-semibold text-gray-700">Tâches planifiées</span>
        </div>
        <StatusBadge status={ok ? "healthy" : "error"} />
      </div>

      {jobs.length === 0
        ? <p className="text-xs text-gray-400">Aucune tâche configurée.</p>
        : (
          <div className="divide-y divide-gray-50">
            {jobs.map(job => {
              const next = job.next_run ? new Date(job.next_run) : null;
              const soon = next && (next - Date.now()) < 3_600_000;
              const nextStr = job.paused ? null
                : next ? next.toLocaleString("fr-FR", {
                    day: "2-digit", month: "2-digit", year: "numeric",
                    hour: "2-digit", minute: "2-digit",
                  }) : "—";
              return (
                <div key={job.id}
                  className={`flex items-center justify-between py-2.5 px-1 text-xs gap-3
                    ${soon && !job.paused ? "bg-blue-50 rounded-lg px-2" : ""}`}>
                  <div className="flex items-center gap-2.5 min-w-0 flex-1">
                    <span className={`w-2 h-2 rounded-full shrink-0
                      ${job.paused ? "bg-orange-400" : soon ? "bg-blue-500 animate-pulse" : "bg-green-400"}`} />
                    <div className="min-w-0">
                      <p className="font-semibold text-gray-700 truncate">{job.name}</p>
                      <p className="text-gray-400 font-mono text-xs">{job.id}</p>
                    </div>
                  </div>
                  <span className={`shrink-0 font-mono text-right
                    ${job.paused ? "text-orange-500 font-bold" : soon ? "text-blue-600 font-bold" : "text-gray-400"}`}>
                    {job.paused ? "En pause" : nextStr}
                  </span>
                </div>
              );
            })}
          </div>
        )
      }
    </div>
  );
}

// Badge carré (style mockup)
function SquareBadge({ ok, labelOk = "Opérationnel", labelKo = "Erreur" }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold
      ${ok ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}`}>
      <span className={`w-2 h-2 rounded-sm shrink-0 ${ok ? "bg-green-500" : "bg-red-500"}`} />
      {ok ? labelOk : labelKo}
    </span>
  );
}

// Icône grille (tile icon)
function GridIcon({ className = "" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
    </svg>
  );
}

function PackagesGaugeCard({ check }) {
  const ok = check?.ok !== false;
  const byFormat = check?.by_format ?? {};
  const total    = check?.pool_files ?? 0;

  const formats = [
    { key: "deb", label: ".deb", color: "#6366f1" },
    { key: "rpm", label: ".rpm", color: "#0d9488" },
    { key: "apk", label: ".apk", color: "#b45309" },
  ];

  const BAR_MAX_H = 88; // px — hauteur barre la plus grande
  const maxCount  = Math.max(...formats.map(f => byFormat[f.key] ?? 0), 1);

  return (
    <div className={`bg-white rounded-2xl border ${ok ? "border-gray-200" : "border-red-200"} p-5 flex flex-col gap-4 h-full`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center shrink-0">
            <GridIcon className="w-4 h-4 text-gray-500" />
          </div>
          <span className="text-xs font-bold tracking-widest text-gray-500 uppercase">Paquets</span>
        </div>
        <SquareBadge ok={ok} />
      </div>

      {/* Total */}
      <div className="flex items-baseline gap-2">
        <span className="text-5xl font-bold text-gray-900 leading-none">{total}</span>
        <span className="text-sm text-gray-400">paquets au total</span>
      </div>

      {/* Barres verticales */}
      <div className="flex items-end gap-4 flex-1" style={{ minHeight: BAR_MAX_H + 28 }}>
        {formats.map(f => {
          const count = byFormat[f.key] ?? 0;
          const barH  = count > 0 ? Math.max(Math.round((count / maxCount) * BAR_MAX_H), 5) : 0;
          return (
            <div key={f.key} className="flex-1 flex flex-col items-center gap-1">
              <span className="text-sm font-bold text-gray-700">{count}</span>
              <div className="w-full rounded-t-xl transition-all"
                style={{ height: barH, backgroundColor: f.color, minWidth: 24 }} />
            </div>
          );
        })}
      </div>

      {/* Labels formats */}
      <div className="flex gap-4 -mt-2">
        {formats.map(f => (
          <div key={f.key} className="flex-1 text-center">
            <span className="text-xs font-mono font-semibold" style={{ color: f.color }}>{f.label}</span>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="border-t border-gray-100 pt-4 grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs font-bold tracking-widest text-gray-400 uppercase mb-1">Manifests</p>
          <p className="text-xl font-bold text-gray-800">{check?.total_manifests ?? "—"}</p>
        </div>
        <div>
          <p className="text-xs font-bold tracking-widest text-gray-400 uppercase mb-1">Taille Pool</p>
          <p className="text-xl font-bold text-gray-800">
            {check?.pool_size_mb != null ? `${check.pool_size_mb} Mo` : "—"}
          </p>
        </div>
      </div>
    </div>
  );
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch { return iso; }
}

const BASE_URL = getBaseUrl();

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handle = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handle}
      className="ml-auto px-3 py-1.5 text-xs font-medium rounded-lg border border-gray-200
                 hover:bg-gray-100 text-gray-600 transition-colors flex items-center gap-1.5"
    >
      {copied ? (
        <>
          <svg className="w-3 h-3 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
          Copié !
        </>
      ) : (
        <>
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
          Copier
        </>
      )}
    </button>
  );
}

// ─── Composant : Bases de sécurité ───────────────────────────────────────────

function AgeChip({ ageHours, stale, fresh }) {
  if (ageHours == null) return <span className="text-xs text-gray-400">—</span>;
  const color = stale || !fresh
    ? "bg-red-100 text-red-700"
    : ageHours < 12
      ? "bg-green-100 text-green-700"
      : "bg-orange-100 text-orange-700";
  const label = ageHours < 1
    ? `${Math.round(ageHours * 60)} min`
    : ageHours < 24
      ? `${ageHours.toFixed(1)} h`
      : `${(ageHours / 24).toFixed(1)} j`;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${color}`}>
      {stale || !fresh ? "périmé · " : ""}{label}
    </span>
  );
}

function SseLogPanel({ logs, running, done, onClose }) {
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [logs]);
  if (!running && logs.length === 0) return null;
  return (
    <div className="relative mt-3 bg-gray-900 rounded-lg p-3 pr-8 max-h-48 overflow-y-auto text-xs font-mono space-y-0.5">
      {onClose && (
        <button
          onClick={onClose}
          title="Fermer"
          className="absolute top-2 right-2 text-gray-500 hover:text-gray-200 transition-colors"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
      {logs.map((line, i) => {
        const [lvl, ...rest] = line.split("|");
        const msg = rest.join("|");
        const color =
          lvl === "error"   ? "text-red-400"    :
          lvl === "success" ? "text-green-400"   :
          lvl === "warning" ? "text-yellow-400"  : "text-gray-300";
        return <p key={i} className={color}>{msg || line}</p>;
      })}
      {running && (
        <p className="text-blue-400 flex items-center gap-1">
          <svg className="animate-spin w-3 h-3" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
          </svg>
          En cours…
        </p>
      )}
      {done && <p className="text-green-500 font-semibold">Terminé.</p>}
      <div ref={endRef} />
    </div>
  );
}

const AUTO_HIDE_DELAY_MS = 10_000;

function SecurityDbCard({ title, icon, available, ageHours, stale, fresh, extra, onUpdate, onDone, isAdmin }) {
  const [logs, setLogs]       = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone]       = useState(false);
  const [hidden, setHidden]   = useState(false);
  const autoHideRef = useRef(null);

  useEffect(() => () => clearTimeout(autoHideRef.current), []);

  const handleUpdate = () => {
    if (!onUpdate || running) return;
    clearTimeout(autoHideRef.current);
    setLogs([]);
    setDone(false);
    setHidden(false);
    setRunning(true);
    const token = localStorage.getItem("token");
    fetch(onUpdate, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({}),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur serveur" }));
        setLogs([`error|${err.detail || "Erreur serveur"}`]);
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let hadError = false;
      while (true) {
        const { value, done: sd } = await reader.read();
        if (sd) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop();
        for (const part of parts) {
          const dataLine = part.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          const payload = dataLine.slice(5).trim();
          if (payload.startsWith("done|")) {
            setDone(true);
            setRunning(false);
            onDone?.();
            if (!hadError) {
              autoHideRef.current = setTimeout(() => setHidden(true), AUTO_HIDE_DELAY_MS);
            }
          } else {
            if (payload.startsWith("error|")) hadError = true;
            setLogs((p) => [...p, payload]);
          }
        }
      }
      setRunning(false);
    }).catch((e) => {
      setLogs([`error|${e.message}`]);
      setRunning(false);
    });
  };

  const statusColor = !available
    ? "border-gray-200"
    : (stale || !fresh)
      ? "border-orange-300"
      : "border-green-200";

  return (
    <div className={`bg-white rounded-xl border ${statusColor} p-4 space-y-3`}>
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 text-indigo-500 shrink-0">{icon}</span>
          <span className="text-sm font-semibold text-gray-800">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          {available !== false && (
            <AgeChip ageHours={ageHours} stale={stale} fresh={fresh} />
          )}
          {!available && (
            <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded">Non disponible</span>
          )}
        </div>
      </div>

      {/* Méta */}
      {extra && (
        <div className="space-y-1">
          {extra.map(([label, val]) => (
            <div key={label} className="flex justify-between items-center text-xs">
              <span className="text-gray-500">{label}</span>
              <span className="font-medium text-gray-700 font-mono">{val ?? "—"}</span>
            </div>
          ))}
        </div>
      )}

      {/* Bouton mise à jour */}
      {isAdmin && onUpdate && (
        <button
          onClick={handleUpdate}
          disabled={running}
          className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold
                     bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 transition-colors"
        >
          {running ? (
            <>
              <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
              </svg>
              Mise à jour en cours…
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round"
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Mettre à jour
            </>
          )}
        </button>
      )}

      {!hidden && (
        <SseLogPanel
          logs={logs}
          running={running}
          done={done}
          onClose={() => { clearTimeout(autoHideRef.current); setHidden(true); }}
        />
      )}
    </div>
  );
}

function SecurityDatabasesSection({ isAdmin }) {
  const [grype, setGrype]   = useState(null);
  const [feeds, setFeeds]   = useState(null);
  const [clamav, setClamav] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [g, f, c] = await Promise.allSettled([
        getGrypeStatus(),
        getFeedsStatus(),
        getClamavStatus(),
      ]);
      if (g.status === "fulfilled") setGrype(g.value);
      if (f.status === "fulfilled") setFeeds(f.value);
      if (c.status === "fulfilled") setClamav(c.value);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const clamavAgeHours = (() => {
    if (!clamav?.db_date) return null;
    try {
      const dt = new Date(clamav.db_date);
      const diff = Date.now() - dt.getTime();
      return Math.round(diff / 3600000 * 10) / 10;
    } catch { return null; }
  })();

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
          Bases de sécurité
        </h2>
        <button
          onClick={loadAll}
          disabled={loading}
          className="p-1.5 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-400
                     disabled:opacity-50 transition-colors"
          title="Rafraîchir"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">

        {/* ClamAV */}
        <SecurityDbCard
          title="ClamAV"
          icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>}
          available={!!clamav?.available}
          ageHours={clamavAgeHours}
          stale={clamavAgeHours != null && clamavAgeHours > 48}
          fresh={clamavAgeHours != null && clamavAgeHours <= 48}
          extra={[
            ["Version DB", clamav?.db_version],
            ["Date DB", clamav?.db_date ? new Date(clamav.db_date).toLocaleDateString("fr-FR") : null],
            ["Engine", clamav?.version],
          ]}
          onUpdate={getClamavUpdateUrl()}
          onDone={loadAll}
          isAdmin={isAdmin}
        />

        {/* Grype */}
        <SecurityDbCard
          title="Grype (CVE)"
          icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>}
          available={grype?.available ?? false}
          ageHours={grype?.age_hours}
          stale={grype?.stale}
          fresh={!grype?.stale && grype?.available}
          extra={[
            ["Schéma", grype?.schema],
            ["Construite le", grype?.built_at ? new Date(grype.built_at).toLocaleDateString("fr-FR") : null],
            ["Statut", grype?.status],
          ]}
          onUpdate={getGrypeUpdateUrl()}
          onDone={loadAll}
          isAdmin={isAdmin}
        />

        {/* KEV */}
        <SecurityDbCard
          title="KEV (CISA)"
          icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}
          available={feeds?.kev?.available ?? false}
          ageHours={feeds?.kev?.age_hours}
          stale={!feeds?.kev?.fresh}
          fresh={feeds?.kev?.fresh}
          extra={[
            ["Entrées", feeds?.kev?.total],
            ["Version catalogue", feeds?.kev?.catalog_version || null],
            ["Mis à jour", feeds?.kev?.fetched_at ? new Date(feeds.kev.fetched_at).toLocaleDateString("fr-FR") : null],
            ["TTL", feeds?.kev?.ttl_hours != null ? `${feeds.kev.ttl_hours} h` : null],
          ]}
          onUpdate={getFeedsRefreshUrl()}
          onDone={loadAll}
          isAdmin={isAdmin}
        />

        {/* EPSS */}
        <SecurityDbCard
          title="EPSS (FIRST.org)"
          icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>}
          available={feeds?.epss?.available ?? false}
          ageHours={feeds?.epss?.age_hours}
          stale={!feeds?.epss?.fresh}
          fresh={feeds?.epss?.fresh}
          extra={[
            ["Scores chargés", feeds?.epss?.count],
            ["Mis à jour", feeds?.epss?.updated_at ? new Date(feeds.epss.updated_at).toLocaleDateString("fr-FR") : null],
            ["TTL", feeds?.epss?.ttl_hours != null ? `${feeds.epss.ttl_hours} h` : null],
          ]}
          onUpdate={getFeedsRefreshUrl()}
          onDone={loadAll}
          isAdmin={isAdmin}
        />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

export default function HealthPage() {
  const { isAdmin } = useAuth();
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");
  const [lastRefresh, setLastRefresh] = useState(null);

  const load = useCallback(async () => {
    try {
      const d = await getHealth();
      setData(d);
      setError("");
      setLastRefresh(new Date());
    } catch (e) {
      setError("Impossible de charger le statut de santé.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30_000); // refresh toutes les 30s
    return () => clearInterval(interval);
  }, [load]);

  // Le backend retourne checks.critical.* et checks.non_critical.* — on aplatit
  const checks = {
    ...(data?.checks?.critical    ?? {}),
    ...(data?.checks?.non_critical ?? {}),
    ...(data?.checks?.info         ?? {}),
  };

  return (
    <div className="p-6 space-y-6">

      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Supervision système</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            État des composants · refresh auto 30s
            {lastRefresh && (
              <span className="ml-2 text-gray-400">
                · mis à jour {lastRefresh.toLocaleTimeString("fr-FR")}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && <StatusBadge status={data.status} />}
          <button
            onClick={load}
            disabled={loading}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 text-gray-500
                       disabled:opacity-50 transition-colors"
            title="Rafraîchir"
          >
            <svg className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-700">{error}</div>
      )}

      {/* ─── Section Prometheus ─────────────────────────────── */}
      {(() => {
        const origin      = BASE_URL || window.location.origin;
        const metricsUrl  = `${origin}/metrics`;
        const scheme      = origin.startsWith("https") ? "https" : "http";
        const scrapeYaml  = `- job_name: 'repod'\n  scrape_interval: 30s\n  scheme: ${scheme}\n  bearer_token: '<METRICS_TOKEN>'  # voir METRICS_TOKEN dans backend.env\n  static_configs:\n    - targets: ['<HOST>:<PORT>']  # adresse de ce serveur repod\n  metrics_path: /metrics`;
        return (
          <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4">
            <div className="flex items-center gap-2">
              <svg className="w-5 h-5 text-orange-500 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2zm0 18a8 8 0 110-16 8 8 0 010 16zm-1-5h2v2h-2v-2zm0-8h2v6h-2V7z"/>
              </svg>
              <h2 className="text-sm font-semibold text-gray-800">Métriques Prometheus</h2>
            </div>
            <p className="text-xs text-gray-500">
              Endpoint <span className="font-mono">/metrics</span> disponible pour le scraping.
              Expose les compteurs HTTP, latences, paquets et vulnérabilités.
            </p>

            {/* Lien endpoint */}
            <div className="flex items-center gap-2 bg-gray-50 rounded-lg px-3 py-2">
              <span className="text-xs font-mono font-semibold text-green-700 bg-green-100 px-2 py-0.5 rounded">GET</span>
              <span className="text-xs font-mono text-gray-700 flex-1">{metricsUrl}</span>
              <a
                href={metricsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-600 hover:underline whitespace-nowrap"
              >
                Ouvrir ↗
              </a>
            </div>

            {/* Métriques exposées */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                ["repod_http_requests_total",            "Requêtes HTTP (method, path, status)"],
                ["repod_http_request_duration_seconds",  "Latence des requêtes (histogramme)"],
                ["repod_packages_total",                 "Paquets par distribution et arch"],
                ["repod_vulnerabilities_total",          "CVE par sévérité"],
                ["repod_uploads_total",                  "Uploads de paquets (succès/échec)"],
              ].map(([name, desc]) => (
                <div key={name} className="bg-gray-50 rounded-lg px-3 py-2">
                  <p className="font-mono text-gray-800 text-xs leading-tight">{name}</p>
                  <p className="text-gray-400 mt-0.5">{desc}</p>
                </div>
              ))}
            </div>

            {/* Config scrape */}
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <p className="text-xs font-medium text-gray-700">Configuration <span className="font-mono">prometheus.yml</span></p>
                <CopyButton text={scrapeYaml} />
              </div>
              <pre className="bg-gray-900 text-green-400 text-xs rounded-lg p-4 overflow-x-auto leading-relaxed">
{scrapeYaml}
              </pre>
            </div>
          </div>
        );
      })()}

      {loading && !data && (
        <div className="flex justify-center py-16">
          <svg className="animate-spin w-8 h-8 text-blue-500" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
          </svg>
        </div>
      )}

      {data && (
        <>
          {/* Infos API */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl px-5 py-3 flex flex-wrap gap-6 text-sm">
            <div>
              <span className="text-blue-500 font-medium">Version</span>
              <span className="ml-2 font-mono text-blue-800">{data.version || "dev"}</span>
            </div>
            <div>
              <span className="text-blue-500 font-medium">Timestamp</span>
              <span className="ml-2 text-blue-800">{fmtDate(data.timestamp)}</span>
            </div>
          </div>

          {/* ── 3 colonnes : Stockage | Paquets | Services ───────── */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-stretch">
            <StorageCard storage={checks.storage} />
            <PackagesGaugeCard check={checks.packages} />
            <ServicesCard
              clamav={checks.clamav}
              reprepro={checks.reprepro}
              gpg={checks.gpg}
            />
          </div>

          {/* ── Tâches planifiées ─────────────────────────────────── */}
          <SchedulerCard scheduler={checks.scheduler} />

          {/* Bases de sécurité */}
          <SecurityDatabasesSection isAdmin={isAdmin} />
        </>
      )}
    </div>
  );
}
