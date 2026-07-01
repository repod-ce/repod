import { useState, useEffect, useCallback } from "react";
import { getDashboardStats, getDashboardHistory, getEnrichedDashboard } from "../api";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import GridLayout, { WidthProvider } from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";

const ReactGridLayout = WidthProvider(GridLayout);
import {
  AreaChart, Area,
  LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  PieChart, Pie, Cell,
  ResponsiveContainer,
} from "recharts";
import Paginator from "../components/Paginator";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmtBytes = b => {
  if (!b) return "0 B";
  if (b < 1_048_576)   return `${(b / 1_024).toFixed(1)} KB`;
  if (b < 1_073_741_824) return `${(b / 1_048_576).toFixed(1)} MB`;
  return `${(b / 1_073_741_824).toFixed(2)} GB`;
};

const fmtNum = n => {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 10_000)    return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return n.toLocaleString("fr-FR");
};

const fmtTs = iso =>
  iso
    ? new Date(iso).toLocaleString("fr-FR", {
        day: "2-digit", month: "2-digit",
        hour: "2-digit", minute: "2-digit",
      })
    : "—";

const fmtDay = iso => {
  if (!iso) return "";
  const parts = iso.split("-");
  return `${parts[2]}/${parts[1]}`;
};

// ─── Semantic color palette ────────────────────────────────────────────────────
// Never change orange usage here — these are semantic status colors only
const C = {
  blue:   "#3B82F6",
  green:  "#22C55E",
  yellow: "#F59E0B",
  orange: "#F97316",   // sévérité HIGH CVE — ne jamais supprimer
  red:    "#EF4444",
  purple: "#8B5CF6",
  teal:   "#14B8A6",
  indigo: "#6366F1",
  muted:  "#94A3B8",
  border: "#E2E8F0",
  text:   "#0F172A",
  sub:    "#475569",
};

// CVE severity rows (orange kept for HIGH as semantic color)
const SEV = [
  { key: "critical",   label: "CRITICAL", color: C.red    },
  { key: "high",       label: "HIGH",     color: C.orange },
  { key: "medium",     label: "MEDIUM",   color: C.yellow },
  { key: "low",        label: "LOW",      color: C.green  },
  { key: "negligible", label: "NEG.",     color: C.muted  },
];

const STATUS_META = {
  pending_review:   { label: "En révision",   color: C.orange },
  blocked:          { label: "Bloqués",        color: C.red    },
  quarantined:      { label: "Quarantaine",    color: C.purple },
  accepted_risk:    { label: "Risque accepté", color: C.green  },
  exception:        { label: "Exception",      color: C.blue   },
  upgrade_required: { label: "Upgrade requis", color: C.teal   },
};

const ACTION_COLOR = {
  UPLOAD: C.blue, IMPORT: C.teal,
  PENDING_REVIEW: C.orange, SECURITY_DECISION: C.purple,
};

const ALERT_STYLE = {
  deps_missing: { bg: "#FDE68A", border: "#D97706", text: "#92400E" },
  sla_warning:  { bg: "#FDE68A", border: "#D97706", text: "#92400E" },
  sla_expired:  { bg: `${C.red}18`, border: C.red,  text: C.red    },
  security:     { bg: `${C.red}18`, border: C.red,  text: C.red    },
};

const PERIODS = [
  { label: "24 h", days: 1  },
  { label: "7 j",  days: 7  },
  { label: "30 j", days: 30 },
];

const PER_PAGE = 10;

// ─── Panel wrapper ─────────────────────────────────────────────────────────────
// ─── Grid layout ──────────────────────────────────────────────────────────────
const LS_KEY = "repod_dashboard_layout_v4";
const GRID_COLS = 15;
const GRID_ROW_H = 65;

const DEFAULT_LAYOUT = [
  // ── Ligne 1 : KPI cards — 5 × w:3 = 15 cols (pleine largeur, dimensions égales) ──
  { i: "kpi-paquets",    x: 0,  y: 0,  w: 3,  h: 3, minW: 2, minH: 2 },
  { i: "kpi-imports",    x: 3,  y: 0,  w: 3,  h: 3, minW: 2, minH: 2 },
  { i: "kpi-cves",       x: 6,  y: 0,  w: 3,  h: 3, minW: 2, minH: 2 },
  { i: "kpi-rssi",       x: 9,  y: 0,  w: 3,  h: 3, minW: 2, minH: 2 },
  { i: "kpi-alertes",    x: 12, y: 0,  w: 3,  h: 3, minW: 2, minH: 2 },
  // ── Ligne 2 : 3 vues de distribution — 3 × w:5 = 15, h:5 ───────────────────
  { i: "rssi-donut",     x: 0,  y: 3,  w: 5,  h: 5, minW: 3, minH: 3 },
  { i: "cve-dist",       x: 5,  y: 3,  w: 5,  h: 5, minW: 3, minH: 3 },
  { i: "clamav",         x: 10, y: 3,  w: 5,  h: 5, minW: 2, minH: 3 },
  // ── Ligne 3 : historique + SLA violations ───────────────────────────────────
  { i: "history",        x: 0,  y: 8,  w: 12, h: 5, minW: 4, minH: 3 },
  { i: "sla-violations", x: 12, y: 8,  w: 3,  h: 5, minW: 2, minH: 3 },
  // ── Ligne 4 : tendances CVE ──────────────────────────────────────────────────
  { i: "cve-trends",     x: 0,  y: 13, w: 15, h: 5, minW: 4, minH: 3 },
  // ── Ligne 5 : alertes système ────────────────────────────────────────────────
  { i: "alerts",         x: 0,  y: 18, w: 15, h: 6, minW: 6, minH: 3 },
  // ── Ligne 6 : activité récente ───────────────────────────────────────────────
  { i: "imports-table",  x: 0,  y: 24, w: 15, h: 9, minW: 6, minH: 4 },
];

function loadSavedLayout() {
  try {
    const s = localStorage.getItem(LS_KEY);
    if (s) return JSON.parse(s);
  } catch {}
  return DEFAULT_LAYOUT;
}

// Generic card container — h-full to fill its grid cell.
function Panel({ title, children, badge, icon, onAction, actionLabel, className = "" }) {
  return (
    <div className={`bg-white border border-slate-200 rounded-xl flex flex-col h-full shadow-[0_1px_3px_rgba(0,0,0,0.06)] overflow-hidden ${className}`}>
      {/* Header — drag handle */}
      <div className="drag-handle flex items-center justify-between px-4 py-2.5 border-b border-slate-100 flex-shrink-0 cursor-grab active:cursor-grabbing select-none">
        <div className="flex items-center gap-2 min-w-0">
          {icon && <span className="text-slate-400 flex-shrink-0 flex">{icon}</span>}
          <span className="text-[10px] font-bold tracking-[0.07em] uppercase text-slate-500 truncate">
            {title}
          </span>
          {badge != null && badge > 0 && (
            <span
              style={{ background: `${C.red}15`, color: C.red, border: `1px solid ${C.red}30` }}
              className="text-[10px] font-bold px-1.5 py-px rounded-full flex-shrink-0"
            >
              {badge}
            </span>
          )}
        </div>
        {onAction && (
          <button
            onClick={(e) => { e.stopPropagation(); onAction(); }}
            style={{ color: C.blue }}
            className="text-[11px] font-semibold flex-shrink-0 pl-3 hover:opacity-75 transition-opacity cursor-pointer"
          >
            {actionLabel || "Voir →"}
          </button>
        )}
      </div>
      {/* Body */}
      <div className="flex-1 min-h-0 overflow-hidden p-4">
        {children}
      </div>
    </div>
  );
}

// ─── KPI Card palettes — style GLPI : fond coloré vif, texte assombri ──────────
const KPI_PALETTES = {
  paquets: { bg: "#f5c5c5", color: "#7f1d1d" },  // rouge corail → Computers GLPI
  imports: { bg: "#b8e6b8", color: "#14532d" },  // vert moyen   → Software GLPI
  cves:    { bg: "#b8d4e8", color: "#1e3a5f" },  // bleu ciel    → Network GLPI
  rssi:    { bg: "#f5e6a3", color: "#713f12" },  // ambre doré   → Racks GLPI
  alertes: { bg: "#a8d5d0", color: "#134e4a" },  // teal         → Enclosures GLPI
};

// ─── KPI Card — style GLPI ────────────────────────────────────────────────────
function KpiCard({ label, value, sub, palette, onClick, icon }) {
  return (
    <div
      style={{ background: palette.bg }}
      className="h-full rounded-lg shadow-sm flex flex-col overflow-hidden"
    >
      {/* Drag handle sur le haut de la carte */}
      <div className="drag-handle h-6 flex-shrink-0 cursor-grab active:cursor-grabbing select-none" />
      <div
        onClick={onClick}
        className={`flex-1 px-5 pb-5 flex flex-col justify-between min-h-0
          ${onClick ? "cursor-pointer hover:brightness-95" : ""}
          transition-all duration-150`}
      >
      {/* Haut : valeur + icône */}
      <div className="flex items-start justify-between gap-2">
        <span
          style={{ color: palette.color }}
          className="text-[46px] font-light leading-none tabular-nums tracking-tight"
        >
          {value != null ? fmtNum(value) : "—"}
        </span>
        {icon && (
          <span style={{ color: palette.color }} className="opacity-40 mt-1 shrink-0">
            {icon}
          </span>
        )}
      </div>
      {/* Bas : sous-titre + label */}
      <div>
        {sub && (
          <p style={{ color: palette.color }} className="text-[11px] font-medium mb-1 opacity-60 leading-tight">
            {sub}
          </p>
        )}
        <p style={{ color: palette.color }} className="text-sm font-bold">
          {label}
        </p>
      </div>
      </div>
    </div>
  );
}

// ─── Area chart — Import history ───────────────────────────────────────────────
function HistoryChart({ data }) {
  if (!data?.length) return (
    <div className="flex items-center justify-center h-full text-xs text-slate-400">
      Pas encore de données historiques
    </div>
  );
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 6, right: 8, left: -22, bottom: 0 }}>
        <defs>
          <linearGradient id="gradImports" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#2D9C6E" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#2D9C6E" stopOpacity={0.04} />
          </linearGradient>
          <linearGradient id="gradFail" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#C0392B" stopOpacity={0.28} />
            <stop offset="100%" stopColor="#C0392B" stopOpacity={0.03} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke={C.border} vertical={false} />
        <XAxis
          dataKey="date" tickFormatter={fmtDay}
          tick={{ fontSize: 10, fill: C.muted }} tickLine={false} axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          allowDecimals={false}
          tick={{ fontSize: 10, fill: C.muted }} tickLine={false} axisLine={false}
        />
        <Tooltip
          contentStyle={{
            fontSize: 12, borderRadius: 8,
            border: `1px solid ${C.border}`,
            boxShadow: "0 4px 12px rgba(0,0,0,.08)",
          }}
          labelFormatter={v => v}
        />
        <Area
          type="linear" dataKey="imports" name="Imports réussis"
          stroke="#2D9C6E" strokeWidth={2}
          fill="url(#gradImports)"
          dot={false} activeDot={{ r: 4 }}
        />
        <Area
          type="linear" dataKey="failures" name="Échecs"
          stroke="#C0392B" strokeWidth={2}
          fill="url(#gradFail)"
          dot={false} activeDot={{ r: 3 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ─── CVE Distribution — horizontal bars ───────────────────────────────────────
function CveDistribution({ posture }) {
  if (!posture || posture.scanned === 0) return (
    <div className="flex flex-col items-center justify-center h-full gap-2 text-xs text-slate-400">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}
        strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 opacity-40">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
      Aucun paquet scanné
    </div>
  );
  const total = SEV.reduce((s, { key }) => s + (posture[key] || 0), 0);
  const max   = Math.max(...SEV.map(({ key }) => posture[key] || 0), 1);

  return (
    <div className="h-full flex flex-col gap-1.5">
      {/* Summary */}
      <div className="flex items-baseline gap-2 mb-2">
        <span
          style={{ color: total > 0 ? C.red : C.green }}
          className="text-[28px] font-extrabold tabular-nums leading-none"
        >
          {fmtNum(total)}
        </span>
        <span className="text-[10px] text-slate-400">
          CVE · {posture.scanned}/{posture.total} paquets analysés
        </span>
      </div>
      {/* Bars */}
      <div className="flex flex-col gap-2.5 flex-1 justify-around">
        {SEV.map(({ key, label, color }) => {
          const n   = posture[key] || 0;
          const pct = n > 0 ? Math.max((n / max) * 100, 4) : 0;
          return (
            <div key={key} className="flex items-center gap-2.5">
              <span
                style={{ color }}
                className="text-[10px] font-bold w-11 text-right flex-shrink-0 tabular-nums"
              >
                {label}
              </span>
              <div className="flex-1 h-2.5 bg-slate-100 overflow-hidden" style={{ borderRadius: 0 }}>
                <div
                  style={{ width: `${pct}%`, background: color, transition: "width .5s ease", borderRadius: 0 }}
                  className="h-full"
                />
              </div>
              <span
                style={{ color: n > 0 ? color : C.border }}
                className="text-xs font-bold w-8 text-right tabular-nums flex-shrink-0"
              >
                {fmtNum(n)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Security Review — pie / donut ────────────────────────────────────────────
const CUSTOM_LABEL = ({ cx, cy, midAngle, innerRadius, outerRadius, value }) => {
  if (value === 0) return null;
  const RADIAN = Math.PI / 180;
  const r  = innerRadius + (outerRadius - innerRadius) * 0.5;
  const x  = cx + r * Math.cos(-midAngle * RADIAN);
  const y  = cy + r * Math.sin(-midAngle * RADIAN);
  return (
    <text x={x} y={y} fill="white" textAnchor="middle" dominantBaseline="central"
      style={{ fontSize: 11, fontWeight: 700 }}>
      {value}
    </text>
  );
};

function SecurityDonut({ review, onNavigate }) {
  if (!review) return null;

  const slices = Object.entries(STATUS_META)
    .map(([key, meta]) => ({ name: meta.label, value: review[key] || 0, color: meta.color }))
    .filter(s => s.value > 0);

  const total    = slices.reduce((s, { value }) => s + value, 0);
  const expiring = review.expiring_soon || [];

  if (total === 0 && expiring.length === 0) return (
    <div className="flex flex-col items-center justify-center h-full gap-2">
      <svg viewBox="0 0 24 24" fill="none" stroke={C.green} strokeWidth={1.5}
        strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 opacity-70">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      <span style={{ color: C.green }} className="text-xs">Aucune action requise</span>
    </div>
  );

  return (
    <div className="h-full flex items-stretch gap-5">

      {/* ── Grand donut — remplit toute la hauteur ── */}
      {slices.length > 0 && (
        <div style={{ minWidth: 158, maxWidth: 158 }} className="h-full">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={slices} cx="50%" cy="50%"
                innerRadius={44} outerRadius={68}
                dataKey="value" labelLine={false}
                label={CUSTOM_LABEL}
                paddingAngle={2}
              >
                {slices.map((s, i) => (
                  <Cell key={i} fill={s.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* ── Légende + expirantes ── */}
      <div className="flex flex-col justify-center gap-3 flex-1 min-w-0">
        {slices.map((s, i) => (
          <div key={i} className="flex items-center gap-2.5 min-w-0">
            <span
              style={{ background: s.color }}
              className="w-2.5 h-2.5 rounded-full flex-shrink-0"
            />
            <span className="text-[12px] text-slate-500 flex-1 truncate">{s.name}</span>
            <span style={{ color: s.color }} className="text-[13px] font-bold flex-shrink-0">
              {s.value}
            </span>
          </div>
        ))}

      </div>
    </div>
  );
}

// ─── ClamAV panel — menaces bloquées (style RSSI) ─────────────────────────────
function ClamavPanel({ clamav }) {
  if (!clamav) return null;

  const count     = clamav.detections_total ?? 0;
  const ok        = clamav.available && clamav.daemon_running;
  const color     = count > 0 ? "#DC2626" : "#16a34a";

  // Âge base de signatures en jours
  let dbAgeDays = null;
  if (clamav.db_date) {
    try {
      const dbDate = new Date(clamav.db_date);
      dbAgeDays = Math.floor((Date.now() - dbDate.getTime()) / 86_400_000);
    } catch {}
  }
  const dbAgeColor = dbAgeDays == null ? C.muted
    : dbAgeDays <= 3  ? "#16a34a"
    : dbAgeDays <= 7  ? C.yellow
    : C.red;

  // Dernière détection
  let lastDetectLabel = null;
  if (clamav.last_detection) {
    try {
      const d = new Date(clamav.last_detection);
      const daysAgo = Math.floor((Date.now() - d.getTime()) / 86_400_000);
      lastDetectLabel = daysAgo === 0 ? "aujourd'hui"
        : daysAgo === 1 ? "il y a 1 jour"
        : `il y a ${daysAgo} jours`;
    } catch {}
  }

  return (
    <div className="h-full flex flex-col items-center text-center px-4" style={{ paddingTop: "1.75rem" }}>
      {/* Nombre */}
      <div style={{ color }} className="text-[64px] font-light leading-none tabular-nums tracking-tight">
        {count}
      </div>
      {/* Label — minHeight identique à SlaViolationsPanel pour aligner le séparateur */}
      <div className="text-[12px] text-slate-500 leading-snug mt-2 flex items-start justify-center"
           style={{ minHeight: "2.5rem" }}>
        menace{count !== 1 ? "s" : ""} bloquée{count !== 1 ? "s" : ""}
      </div>
      {/* Séparateur */}
      <div className="w-10 border-t border-slate-200 mt-1 mb-3 flex-shrink-0" />
      {/* Méta antivirus */}
      <div className="flex flex-col items-center gap-1 text-[11px]">
        <div className="flex items-center justify-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full flex-shrink-0"
            style={{ background: ok ? "#16a34a" : C.red }} />
          <span className="text-slate-500">
            {ok ? "Antivirus actif" : clamav.available ? "Sans daemon" : "Inactif"}
          </span>
        </div>
        {dbAgeDays != null && (
          <div style={{ color: dbAgeColor }} className="font-medium">
            Base {dbAgeDays === 0 ? "à jour (aujourd'hui)"
              : dbAgeDays === 1 ? "mise à jour il y a 1 jour"
              : `mise à jour il y a ${dbAgeDays} j`}
            {clamav.db_version ? ` · v${clamav.db_version}` : ""}
          </div>
        )}
        {count > 0 && lastDetectLabel ? (
          <div className="text-slate-400">
            Dernière : <span className="font-mono text-slate-600">{clamav.last_package}</span>{" "}
            <span style={{ color: C.red }}>{lastDetectLabel}</span>
          </div>
        ) : (
          <div className="text-slate-400">Aucune menace détectée</div>
        )}
      </div>
    </div>
  );
}

// ─── SLA Violations panel ─────────────────────────────────────────────────────
function SlaViolationsPanel({ slaOverdue, onNavigate }) {
  const count = slaOverdue?.length || 0;
  const color = count > 0 ? "#DC2626" : "#16a34a";
  return (
    <div className="h-full flex flex-col items-center text-center px-4" style={{ paddingTop: "1.75rem" }}>
      {/* Nombre */}
      <div style={{ color }} className="text-[64px] font-light leading-none tabular-nums tracking-tight">
        {count}
      </div>
      {/* Label — minHeight identique à ClamAV pour aligner le séparateur */}
      <div className="text-[12px] text-slate-500 leading-snug mt-2 flex items-start justify-center"
           style={{ minHeight: "2.5rem" }}>
        paquet{count !== 1 ? "s" : ""} dépass{count !== 1 ? "ent" : "e"} le SLA de révision
      </div>
      {/* Séparateur */}
      <div className="w-10 border-t border-slate-200 mt-1 mb-3 flex-shrink-0" />
      {/* Action */}
      <div className="flex flex-col items-center gap-1 text-[11px]">
        {count > 0 ? (
          <button
            onClick={onNavigate}
            style={{ color: "#DC2626", background: "#FEF2F2", border: "1px solid #FECACA" }}
            className="text-[11px] font-semibold px-3 py-1 rounded-lg hover:opacity-80 transition-opacity cursor-pointer"
          >
            Traiter →
          </button>
        ) : (
          <span className="text-slate-400">Aucun SLA dépassé</span>
        )}
      </div>
    </div>
  );
}

// ─── Alerts banner ─────────────────────────────────────────────────────────────
function AlertsBanner({ alerts }) {
  if (!alerts?.length) return null;
  return (
    <div className="bg-white border border-slate-200 rounded-xl px-4 py-3 mb-4 shadow-[0_1px_3px_rgba(0,0,0,0.06)]">
      <div className="flex items-center gap-2 mb-2">
        <svg viewBox="0 0 24 24" fill="none" stroke={C.red} strokeWidth={2}
          strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4 flex-shrink-0">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
        <span style={{ color: C.red }} className="text-[11px] font-bold uppercase tracking-wider">
          {alerts.length} alerte{alerts.length > 1 ? "s" : ""} système
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-1.5">
        {alerts.map((a, i) => {
          const style = ALERT_STYLE[a.type] || { bg: `${C.muted}18`, border: C.muted, text: C.muted };
          const isDepsMissing = a.type === "deps_missing";
          return (
            <div key={i}
              style={{ background: style.bg, borderLeft: `3px solid ${style.border}` }}
              className="flex items-start justify-between gap-2 px-3 py-2 rounded-r-lg"
            >
              <div className="min-w-0 flex-1">
                <p style={{ color: C.text }} className="text-[12px] font-semibold truncate">
                  {a.package}
                </p>
                <p style={{ color: C.sub }} className="text-[11px] mt-px leading-tight">
                  {a.message}
                </p>
                {isDepsMissing && a.deps?.length > 0 && (
                  <p className="text-[10px] mt-0.5 font-mono truncate" style={{ color: style.text }}>
                    {a.deps.join(", ")}
                  </p>
                )}
              </div>
              {isDepsMissing && (
                <a href="/packages"
                  className="shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-md transition-opacity hover:opacity-70"
                  style={{ color: style.text, background: "#D9770630" }}
                  title="Voir dans les paquets et résoudre"
                >
                  Résoudre →
                </a>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Recent imports table ──────────────────────────────────────────────────────
function ImportsTable({ imports, page, onPageChange }) {
  const total = imports?.length || 0;
  const pages = Math.ceil(total / PER_PAGE);
  const rows  = (imports || []).slice((page - 1) * PER_PAGE, page * PER_PAGE);

  if (!total) return (
    <div className="text-center py-10 text-xs text-slate-400">
      Aucun import récent.
    </div>
  );

  return (
    <div className="flex flex-col">
      <div className="overflow-x-auto -mx-4 -mt-4">
        <table className="w-full border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50/80">
              {["Paquet", "Version", "Action", "Date", "Statut"].map(h => (
                <th key={h} className="px-4 py-2 text-left text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((e, i) => {
              const ok = e.result === "SUCCESS";
              return (
                <tr key={i} className="border-b border-slate-50 hover:bg-slate-50/70 transition-colors">
                  <td className="px-4 py-2.5 font-mono font-semibold" style={{ color: C.text }}>
                    {e.package || "—"}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-slate-400">
                    {e.version || "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-slate-100 text-slate-500">
                      {e.action || "—"}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-slate-400">{fmtTs(e.timestamp)}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-[10px] font-semibold" style={{ color: ok ? C.green : C.red }}>
                      {ok ? "Succès" : "Échec"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {pages > 1 && (
        <Paginator page={page} pages={pages} total={total} perPage={PER_PAGE} onPageChange={onPageChange} />
      )}
    </div>
  );
}

// ─── CVE Trends Chart ─────────────────────────────────────────────────────────
function CveTrendsChart({ trends }) {
  // trends = [{window_days, packages_imported, cve_totals:{critical,high,medium,low,negligible}, ...}, ...]
  const data = (trends || []).map((t) => ({
    name: `${t.window_days}j`,
    critical:   t.cve_totals?.critical   || 0,
    high:       t.cve_totals?.high       || 0,
    medium:     t.cve_totals?.medium     || 0,
    low:        t.cve_totals?.low        || 0,
    paquets:    t.packages_imported      || 0,
  }));

  if (!data.length) return <p className="text-sm text-slate-400 py-4 text-center">Pas de données</p>;

  return (
    <div className="space-y-4">
      <ResponsiveContainer width="100%" height={180}>
        <LineChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={C.border} />
          <XAxis dataKey="name" tick={{ fontSize: 11, fill: C.sub }} />
          <YAxis tick={{ fontSize: 11, fill: C.sub }} width={48} />
          <Tooltip
            contentStyle={{ fontSize: 12, borderRadius: 8, border: `1px solid ${C.border}` }}
          />
          <Legend wrapperStyle={{ fontSize: 11 }} />
          <Line type="monotone" dataKey="critical" stroke={C.red}    strokeWidth={2} dot={{ r: 3 }} name="Critical" />
          <Line type="monotone" dataKey="high"     stroke={C.orange} strokeWidth={2} dot={{ r: 3 }} name="High" />
          <Line type="monotone" dataKey="medium"   stroke={C.yellow} strokeWidth={2} dot={{ r: 3 }} name="Medium" />
          <Line type="monotone" dataKey="low"      stroke={C.green}  strokeWidth={1} dot={{ r: 2 }} name="Low" />
        </LineChart>
      </ResponsiveContainer>
      <div className="grid grid-cols-3 gap-3">
        {data.map((d) => (
          <div key={d.name} className="rounded-lg bg-slate-50 border border-slate-200 p-3">
            <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{d.name}</p>
            <p className="text-lg font-bold text-slate-800 mt-0.5">{d.paquets} <span className="text-[11px] font-normal text-slate-400">paquets</span></p>
            <div className="flex gap-2 mt-1 flex-wrap">
              {d.critical > 0 && <span className="text-[10px] font-bold text-red-600">🔴 {d.critical}</span>}
              {d.high     > 0 && <span className="text-[10px] font-bold text-orange-500">🟠 {d.high}</span>}
              {d.medium   > 0 && <span className="text-[10px] text-yellow-600">🟡 {d.medium}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [stats,       setStats]       = useState(null);
  const [history,     setHistory]     = useState([]);
  const [enriched,    setEnriched]    = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [lastRefresh, setLast]        = useState(null);
  const [period,      setPeriod]      = useState(30);
  const [importsPage, setImportsPage] = useState(1);
  const [layout,      setLayout]      = useState(loadSavedLayout);
  const navigate = useNavigate();

  const handleLayoutChange = (newLayout) => {
    setLayout(newLayout);
    localStorage.setItem(LS_KEY, JSON.stringify(newLayout));
  };
  const resetLayout = () => {
    setLayout(DEFAULT_LAYOUT);
    localStorage.removeItem(LS_KEY);
  };

  // Full reload — stats + history for selected period
  const load = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [data, hist, enr] = await Promise.all([
        getDashboardStats(),
        getDashboardHistory(period),
        getEnrichedDashboard({ trend_windows: "30,60,90" }).catch(() => null),
      ]);
      setStats(data);
      setHistory(hist?.history || []);
      setEnriched(enr);
      setLast(new Date());
      if (!silent) toast.success("Tableau de bord actualisé");
    } catch {
      if (!silent) toast.error("Impossible de charger le tableau de bord");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [period]);

  // Period change — only reload history, keep stats
  const handlePeriod = useCallback(async (days) => {
    if (days === period) return;
    setPeriod(days);
    try {
      const hist = await getDashboardHistory(days);
      setHistory(hist?.history || []);
    } catch { /* silent — keep previous data */ }
  }, [period]);

  // Initial load + polling every 30 s
  useEffect(() => {
    load(true);
    const id = setInterval(() => load(true), 30_000);
    return () => clearInterval(id);
  }, [load]);

  // Reset page when imports data changes
  useEffect(() => { setImportsPage(1); }, [stats]);

  // ── Loading skeleton ──
  if (loading) return (
    <div className="flex items-center justify-center h-48">
      <div
        style={{ borderTopColor: "transparent", borderColor: C.blue }}
        className="w-7 h-7 border-2 rounded-full animate-spin"
      />
    </div>
  );
  if (!stats) return null;

  const {
    packages, activity, recent_imports,
    alerts, clamav, security_posture, security_review,
  } = stats;

  const needsAction  = (security_review?.pending_review || 0) + (security_review?.blocked || 0);
  const totalCve     = SEV.reduce((s, { key }) => s + (security_posture?.[key] || 0), 0);

  return (
    <div className="min-h-full bg-slate-50 px-6 pt-5 pb-12">

      {/* ── Control bar ── */}
      <div className="flex items-center justify-between mb-5 gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-extrabold text-slate-900 leading-none">
            Tableau de bord
          </h1>
          <p className="text-[11px] text-slate-400 mt-1">
            {lastRefresh
              ? `Actualisé à ${lastRefresh.toLocaleTimeString("fr-FR")}`
              : "Chargement…"}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Period filter */}
          <div className="flex rounded-lg border border-slate-200 bg-white overflow-hidden shadow-[0_1px_2px_rgba(0,0,0,0.05)]">
            {PERIODS.map(({ label, days }) => (
              <button
                key={days}
                onClick={() => handlePeriod(days)}
                style={
                  period === days
                    ? { background: "#EEF2FF", color: C.indigo, borderColor: "#C7D2FE" }
                    : {}
                }
                className={`text-[11px] font-medium px-3 py-1.5 border-r last:border-r-0 border-slate-200 transition-colors ${
                  period === days ? "" : "text-slate-500 hover:bg-slate-50"
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {/* Reset layout */}
          <button
            onClick={resetLayout}
            className="text-[11px] font-medium px-3 py-1.5 rounded-lg border border-slate-200 text-slate-500 hover:bg-slate-50 transition-colors"
            title="Réinitialiser la disposition"
          >
            Réinitialiser la vue
          </button>

          {/* Refresh */}
          <button
            onClick={() => load(false)}
            disabled={refreshing}
            style={{ color: C.blue, borderColor: `${C.blue}40`, background: `${C.blue}10` }}
            className="text-[11px] font-semibold px-3 py-1.5 rounded-lg border flex items-center gap-1.5 disabled:opacity-60 transition-opacity"
          >
            <svg
              viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"
              className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`}
            >
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
            </svg>
            Actualiser
          </button>
        </div>
      </div>

      {/* ── Grille déplaçable / redimensionnable ── */}
      <ReactGridLayout
        layout={layout}
        cols={GRID_COLS}
        rowHeight={GRID_ROW_H}
        margin={[12, 12]}
        containerPadding={[0, 0]}
        draggableHandle=".drag-handle"
        onLayoutChange={handleLayoutChange}
        resizeHandles={["se"]}
      >
        {/* KPI Paquets */}
        <div key="kpi-paquets">
          <KpiCard label="Paquets" value={packages?.total ?? 0} sub={fmtBytes(packages?.total_size_bytes)}
            palette={KPI_PALETTES.paquets}
            icon={<svg className="w-9 h-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.4}><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>}
          />
        </div>

        {/* KPI Imports */}
        <div key="kpi-imports">
          <KpiCard label="Imports" value={packages?.imports_today ?? 0} sub="ce jour"
            palette={KPI_PALETTES.imports}
            icon={<svg className="w-9 h-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.4}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>}
          />
        </div>

        {/* KPI CVEs */}
        <div key="kpi-cves">
          <KpiCard label="CVEs" value={totalCve} sub={`${security_posture?.scanned ?? 0} paquets analysés`}
            palette={KPI_PALETTES.cves} onClick={() => navigate("/security")}
            icon={<svg className="w-9 h-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.4}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>}
          />
        </div>

        {/* KPI RSSI */}
        <div key="kpi-rssi">
          <KpiCard label="RSSI"
            value={needsAction > 0 ? needsAction : (security_review?.total_decisions ?? 0)}
            sub={needsAction > 0 ? "action(s) requise(s)" : "décision(s) active(s)"}
            palette={KPI_PALETTES.rssi} onClick={() => navigate("/security")}
            icon={<svg className="w-9 h-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.4}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>}
          />
        </div>

        {/* KPI Alertes */}
        <div key="kpi-alertes">
          <KpiCard label="Alertes" value={alerts?.length ?? 0}
            sub={!alerts?.length ? "Tout nominal" : "à traiter"}
            palette={KPI_PALETTES.alertes}
            icon={<svg className="w-9 h-9" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.4}><path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>}
          />
        </div>

        {/* Historique */}
        <div key="history">
          <Panel title={`Historique — Imports & Échecs (${period === 1 ? "24 h" : `${period} j`})`}
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>}>
            <HistoryChart data={history} />
          </Panel>
        </div>

        {/* SLA Violations */}
        <div key="sla-violations">
          <Panel title="SLA de révision"
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>}>
            <SlaViolationsPanel slaOverdue={enriched?.sla_overdue} onNavigate={() => navigate("/security")} />
          </Panel>
        </div>

        {/* Distribution CVE */}
        <div key="cve-dist">
          <Panel title="Distribution CVE — Grype"
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}>
            <CveDistribution posture={security_posture} />
          </Panel>
        </div>

        {/* Révision RSSI */}
        <div key="rssi-donut">
          <Panel title="Révision RSSI" badge={needsAction} onAction={() => navigate("/security")}
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>}>
            <SecurityDonut review={security_review} onNavigate={() => navigate("/security")} />
          </Panel>
        </div>

        {/* ClamAV */}
        <div key="clamav">
          <Panel title="ClamAV — Antivirus"
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>}>
            <ClamavPanel clamav={clamav} />
          </Panel>
        </div>

        {/* Tendances CVE */}
        <div key="cve-trends">
          <Panel title="Tendances CVE — glissement 30/60/90 jours"
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>}>
            {enriched?.cve_trends?.length
              ? <CveTrendsChart trends={enriched.cve_trends} />
              : <div className="flex items-center justify-center h-full text-xs text-slate-400">Aucune tendance disponible</div>}
          </Panel>
        </div>

        {/* Alertes système */}
        <div key="alerts">
          <Panel
            title={`${alerts?.length || 0} alerte${alerts?.length !== 1 ? "s" : ""} système`}
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}
          >
            {!alerts?.length ? (
              <div className="flex items-center justify-center h-full text-xs text-slate-400">
                Aucune alerte système
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-1.5 overflow-auto h-full">
                {alerts.map((a, i) => {
                  const style = ALERT_STYLE[a.type] || { bg: `${C.muted}18`, border: C.muted, text: C.muted };
                  const isDepsMissing = a.type === "deps_missing";
                  return (
                    <div key={i}
                      style={{ background: style.bg, borderLeft: `3px solid ${style.border}` }}
                      className="flex items-start justify-between gap-2 px-3 py-2 rounded-r-lg"
                    >
                      <div className="min-w-0 flex-1">
                        <p style={{ color: C.text }} className="text-[12px] font-semibold truncate">{a.package}</p>
                        <p style={{ color: C.sub }} className="text-[11px] mt-px leading-tight">{a.message}</p>
                        {isDepsMissing && a.deps?.length > 0 && (
                          <p className="text-[10px] mt-0.5 font-mono truncate" style={{ color: style.text }}>
                            {a.deps.join(", ")}
                          </p>
                        )}
                      </div>
                      {isDepsMissing && (
                        <a href="/packages"
                          className="shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-md transition-opacity hover:opacity-70"
                          style={{ color: style.text, background: "#D9770630" }}
                        >
                          Résoudre →
                        </a>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* Activité récente */}
        <div key="imports-table">
          <Panel title="Activité récente — imports" actionLabel="Voir tout →" onAction={() => navigate("/packages")}
            icon={<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>}>
            <ImportsTable imports={recent_imports} page={importsPage} onPageChange={setImportsPage} />
          </Panel>
        </div>
      </ReactGridLayout>

    </div>
  );
}
