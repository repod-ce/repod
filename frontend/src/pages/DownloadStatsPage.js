import { useState, useEffect, useCallback } from "react";
import { getDownloadStats } from "../api";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from "recharts";

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtBytes(b) {
  if (!b) return "0 o";
  if (b >= 1_073_741_824) return `${(b / 1_073_741_824).toFixed(1)} Go`;
  if (b >= 1_048_576)     return `${(b / 1_048_576).toFixed(0)} Mo`;
  if (b >= 1_024)         return `${(b / 1_024).toFixed(0)} Ko`;
  return `${b} o`;
}
function fmtNum(n) { return (n ?? 0).toLocaleString("fr-FR"); }

// ── Metadata par format ────────────────────────────────────────────────────────

const FMT = {
  deb:   { label: "DEB",  long: "Debian / Ubuntu (APT)", color: "#8b5cf6", bg: "#ede9fe" },
  rpm:   { label: "RPM",  long: "RHEL / Fedora (DNF·YUM)", color: "#f97316", bg: "#ffedd5" },
  apk:   { label: "APK",  long: "Alpine Linux (apk)",    color: "#0d9488", bg: "#ccfbf1" },
  mixed: { label: "MULTI",long: "Formats multiples",     color: "#64748b", bg: "#f1f5f9" },
};

function FmtBadge({ fmt }) {
  const m = FMT[fmt] ?? FMT.mixed;
  return (
    <span className="inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide"
          style={{ backgroundColor: m.bg, color: m.color }}>
      {m.label}
    </span>
  );
}

// ── Panel KPI ─────────────────────────────────────────────────────────────────

function KpiPanel({ label, value, sub, loading }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
      <div className="px-4 py-2.5 border-b border-gray-100">
        <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">{label}</p>
      </div>
      <div className="px-4 py-4">
        {loading
          ? <div className="h-7 w-20 bg-gray-100 rounded animate-pulse" />
          : <p className="text-2xl font-bold text-gray-900 leading-none tabular-nums">{value}</p>
        }
        {sub && <p className="text-xs text-gray-400 mt-1.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Jauge horizontale (répartition formats) ────────────────────────────────────

function FormatBreakdown({ perFmt, total, loading }) {
  if (loading) {
    return (
      <div className="space-y-4 py-1">
        {["deb","rpm","apk"].map(f => (
          <div key={f} className="space-y-1.5">
            <div className="h-2.5 w-24 bg-gray-100 rounded animate-pulse" />
            <div className="h-2 bg-gray-100 rounded-full animate-pulse" />
          </div>
        ))}
      </div>
    );
  }
  if (!total) {
    return <p className="text-xs text-gray-400 text-center py-6">Aucun téléchargement</p>;
  }
  return (
    <div className="space-y-4">
      {["deb","rpm","apk"].map(fmt => {
        const m     = FMT[fmt];
        const count = perFmt?.[fmt] ?? 0;
        const pct   = total > 0 ? (count / total) * 100 : 0;
        return (
          <div key={fmt}>
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: m.color }} />
                <span className="text-xs text-gray-600">{m.long}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-gray-800 tabular-nums">
                  {fmtNum(count)}
                </span>
                <span className="text-[10px] text-gray-400 w-8 text-right tabular-nums">
                  {pct.toFixed(0)}%
                </span>
              </div>
            </div>
            <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
              <div className="h-full rounded-full transition-all duration-700"
                   style={{ width: `${pct}%`, backgroundColor: m.color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Tooltip recharts custom ────────────────────────────────────────────────────

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-white border border-gray-200 rounded-lg shadow-lg px-3 py-2 text-xs">
      <p className="font-semibold text-gray-600 mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <span className="w-2 h-2 rounded-full bg-blue-500" />
        <span className="text-gray-500">Téléchargements</span>
        <span className="font-bold text-gray-900 ml-1 tabular-nums">
          {fmtNum(payload[0].value)}
        </span>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DownloadStatsPage() {
  const [days, setDays]       = useState(30);
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await getDownloadStats(days)); }
    catch { setData(null); }
    finally { setLoading(false); }
  }, [days]);

  useEffect(() => { load(); }, [load]);

  const summary    = data?.summary ?? {};
  const perFmt     = summary.per_format ?? {};
  const totalDl    = summary.total_downloads ?? 0;
  const avgPerDay  = summary.avg_per_day ?? 0;
  const peakDay    = summary.peak_day;

  const perPackage = (data?.per_package ?? []).filter(
    (p) => !search || p.name.toLowerCase().includes(search.toLowerCase())
  );
  const perDay = (data?.per_day ?? []).map((d) => ({
    ...d,
    label: d.date.slice(5),
  }));

  const activeDays = perDay.filter(d => d.downloads > 0).length;

  // ── Pas de logs ──────────────────────────────────────────────────────────────
  if (!summary.log_available && !loading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-64">
        <div className="bg-white border border-gray-200 rounded-xl p-8 text-center space-y-3 shadow-sm max-w-md w-full">
          <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto">
            <svg className="w-5 h-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"
                 strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="20" x2="18" y2="10"/>
              <line x1="12" y1="20" x2="12" y2="4"/>
              <line x1="6"  y1="20" x2="6"  y2="14"/>
            </svg>
          </div>
          <p className="font-semibold text-gray-800">Aucun log disponible</p>
          <p className="text-sm text-gray-500">
            Le fichier <code className="font-mono bg-gray-100 px-1 rounded text-xs">downloads.log</code> sera
            créé automatiquement dès que le dépôt servira son premier paquet (DEB, RPM ou APK).
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-5">

      {/* ── En-tête ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Statistiques de téléchargements</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Activité du dépôt — paquets DEB, RPM et APK
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          {[7, 30, 90].map((d) => (
            <button key={d} onClick={() => setDays(d)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                days === d
                  ? "bg-blue-600 text-white shadow-sm"
                  : "border border-gray-200 text-gray-600 hover:bg-gray-50"
              }`}>
              {d}j
            </button>
          ))}
          <button onClick={load} disabled={loading}
            className="ml-1 p-2 rounded-lg border border-gray-200 hover:bg-gray-50
                       text-gray-500 disabled:opacity-50 transition-colors">
            <svg className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} fill="none"
                 viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
          </button>
        </div>
      </div>

      {/* ── KPIs ────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiPanel
          label="Téléchargements"
          value={fmtNum(totalDl)}
          sub={`~${fmtNum(avgPerDay)} / jour en moyenne`}
          loading={loading}
        />
        <KpiPanel
          label="Paquets distincts"
          value={fmtNum(summary.unique_packages)}
          sub="noms uniques dans les logs"
          loading={loading}
        />
        <KpiPanel
          label="Clients actifs"
          value={fmtNum(summary.unique_clients)}
          sub={`${fmtNum(activeDays)} jour${activeDays !== 1 ? "s" : ""} avec activité`}
          loading={loading}
        />
        <KpiPanel
          label="Volume servi"
          value={fmtBytes(summary.total_bytes)}
          sub={peakDay ? `Pic : ${peakDay.date?.slice(5)} (${fmtNum(peakDay.downloads)})` : "—"}
          loading={loading}
        />
      </div>

      {/* ── Graphe activité + répartition formats ───────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Area chart — 2/3 de la largeur */}
        <div className="lg:col-span-2 bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between gap-3">
            <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
              Activité journalière — {days} derniers jours
            </p>
            {peakDay && !loading && (
              <span className="text-[10px] text-gray-400 shrink-0">
                pic : {peakDay.date?.slice(5)} · {fmtNum(peakDay.downloads)} téléch.
              </span>
            )}
          </div>
          <div className="p-4">
            {!loading && perDay.length === 0 ? (
              <div className="h-44 flex items-center justify-center text-sm text-gray-400">
                Aucune activité sur cette période
              </div>
            ) : loading ? (
              <div className="h-44 bg-gray-50 rounded-lg animate-pulse" />
            ) : (
              <ResponsiveContainer width="100%" height={176}>
                <AreaChart data={perDay} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="dlGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.15} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}    />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                  <XAxis dataKey="label" tick={{ fontSize: 10, fill: "#94a3b8" }}
                         tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "#94a3b8" }}
                         tickLine={false} axisLine={false} allowDecimals={false} width={30} />
                  <Tooltip content={<ChartTooltip />} cursor={{ stroke: "#e2e8f0", strokeWidth: 1 }} />
                  <Area type="monotone" dataKey="downloads"
                        stroke="#3b82f6" strokeWidth={2}
                        fill="url(#dlGrad)"
                        dot={false}
                        activeDot={{ r: 4, fill: "#3b82f6", strokeWidth: 0 }} />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Répartition formats — 1/3 */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-gray-100">
            <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
              Répartition par format
            </p>
          </div>
          <div className="px-4 py-4 flex-1">
            <FormatBreakdown perFmt={perFmt} total={totalDl} loading={loading} />
          </div>
          {/* Mini stats en bas du panneau */}
          <div className="border-t border-gray-100 px-4 py-3 grid grid-cols-2 gap-3 bg-gray-50/40">
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-gray-400 mb-0.5">
                Moy. / jour
              </p>
              <p className="text-base font-bold text-gray-800 tabular-nums">
                {loading ? "…" : fmtNum(avgPerDay)}
              </p>
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-gray-400 mb-0.5">
                Jours actifs
              </p>
              <p className="text-base font-bold text-gray-800 tabular-nums">
                {loading ? "…" : fmtNum(activeDays)}
                <span className="text-xs text-gray-400 font-normal ml-1">/ {days}</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Top paquets ─────────────────────────────────────────────────────── */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-5 py-3.5 border-b border-gray-100 flex items-center justify-between gap-3 flex-wrap">
          <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
            Top paquets téléchargés
          </p>
          <input
            type="text"
            placeholder="Rechercher…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="border border-gray-200 rounded-lg px-3 py-1.5 text-xs
                       focus:outline-none focus:ring-2 focus:ring-blue-500 w-44"
          />
        </div>

        {loading ? (
          <div className="py-6 px-5 space-y-3">
            {[1,2,3].map(i => (
              <div key={i} className="flex items-center gap-4">
                <div className="h-4 w-6 bg-gray-100 rounded animate-pulse" />
                <div className="h-4 flex-1 bg-gray-100 rounded animate-pulse" />
                <div className="h-4 w-16 bg-gray-100 rounded animate-pulse" />
                <div className="h-4 w-12 bg-gray-100 rounded animate-pulse" />
              </div>
            ))}
          </div>
        ) : perPackage.length === 0 ? (
          <div className="py-10 text-center text-sm text-gray-400">
            {search ? "Aucun paquet correspondant." : "Aucun téléchargement sur cette période."}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50/70 text-[10px] font-semibold text-gray-400
                               uppercase tracking-wider border-b border-gray-100">
                  <th className="px-4 py-3 text-left w-8">#</th>
                  <th className="px-4 py-3 text-left">Paquet</th>
                  <th className="px-4 py-3 text-left">Format</th>
                  <th className="px-4 py-3 text-right">Téléch.</th>
                  <th className="px-4 py-3 text-right">Volume</th>
                  <th className="px-4 py-3 text-right">Clients</th>
                  <th className="px-4 py-3 text-left">Versions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {perPackage.map((pkg, i) => {
                  const maxDl = perPackage[0]?.downloads || 1;
                  const pct   = Math.round((pkg.downloads / maxDl) * 100);
                  const fmt   = FMT[pkg.format] ?? FMT.mixed;
                  return (
                    <tr key={pkg.name} className="hover:bg-blue-50/20 transition-colors group">
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs">{i + 1}</td>
                      <td className="px-4 py-3 min-w-[180px]">
                        <div className="font-medium text-gray-800 text-sm">{pkg.name}</div>
                        {/* Barre de progression relative */}
                        <div className="mt-1.5 flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden max-w-32">
                            <div className="h-full rounded-full transition-all duration-500"
                                 style={{ width: `${pct}%`, backgroundColor: fmt.color + "99" }} />
                          </div>
                          <span className="text-[9px] text-gray-400 tabular-nums">{pct}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <FmtBadge fmt={pkg.format ?? "deb"} />
                      </td>
                      <td className="px-4 py-3 text-right font-semibold text-gray-800 tabular-nums">
                        {fmtNum(pkg.downloads)}
                      </td>
                      <td className="px-4 py-3 text-right text-gray-500 text-xs tabular-nums">
                        {fmtBytes(pkg.bytes)}
                      </td>
                      <td className="px-4 py-3 text-right text-gray-600 tabular-nums">
                        {pkg.clients}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {pkg.versions.slice(0, 3).map((v) => (
                            <span key={v} className="px-1.5 py-0.5 bg-gray-100 text-gray-500
                                                     rounded text-[10px] font-mono">
                              {v}
                            </span>
                          ))}
                          {pkg.versions.length > 3 && (
                            <span className="text-[10px] text-gray-400">+{pkg.versions.length - 3}</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Activité récente ─────────────────────────────────────────────────── */}
      {(data?.recent ?? []).length > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100">
            <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
              Activité récente · 50 derniers téléchargements
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50/70 text-[10px] font-semibold text-gray-400
                               uppercase tracking-wider border-b border-gray-100">
                  <th className="px-4 py-3 text-left">Date</th>
                  <th className="px-4 py-3 text-left">Fichier</th>
                  <th className="px-4 py-3 text-left">Format</th>
                  <th className="px-4 py-3 text-left">Client IP</th>
                  <th className="px-4 py-3 text-right">Taille</th>
                  <th className="px-4 py-3 text-left">User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {data.recent.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-gray-500 whitespace-nowrap">
                      {r.date}
                    </td>
                    <td className="px-4 py-2.5 text-gray-700 max-w-[240px] truncate font-medium">
                      {r.filename}
                    </td>
                    <td className="px-4 py-2.5">
                      <FmtBadge fmt={r.pkg_format ?? "deb"} />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-gray-500">{r.ip}</td>
                    <td className="px-4 py-2.5 text-right text-gray-400 tabular-nums">
                      {fmtBytes(r.bytes)}
                    </td>
                    <td className="px-4 py-2.5 text-gray-400 max-w-[200px] truncate">
                      {r.user_agent}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
