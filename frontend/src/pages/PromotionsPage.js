import { useState, useEffect, useCallback } from "react";
import { listPendingPromotions } from "../api";
import toast from "react-hot-toast";
import Paginator from "../components/Paginator";

// ─── Helpers ──────────────────────────────────────────────────────────────────
const fmtTs = (iso) =>
  iso
    ? new Date(iso).toLocaleString("fr-FR", {
        day: "2-digit", month: "2-digit", year: "numeric",
        hour: "2-digit", minute: "2-digit",
      })
    : "—";

// ─── Badge de statut ──────────────────────────────────────────────────────────
function StatusChip({ status }) {
  const meta = {
    approved:       { label: "Effectuée",   bg: "#F0FDF4", color: "#15803D", border: "#BBF7D0", dot: "#22c55e" },
    already_present:{ label: "Déjà présent",bg: "#EFF6FF", color: "#1D4ED8", border: "#BFDBFE", dot: "#3b82f6" },
    rejected:       { label: "Refusée",     bg: "#FEF2F2", color: "#DC2626", border: "#FECACA", dot: "#ef4444" },
    pending:        { label: "En attente",  bg: "#FFF7ED", color: "#EA580C", border: "#FED7AA", dot: "#f97316" },
    blocked:        { label: "Bloquée",     bg: "#FEF2F2", color: "#991B1B", border: "#FECACA", dot: "#dc2626" },
  }[status] || { label: status, bg: "#F8FAFC", color: "#64748B", border: "#E2E8F0", dot: "#94a3b8" };

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border"
      style={{ background: meta.bg, color: meta.color, borderColor: meta.border }}
    >
      {meta.label}
    </span>
  );
}

// ─── Badge distribution ────────────────────────────────────────────────────────
const DIST_COLORS = {
  jammy:    { bg: "#EFF6FF", text: "#1D4ED8", border: "#BFDBFE" },
  noble:    { bg: "#F0FDF4", text: "#15803D", border: "#BBF7D0" },
  focal:    { bg: "#FFF7ED", text: "#C2410C", border: "#FED7AA" },
  bookworm: { bg: "#FDF4FF", text: "#7E22CE", border: "#E9D5FF" },
  bullseye: { bg: "#FEF9C3", text: "#854D0E", border: "#FEF08A" },
};

function DistBadge({ codename }) {
  if (!codename) return null;
  const c = DIST_COLORS[codename] || { bg: "#F8FAFC", text: "#64748B", border: "#E2E8F0" };
  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-mono font-semibold border"
      style={{ background: c.bg, color: c.text, borderColor: c.border }}
    >
      {codename}
    </span>
  );
}

// ─── Ligne de promotion ────────────────────────────────────────────────────────
function PromotionRow({ record }) {
  const [open, setOpen] = useState(false);
  const verdict   = record.policy_verdict || {};
  const warnings  = verdict.warnings  || [];
  const reviewing = verdict.reviewing || [];
  const blocking  = verdict.blocking  || [];

  const allAlerts = [...blocking, ...reviewing, ...warnings];

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden hover:border-slate-300 transition-colors">
      {/* Ligne principale */}
      <div
        className="flex items-center gap-4 px-4 py-3 cursor-pointer select-none"
        onClick={() => allAlerts.length > 0 && setOpen((o) => !o)}
      >
        {/* Paquet + route */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-slate-900 font-mono">{record.name}</span>
            {record.version && (
              <span className="text-xs text-slate-400 bg-slate-100 px-1.5 py-0.5 rounded font-mono">
                {record.version}
              </span>
            )}
            {/* Flèche source → cible */}
            <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
              <DistBadge codename={record.from_dist} />
              <svg className="w-3 h-3 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24"
                stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14M12 5l7 7-7 7" />
              </svg>
              <DistBadge codename={record.to_dist} />
            </span>
          </div>
          <div className="mt-0.5 text-xs text-slate-400">
            Par <strong className="text-slate-600">{record.requested_by}</strong>
            {" · "}{fmtTs(record.requested_at)}
            {record.decided_by && (
              <span className="ml-2 text-slate-400">
                · Décidé par <strong className="text-slate-600">{record.decided_by}</strong>
                {" "}{fmtTs(record.decided_at)}
              </span>
            )}
          </div>
        </div>

        {/* Alertes CVE compactes */}
        <div className="hidden sm:flex items-center gap-1 flex-wrap">
          {blocking.map((b, i) => (
            <span key={i} className="text-xs bg-red-50 text-red-700 border border-red-200
                                      px-2 py-0.5 rounded-full font-medium">
              {b}
            </span>
          ))}
          {reviewing.map((r, i) => (
            <span key={i} className="text-xs bg-amber-50 text-amber-700 border border-amber-200
                                      px-2 py-0.5 rounded-full font-medium">
              {r}
            </span>
          ))}
          {warnings.map((w, i) => (
            <span key={i} className="text-xs bg-yellow-50 text-yellow-700 border border-yellow-200
                                      px-2 py-0.5 rounded-full font-medium">
              {w}
            </span>
          ))}
        </div>

        {/* Statut */}
        <div className="shrink-0 flex items-center gap-2">
          <StatusChip status={record.status} />
          {allAlerts.length > 0 && (
            <svg className={`w-3.5 h-3.5 text-slate-400 transition-transform ${open ? "rotate-180" : ""}`}
              fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
              strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
      </div>

      {/* Détails dépliés */}
      {open && (
        <div className="border-t border-slate-100 px-4 py-3 bg-slate-50 space-y-2 text-sm">
          {blocking.length > 0 && (
            <div className="flex items-start gap-2">
              <span className="mt-0.5 shrink-0">
                <svg className="w-3.5 h-3.5 text-red-500" fill="none" viewBox="0 0 24 24"
                  stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/>
                  <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
              </span>
              <span className="text-red-700"><strong>Bloquant :</strong> {blocking.join(" · ")}</span>
            </div>
          )}
          {reviewing.length > 0 && (
            <div className="flex items-start gap-2">
              <span className="mt-0.5 shrink-0">
                <svg className="w-3.5 h-3.5 text-amber-500" fill="none" viewBox="0 0 24 24"
                  stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
              </span>
              <span className="text-amber-700"><strong>Attention :</strong> {reviewing.join(" · ")}</span>
            </div>
          )}
          {warnings.length > 0 && (
            <div className="flex items-start gap-2">
              <span className="mt-0.5 shrink-0">
                <svg className="w-3.5 h-3.5 text-yellow-500" fill="none" viewBox="0 0 24 24"
                  stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </span>
              <span className="text-yellow-700"><strong>Avertissements :</strong> {warnings.join(" · ")}</span>
            </div>
          )}
          {record.decision_note && (
            <div className="flex items-start gap-2 pt-1 border-t border-slate-200">
              <svg className="w-3.5 h-3.5 mt-0.5 text-slate-400 shrink-0" fill="none" viewBox="0 0 24 24"
                stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
              </svg>
              <span className="text-slate-500 italic">« {record.decision_note} »</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────
const STATUS_FILTERS = [
  { key: "all",            label: "Toutes"       },
  { key: "approved",       label: "Effectuées"   },
  { key: "already_present",label: "Déjà présent" },
  { key: "pending",        label: "En attente"   },
  { key: "rejected",       label: "Refusées"     },
  { key: "blocked",        label: "Bloquées"     },
];

export default function PromotionsPage() {
  const [filter,  setFilter]  = useState("all");
  const [data,    setData]    = useState({ total: 0, items: [] });
  const [page,    setPage]    = useState(1);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await listPendingPromotions("all", page, 20);
      setData(res);
    } catch {
      toast.error("Impossible de charger l'historique des promotions");
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => { load(); }, [load]);

  const allItems = data.items?.items || data.items || [];
  const total    = data.total ?? 0;

  const visibleItems = filter === "all"
    ? allItems
    : allItems.filter((r) => r.status === filter);

  return (
    <div className="min-h-full bg-slate-50 px-6 pt-5 pb-12 space-y-6">

      {/* ── En-tête ───────────────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Promotions</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Historique des promotions de paquets entre distributions
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-600
                     bg-white border border-slate-200 rounded-lg hover:bg-slate-50
                     transition-colors disabled:opacity-40"
        >
          <svg className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
            strokeLinecap="round" strokeLinejoin="round">
            <path d="M23 4v6h-6M1 20v-6h6" />
            <path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15" />
          </svg>
          Rafraîchir
        </button>
      </div>

      {/* ── Info politique CVE ────────────────────────────────────────────── */}
      <div className="flex items-start gap-3 p-4 bg-white border border-slate-200 rounded-xl text-sm text-slate-600 shadow-sm">
        <svg className="w-4 h-4 mt-0.5 shrink-0 text-slate-400" fill="none" viewBox="0 0 24 24"
          stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="16" x2="12" y2="12"/>
          <line x1="12" y1="8" x2="12.01" y2="8"/>
        </svg>
        <div className="space-y-0.5">
          <p className="font-semibold text-slate-700">Politique de promotion</p>
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1">
            <span className="flex items-center gap-1.5">
              <strong>Critical</strong> — promotion bloquée
            </span>
            <span className="flex items-center gap-1.5">
              <strong>High / Medium</strong> — avertissement, promotion autorisée
            </span>
            <span className="flex items-center gap-1.5">
              <strong>Low / Negligible</strong> — transparent
            </span>
          </div>
        </div>
      </div>

      {/* ── Filtres statut ────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        {STATUS_FILTERS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => { setFilter(key); setPage(1); }}
            className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              filter === key
                ? "bg-slate-800 text-white border-slate-800"
                : "bg-white text-slate-600 border-slate-200 hover:bg-slate-50"
            }`}
          >
            {label}
          </button>
        ))}
        {total > 0 && (
          <span className="ml-auto text-xs text-slate-400">{total} entrée(s)</span>
        )}
      </div>

      {/* ── Contenu ───────────────────────────────────────────────────────── */}
      {loading && visibleItems.length === 0 ? (
        <div className="flex items-center justify-center h-32 text-slate-400 text-sm gap-2">
          <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
          </svg>
          Chargement…
        </div>
      ) : visibleItems.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-slate-400">
          <svg className="w-12 h-12 mb-3 opacity-25" fill="none" viewBox="0 0 24 24"
            stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/>
          </svg>
          <p className="font-medium text-slate-500">
            {filter === "all" ? "Aucune promotion enregistrée" : `Aucune promotion "${filter}"`}
          </p>
          <p className="text-sm mt-0.5">
            Les promotions de paquets entre distributions s'afficheront ici.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {visibleItems.map((record) => (
            <PromotionRow key={record.id} record={record} />
          ))}
        </div>
      )}

      {/* ── Pagination ────────────────────────────────────────────────────── */}
      {total > 20 && (
        <Paginator
          page={page}
          perPage={20}
          total={total}
          onPageChange={setPage}
        />
      )}
    </div>
  );
}
