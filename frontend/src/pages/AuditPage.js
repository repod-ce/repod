import { useState, useEffect, useCallback } from "react";
import { getAuditLogs } from "../api";
import toast from "react-hot-toast";
import Paginator from "../components/Paginator";

const ACTION_META = {
  UPLOAD:    { label: "Upload",       bg: "#EFF6FF", color: "#2563EB" },
  VALIDATE:  { label: "Validation",   bg: "#F0FDF4", color: "#16A34A" },
  INSTALL:   { label: "Install",      bg: "#FAF5FF", color: "#7C3AED" },
  DELETE:    { label: "Suppression",  bg: "#FEF2F2", color: "#DC2626" },
  SYNC:      { label: "Sync",         bg: "#F0F9FF", color: "#0284C7" },
  LOGIN:     { label: "Connexion",    bg: "#F8FAFC", color: "#475569" },
  DECISION:  { label: "Décision",     bg: "#FFF7ED", color: "#EA580C" },
  QUARANTINE:{ label: "Quarantaine",  bg: "#FDF4FF", color: "#9333EA" },
  SLA_RESET: { label: "SLA Reset",   bg: "#FFF1F2", color: "#BE123C" },
  IMPORT:    { label: "Import",       bg: "#F0FDF4", color: "#15803D" },
};

const RESULT_META = {
  SUCCESS: { label: "Succès",    bg: "#DCFCE7", color: "#15803D" },
  FAILURE: { label: "Échec",     bg: "#FEE2E2", color: "#DC2626" },
  WARNING: { label: "Attention", bg: "#FEF9C3", color: "#CA8A04" },
};

function fmtTs(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString("fr-FR", { day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit", second:"2-digit" });
}

function Badge({ map, value }) {
  const m = map[value?.toUpperCase()] || { label: value, bg: "#F1F5F9", color: "#64748B" };
  return (
    <span style={{ background: m.bg, color: m.color, padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>
      {m.label}
    </span>
  );
}

const ACTIONS = ["", "UPLOAD", "VALIDATE", "DELETE", "SYNC", "LOGIN", "DECISION", "QUARANTINE", "SLA_RESET", "IMPORT", "INSTALL"];
const RESULTS = ["", "SUCCESS", "FAILURE", "WARNING"];

const AUDIT_PER_PAGE = 100;

export default function AuditPage() {
  const [logs, setLogs]           = useState([]);
  const [total, setTotal]         = useState(0);
  const [pages, setPages]         = useState(1);
  const [page, setPage]           = useState(1);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [actionFilter, setAction] = useState("");
  const [resultFilter, setResult] = useState("");
  const [packageFilter, setPkg]   = useState("");
  const [sortOrder, setSortOrder] = useState("desc");

  const load = useCallback(async (p = page) => {
    setLoading(true);
    try {
      const data = await getAuditLogs({
        page:    p,
        per_page: AUDIT_PER_PAGE,
        package: packageFilter || undefined,
        action:  actionFilter  || undefined,
        result:  resultFilter  || undefined,
        q:       search        || undefined,
        sort:    sortOrder,
      });
      // Le backend retourne maintenant {items, total, page, per_page, pages}
      setLogs(data.items || data.logs || []);
      setTotal(data.total || 0);
      setPages(data.pages || 1);
    } catch {
      toast.error("Impossible de charger les logs d'audit");
    } finally {
      setLoading(false);
    }
  }, [page, packageFilter, actionFilter, resultFilter, search, sortOrder]);

  useEffect(() => { load(); }, [load]);

  // Réinitialise la page quand les filtres backend changent
  useEffect(() => { setPage(1); }, [packageFilter, actionFilter, resultFilter, search, sortOrder]);

  // Tous les filtres sont server-side — visible = page courante complète
  const visible = logs;

  return (
    <div style={{ padding: "24px 28px 40px", background: "#F8FAFC", minHeight: "100%" }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: "#0F172A", margin: 0 }}>Journal d'audit</h1>
        <p style={{ fontSize: 12, color: "#94A3B8", margin: "4px 0 0" }}>
          Traçabilité complète — toutes les actions critiques sont enregistrées de manière immuable
        </p>
      </div>

      {/* Filtres */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
        {/* Recherche texte */}
        <div style={{ position: "relative", flex: "1 1 220px", minWidth: 200 }}>
          <svg style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)", width:14, height:14, color:"#94A3B8" }}
            viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input value={search} onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="Filtrer par paquet, utilisateur, détail…"
            style={{ width:"100%", paddingLeft:32, paddingRight:12, paddingTop:8, paddingBottom:8, border:"1px solid #E2E8F0", borderRadius:8, fontSize:13, outline:"none", background:"#fff", boxSizing:"border-box" }}/>
        </div>

        {/* Filtre action */}
        <select value={actionFilter} onChange={e => setAction(e.target.value)}
          style={{ padding:"8px 12px", border:"1px solid #E2E8F0", borderRadius:8, fontSize:13, background:"#fff", cursor:"pointer" }}>
          <option value="">Toutes les actions</option>
          {ACTIONS.filter(Boolean).map(a => <option key={a} value={a}>{ACTION_META[a]?.label || a}</option>)}
        </select>

        {/* Filtre résultat */}
        <select value={resultFilter} onChange={e => setResult(e.target.value)}
          style={{ padding:"8px 12px", border:"1px solid #E2E8F0", borderRadius:8, fontSize:13, background:"#fff", cursor:"pointer" }}>
          <option value="">Tous les résultats</option>
          {RESULTS.filter(Boolean).map(r => <option key={r} value={r}>{RESULT_META[r]?.label || r}</option>)}
        </select>

        {/* Filtre paquet */}
        <input value={packageFilter} onChange={e => setPkg(e.target.value)}
          placeholder="Paquet spécifique…"
          style={{ padding:"8px 12px", border:"1px solid #E2E8F0", borderRadius:8, fontSize:13, background:"#fff", width:180 }}/>

        {/* Ordre de tri */}
        <select value={sortOrder} onChange={e => setSortOrder(e.target.value)}
          title="Ordre de tri par horodatage"
          style={{ padding:"8px 12px", border:"1px solid #E2E8F0", borderRadius:8, fontSize:13, background:"#fff", cursor:"pointer" }}>
          <option value="desc">Plus récent d'abord</option>
          <option value="asc">Plus ancien d'abord</option>
        </select>

        <button onClick={load} style={{ padding:"8px 14px", background:"#3B82F6", color:"#fff", border:"none", borderRadius:8, fontSize:13, fontWeight:600, cursor:"pointer" }}>
          Actualiser
        </button>
      </div>

      {/* Compteur */}
      <div style={{ marginBottom: 12, fontSize: 12, color: "#94A3B8" }}>
        {loading ? "Chargement…" : `${visible.length} entrée${visible.length !== 1 ? "s" : ""} affichée${visible.length !== 1 ? "s" : ""} · ${total} au total`}
      </div>

      {/* Table */}
      <div style={{ background: "#fff", border: "1px solid #E2E8F0", borderRadius: 12, overflow: "hidden" }}>
        {loading ? (
          <div style={{ padding: 60, textAlign: "center", color: "#94A3B8", fontSize: 14 }}>Chargement des logs…</div>
        ) : visible.length === 0 ? (
          <div style={{ padding: 60, textAlign: "center", color: "#94A3B8", fontSize: 14 }}>
            Aucune entrée ne correspond aux filtres sélectionnés.
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ background: "#F8FAFC", borderBottom: "1px solid #E2E8F0" }}>
                {["Horodatage", "Action", "Résultat", "Paquet / Version", "Utilisateur", "Détail"].map(h => (
                  <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, fontWeight: 700, color: "#94A3B8", textTransform: "uppercase", letterSpacing: "0.05em", whiteSpace: "nowrap" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map((log, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #F1F5F9", background: i % 2 === 0 ? "#fff" : "#FAFAFA" }}>
                  <td style={{ padding: "10px 16px", fontFamily: "monospace", fontSize: 12, color: "#64748B", whiteSpace: "nowrap" }}>
                    {fmtTs(log.timestamp)}
                  </td>
                  <td style={{ padding: "10px 16px" }}>
                    <Badge map={ACTION_META} value={log.action} />
                  </td>
                  <td style={{ padding: "10px 16px" }}>
                    <Badge map={RESULT_META} value={log.result} />
                  </td>
                  <td style={{ padding: "10px 16px" }}>
                    {log.package ? (
                      <span style={{ fontFamily: "monospace", fontWeight: 600, color: "#0F172A" }}>{log.package}</span>
                    ) : <span style={{ color: "#CBD5E1" }}>—</span>}
                    {log.version && (
                      <span style={{ marginLeft: 6, fontSize: 11, color: "#94A3B8" }}>{log.version}</span>
                    )}
                  </td>
                  <td style={{ padding: "10px 16px", color: "#475569", whiteSpace: "nowrap" }}>
                    {log.user || "—"}
                  </td>
                  <td style={{ padding: "10px 16px", color: "#64748B", maxWidth: 380 }}>
                    <span style={{ display: "block", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={log.detail}>
                      {log.detail || "—"}
                    </span>
                    {log.action_taken && (
                      <span style={{ fontSize: 11, color: "#94A3B8" }}>{log.action_taken}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      <div style={{ marginTop: 16 }}>
        <Paginator
          page={page}
          pages={pages}
          total={total}
          perPage={AUDIT_PER_PAGE}
          onPageChange={setPage}
          loading={loading}
        />
      </div>
    </div>
  );
}
