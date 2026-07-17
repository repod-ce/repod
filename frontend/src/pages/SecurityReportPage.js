/**
 * Rapport d'audit de sécurité — export PDF via window.print()
 * Accessible via /security/report (nouvelle tab)
 * Optimisé pour l'impression : @media print masque les contrôles UI
 */
import { useState, useEffect, useRef } from "react";
import { getSecurityReport } from "../api";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function fmtDateShort(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("fr-FR", {
    day: "2-digit", month: "2-digit", year: "numeric",
  });
}

const SEV_COLORS = {
  critical:   { bg: "#fef2f2", text: "#b91c1c", badge: "#dc2626" },
  high:       { bg: "#fff7ed", text: "#c2410c", badge: "#ea580c" },
  medium:     { bg: "#fefce8", text: "#854d0e", badge: "#ca8a04" },
  low:        { bg: "#f0fdf4", text: "#166534", badge: "#16a34a" },
  negligible: { bg: "#f9fafb", text: "#4b5563", badge: "#6b7280" },
};

const ACTION_LABELS = {
  accept_risk:      "Risque accepté",
  exception:        "Exception accordée",
  reject:           "Rejeté / Quarantaine",
  upgrade_required: "Mise à jour requise",
};

const STATUS_LABELS = {
  validated:       "Validé",
  pending_review:  "En révision",
  blocked:         "Bloqué",
  quarantined:     "Quarantaine",
  accepted_risk:   "Risque accepté",
  exception:       "Exception",
  upgrade_required:"Upgrade requis",
};

const POLICY_LABELS = {
  block:   "Bloquer",
  review:  "Révision RSSI",
  warn:    "Avertissement",
  allow:   "Autoriser",
};

// ─── Composants de mise en page rapport ──────────────────────────────────────

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: "28px", pageBreakInside: "avoid" }}>
      <div style={{
        borderBottom: "2px solid #1e3a5f",
        paddingBottom: "6px",
        marginBottom: "14px",
      }}>
        <h2 style={{ fontSize: "14px", fontWeight: "700", color: "#1e3a5f", margin: 0, textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {title}
        </h2>
      </div>
      {children}
    </div>
  );
}

function SevBadge({ sev, count }) {
  if (!count) return null;
  const c = SEV_COLORS[sev] || SEV_COLORS.negligible;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "3px",
      background: c.bg, color: c.text,
      border: `1px solid ${c.badge}30`,
      borderRadius: "4px", padding: "1px 6px",
      fontSize: "11px", fontWeight: "600", marginRight: "4px",
    }}>
      {sev.toUpperCase().slice(0, 4)}: {count}
    </span>
  );
}

function StatusBadge({ status }) {
  const styles = {
    validated:       { bg: "#f0fdf4", color: "#166534", border: "#16a34a" },
    pending_review:  { bg: "#fff7ed", color: "#c2410c", border: "#ea580c" },
    blocked:         { bg: "#fef2f2", color: "#b91c1c", border: "#dc2626" },
    quarantined:     { bg: "#f5f3ff", color: "#5b21b6", border: "#7c3aed" },
    accepted_risk:   { bg: "#ecfdf5", color: "#065f46", border: "#059669" },
    exception:       { bg: "#eff6ff", color: "#1d4ed8", border: "#3b82f6" },
    upgrade_required:{ bg: "#faf5ff", color: "#6b21a8", border: "#9333ea" },
  };
  const s = styles[status] || { bg: "#f9fafb", color: "#374151", border: "#9ca3af" };
  return (
    <span style={{
      background: s.bg, color: s.color,
      border: `1px solid ${s.border}40`,
      borderRadius: "4px", padding: "2px 7px",
      fontSize: "10px", fontWeight: "600",
    }}>
      {STATUS_LABELS[status] || status}
    </span>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function SecurityReportPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const printRef = useRef();

  useEffect(() => {
    getSecurityReport()
      .then(setReport)
      .catch(() => setError("Impossible de charger le rapport. Vérifiez votre session."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", fontFamily: "sans-serif", color: "#6b7280" }}>
        Génération du rapport…
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", fontFamily: "sans-serif", color: "#dc2626" }}>
        {error}
      </div>
    );
  }

  const {
    generated_at, generated_by, cve_policy, summary,
    packages_with_cve, decisions, pending_review,
  } = report;

  const _sevs = ["critical", "high", "medium", "low", "negligible"];

  return (
    <>
      {/* Barre d'outils — masquée à l'impression */}
      <div className="no-print" style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 1000,
        background: "#1e3a5f", color: "white",
        padding: "10px 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        fontFamily: "system-ui, sans-serif", fontSize: "14px",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <span style={{ fontWeight: 600 }}>Rapport d'audit sécurité — repod</span>
          <span style={{ opacity: 0.6, fontSize: "12px" }}>Généré le {fmtDate(generated_at)} par {generated_by}</span>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            onClick={() => window.print()}
            style={{
              background: "white", color: "#1e3a5f",
              border: "none", borderRadius: "6px",
              padding: "7px 16px", fontWeight: 600, fontSize: "13px",
              cursor: "pointer", display: "flex", alignItems: "center", gap: "6px",
            }}
          >
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Télécharger PDF
          </button>
          <button
            onClick={() => window.close()}
            style={{
              background: "transparent", color: "rgba(255,255,255,0.7)",
              border: "1px solid rgba(255,255,255,0.3)", borderRadius: "6px",
              padding: "7px 14px", fontWeight: 500, fontSize: "13px", cursor: "pointer",
            }}
          >
            Fermer
          </button>
        </div>
      </div>

      {/* Corps du rapport */}
      <div ref={printRef} style={{
        fontFamily: "'Segoe UI', system-ui, -apple-system, sans-serif",
        fontSize: "12px",
        color: "#1f2937",
        background: "white",
        maxWidth: "900px",
        margin: "0 auto",
        padding: "72px 48px 48px",
        lineHeight: 1.5,
      }}>

        {/* En-tête du rapport */}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "flex-start",
          marginBottom: "36px",
          paddingBottom: "20px",
          borderBottom: "3px solid #1e3a5f",
        }}>
          <div>
            <div style={{ fontSize: "22px", fontWeight: "800", color: "#1e3a5f", letterSpacing: "-0.02em" }}>
              Rapport d'audit de sécurité
            </div>
            <div style={{ fontSize: "13px", color: "#6b7280", marginTop: "4px" }}>
              Dépôt APT privé — repod
            </div>
          </div>
          <div style={{ textAlign: "right", fontSize: "11px", color: "#6b7280" }}>
            <div><strong>Généré le :</strong> {fmtDate(generated_at)}</div>
            <div><strong>Par :</strong> {generated_by}</div>
            <div style={{ marginTop: "6px", background: "#f3f4f6", borderRadius: "4px", padding: "3px 8px", display: "inline-block" }}>
              CONFIDENTIEL
            </div>
          </div>
        </div>

        {/* Résumé exécutif */}
        <Section title="Résumé exécutif">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "12px", marginBottom: "16px" }}>
            {[
              { label: "Paquets total", value: summary.total_packages, color: "#1e3a5f" },
              { label: "Avec CVE détectées", value: summary.packages_scanned, color: "#ea580c" },
              { label: "Décisions RSSI", value: summary.decisions_count, color: "#059669" },
              { label: "En attente révision", value: summary.pending_count, color: summary.pending_count > 0 ? "#dc2626" : "#059669" },
            ].map(({ label, value, color }) => (
              <div key={label} style={{
                background: "#f9fafb", border: "1px solid #e5e7eb",
                borderRadius: "8px", padding: "12px 14px",
                borderTop: `3px solid ${color}`,
              }}>
                <div style={{ fontSize: "10px", color: "#6b7280", textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</div>
                <div style={{ fontSize: "24px", fontWeight: "800", color, marginTop: "4px" }}>{value}</div>
              </div>
            ))}
          </div>

          {/* CVE totaux */}
          <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
            {_sevs.map(sev => (
              <div key={sev} style={{
                background: SEV_COLORS[sev]?.bg || "#f9fafb",
                border: `1px solid ${SEV_COLORS[sev]?.badge || "#9ca3af"}30`,
                borderRadius: "8px", padding: "10px 14px", minWidth: "100px",
              }}>
                <div style={{ fontSize: "10px", fontWeight: "600", color: SEV_COLORS[sev]?.text || "#374151", textTransform: "uppercase" }}>
                  {sev}
                </div>
                <div style={{ fontSize: "20px", fontWeight: "800", color: SEV_COLORS[sev]?.text || "#374151" }}>
                  {summary.cve_totals[sev] || 0}
                </div>
              </div>
            ))}
          </div>
        </Section>

        {/* Politique CVE configurée */}
        {cve_policy && (
          <Section title="Politique CVE configurée">
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              <thead>
                <tr style={{ background: "#f3f4f6" }}>
                  <th style={{ padding: "7px 12px", textAlign: "left", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb" }}>Sévérité</th>
                  <th style={{ padding: "7px 12px", textAlign: "left", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb" }}>Action</th>
                  <th style={{ padding: "7px 12px", textAlign: "left", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb" }}>SLA</th>
                </tr>
              </thead>
              <tbody>
                {["critical", "high", "medium", "low", "negligible"].map(sev => (
                  <tr key={sev}>
                    <td style={{ padding: "6px 12px", border: "1px solid #e5e7eb" }}>
                      <SevBadge sev={sev} count={summary.cve_totals[sev] || 0} />
                    </td>
                    <td style={{ padding: "6px 12px", border: "1px solid #e5e7eb", fontWeight: "600" }}>
                      {POLICY_LABELS[cve_policy[sev]] || cve_policy[sev] || "—"}
                    </td>
                    <td style={{ padding: "6px 12px", border: "1px solid #e5e7eb", color: "#6b7280" }}>
                      {sev === "critical" ? (cve_policy.sla_critical_days === 0 ? "Immédiat" : `${cve_policy.sla_critical_days}j`) :
                       sev === "high" ? `${cve_policy.sla_high_days || 30}j` :
                       sev === "medium" ? `${cve_policy.sla_medium_days || 90}j` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        )}

        {/* Paquets en attente de révision */}
        {pending_review.length > 0 && (
          <Section title={<span style={{display:"inline-flex",alignItems:"center",gap:"6px"}}><svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>{`File de révision RSSI — ${pending_review.length} paquet(s) en attente`}</span>}>
            <div style={{ background: "#fff7ed", border: "1px solid #fdba74", borderRadius: "6px", padding: "10px 14px", marginBottom: "12px", fontSize: "11px", color: "#92400e" }}>
              Ces paquets ont été importés mais <strong>ne sont pas encore publiés dans le dépôt APT</strong>. Une décision RSSI est requise.
            </div>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              <thead>
                <tr style={{ background: "#f3f4f6" }}>
                  {["Paquet", "Version", "Distribution", "Statut", "CVE", "Importé le"].map(h => (
                    <th key={h} style={{ padding: "7px 10px", textAlign: "left", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {pending_review.map((p, i) => (
                  <tr key={i} style={{ background: i % 2 ? "#fff7ed" : "white" }}>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace", fontWeight: "600" }}>{p.name}</td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace" }}>{p.version}</td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb" }}>{p.distribution || "—"}</td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb" }}><StatusBadge status={p.status} /></td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb" }}>
                      {_sevs.map(s => <SevBadge key={s} sev={s} count={p.cve_counts?.[s]} />)}
                    </td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", color: "#6b7280" }}>{fmtDateShort(p.imported_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        )}

        {/* Paquets avec CVE */}
        {packages_with_cve.length > 0 && (
          <Section title={`Posture CVE — ${packages_with_cve.length} paquet(s) analysés`}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              <thead>
                <tr style={{ background: "#f3f4f6" }}>
                  {["Paquet", "Version", "Statut", "CRITICAL", "HIGH", "MEDIUM", "LOW", "KEV"].map(h => (
                    <th key={h} style={{ padding: "7px 10px", textAlign: h === "Paquet" || h === "Version" || h === "Statut" ? "left" : "center", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {packages_with_cve.map((p, i) => (
                  <tr key={i} style={{ background: i % 2 ? "#f9fafb" : "white" }}>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace", fontWeight: "600" }}>{p.name}</td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace", color: "#6b7280" }}>{p.version || "—"}</td>
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb" }}><StatusBadge status={p.status} /></td>
                    {["critical", "high", "medium", "low"].map(sev => {
                      const n = p.cve_counts[sev] || 0;
                      const c = SEV_COLORS[sev];
                      return (
                        <td key={sev} style={{
                          padding: "6px 10px", border: "1px solid #e5e7eb", textAlign: "center",
                          fontWeight: n > 0 ? "700" : "400",
                          color: n > 0 ? c.text : "#d1d5db",
                          background: n > 0 ? c.bg : "transparent",
                        }}>
                          {n || "·"}
                        </td>
                      );
                    })}
                    <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", textAlign: "center" }}>
                      {p.kev_count > 0 ? (
                        <span style={{ background: "#fef2f2", color: "#b91c1c", fontWeight: "700", borderRadius: "4px", padding: "1px 6px", fontSize: "10px", display:"inline-flex", alignItems:"center", gap:"3px" }}>
                          <svg width="10" height="10" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> {p.kev_count}
                        </span>
                      ) : "·"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>
        )}

        {/* Historique des décisions RSSI */}
        <Section title={`Historique des décisions RSSI — ${decisions.length} décision(s)`}>
          {decisions.length === 0 ? (
            <p style={{ color: "#9ca3af", fontStyle: "italic" }}>Aucune décision enregistrée.</p>
          ) : (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              <thead>
                <tr style={{ background: "#f3f4f6" }}>
                  {["Paquet", "Version", "Action", "Justification", "Décidé par", "Date", "Expire le"].map(h => (
                    <th key={h} style={{ padding: "7px 10px", textAlign: "left", fontWeight: "600", color: "#374151", border: "1px solid #e5e7eb", fontSize: "10px" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {decisions.map((d, i) => {
                  const sla = d.sla || {};
                  const expiredStyle = sla.expired ? { background: "#fef2f2" } : sla.warning ? { background: "#fff7ed" } : {};
                  return (
                    <tr key={i} style={{ background: i % 2 ? "#f9fafb" : "white", ...expiredStyle }}>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace", fontWeight: "600" }}>{d.package}</td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", fontFamily: "monospace", color: "#6b7280" }}>{d.version}</td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", whiteSpace: "nowrap" }}>
                        <span style={{
                          fontWeight: "600", fontSize: "10px",
                          color: d.action === "reject" ? "#b91c1c" :
                                 d.action === "accept_risk" ? "#065f46" :
                                 d.action === "exception" ? "#1d4ed8" : "#6b21a8",
                        }}>
                          {ACTION_LABELS[d.action] || d.action}
                        </span>
                      </td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", maxWidth: "200px", color: "#374151" }}>
                        {d.justification?.slice(0, 120)}{d.justification?.length > 120 ? "…" : ""}
                      </td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", color: "#6b7280", whiteSpace: "nowrap" }}>{d.decided_by}</td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", color: "#6b7280", whiteSpace: "nowrap" }}>{fmtDateShort(d.decided_at)}</td>
                      <td style={{ padding: "6px 10px", border: "1px solid #e5e7eb", whiteSpace: "nowrap" }}>
                        {d.expires_at ? (
                          <span style={{ color: sla.expired ? "#b91c1c" : sla.warning ? "#c2410c" : "#6b7280", fontWeight: sla.expired || sla.warning ? "700" : "400" }}>
                            {fmtDateShort(d.expires_at)}
                            {sla.expired && <svg width="12" height="12" style={{display:"inline",marginLeft:3}} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>}
                            {sla.warning && !sla.expired && ` (J-${sla.remaining_days})`}
                          </span>
                        ) : <span style={{ color: "#9ca3af" }}>Permanente</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Section>

        {/* Pied de page */}
        <div style={{
          marginTop: "40px", paddingTop: "16px",
          borderTop: "1px solid #e5e7eb",
          display: "flex", justifyContent: "space-between",
          fontSize: "10px", color: "#9ca3af",
        }}>
          <span>repod — Gestionnaire de dépôt APT privé</span>
          <span>Rapport généré le {fmtDate(generated_at)} — CONFIDENTIEL</span>
        </div>
      </div>

      {/* CSS impression */}
      <style>{`
        @media print {
          .no-print { display: none !important; }
          body { margin: 0; }
          @page { margin: 15mm 12mm; size: A4; }
        }
        @media screen {
          body { background: #e5e7eb; }
        }
      `}</style>
    </>
  );
}
