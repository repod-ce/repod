import { useState, useEffect, useCallback, useRef } from "react";
import toast from "react-hot-toast";
import { listArtifacts, deleteArtifact, syncIndex, getArtifact, resolveDependencies, getApiBaseUrl, getPackageCve, getPackageDecision, getAuditLogs, getDistributions } from "../api";
import Paginator from "./Paginator";

const REPO_URL     = import.meta.env.REACT_APP_REPO_URL     || "http://localhost:80";
const API_URL      = getApiBaseUrl();

function formatBytes(bytes) {
  if (!bytes) return "–";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function formatDate(iso) {
  if (!iso) return "–";
  return new Date(iso).toLocaleDateString("fr-FR", {
    day: "2-digit", month: "short", year: "numeric",
  });
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    () => toast.success("Commande copiée"),
    () => toast.error("Impossible de copier")
  );
}

function CveBadge({ cve }) {
  if (!cve) {
    return <span className="text-xs text-gray-300 font-mono">—</span>;
  }
  if (cve.critical > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700 border border-red-200">
        <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
        {cve.critical} CRITICAL
      </span>
    );
  }
  if (cve.high > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-orange-100 text-orange-700 border border-orange-200">
        <span className="w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0" />
        {cve.high} HIGH
      </span>
    );
  }
  if (cve.medium > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-yellow-100 text-yellow-700 border border-yellow-200">
        <span className="w-1.5 h-1.5 rounded-full bg-yellow-500 shrink-0" />
        {cve.medium} MEDIUM
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700 border border-green-200">
      <span className="w-1.5 h-1.5 rounded-full bg-green-500 shrink-0" />
      Clean
    </span>
  );
}

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");
  const styles = {
    info: "text-gray-300", success: "text-green-400",
    error: "text-red-400", warning: "text-yellow-400",
    skip: "text-gray-500", done: "text-blue-400 font-semibold",
  };
  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

// ─── Panel : Résoudre les dépendances manquantes ──────────────────────────────

function ResolvePanel({ pkg, onClose, onResolved }) {
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [hasError, setHasError] = useState(false);
  const logsRef = useRef(null);
  const missing = pkg.deps_missing || [];

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  useEffect(() => {
    if (done && !hasError) {
      setTimeout(() => { onResolved(false); }, 1500);
    }
  }, [done, hasError, onResolved]);

  const handleImport = () => {
    if (missing.length === 0) return;
    setLogs([]);
    setDone(false);
    setHasError(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    fetch(`${API_URL}/import/batch`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ packages: missing, group: pkg.name }),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur inconnue" }));
        setLogs([`error|${err.detail}`]);
        setHasError(true);
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let streamHasError = false;
      while (true) {
        const { value, done: streamDone } = await reader.read();
        if (streamDone) break;
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop();
        for (const part of parts) {
          const dataLine = part.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          const payload = dataLine.slice(5).trim();
          setLogs((prev) => [...prev, payload]);
          if (payload.startsWith("error|")) { streamHasError = true; setHasError(true); }
          if (payload.startsWith("done|")) { setDone(true); setRunning(false); }
        }
      }
      setRunning(false);
    }).catch((e) => {
      setLogs([`error|${e.message}`]);
      setHasError(true);
      setRunning(false);
    });
  };

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={!running ? onClose : undefined} />
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-white shadow-2xl flex flex-col overflow-hidden">

        {/* En-tête */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-amber-100 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-amber-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h2 className="font-semibold text-gray-900">Résoudre les dépendances</h2>
              <p className="text-xs text-gray-400 font-mono">{pkg.name}</p>
            </div>
          </div>
          <button onClick={onClose} disabled={running}
            className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors disabled:opacity-40">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-5">

          {/* Bannière */}
          <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
            <p className="text-sm font-semibold text-amber-800">
              {missing.length} dépendance(s) manquante(s) dans le dépôt
            </p>
            <p className="text-xs text-amber-600 mt-0.5">
              Ces paquets sont requis par <span className="font-mono font-semibold">{pkg.name}</span> mais absents du dépôt.
            </p>
          </div>

          {/* Liste des deps manquantes */}
          <div>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
              Dépendances à importer
            </h3>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              <ul className="divide-y divide-gray-100">
                {missing.map((dep) => (
                  <li key={dep} className="flex items-center gap-3 px-4 py-3 bg-white">
                    <div className="w-5 h-5 rounded-full bg-red-100 flex items-center justify-center shrink-0">
                      <svg className="w-3 h-3 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </div>
                    <span className="font-mono text-sm text-gray-800">{dep}</span>
                    <span className="ml-auto text-xs text-red-500 font-medium">Manquant</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Bouton d'import */}
          {!done && (
            <button
              onClick={handleImport}
              disabled={running || missing.length === 0}
              className="w-full flex items-center justify-center gap-2 py-3 bg-blue-600 text-white
                         text-sm font-medium rounded-xl hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {running ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  Import en cours...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
                  </svg>
                  Importer automatiquement ({missing.length} paquet{missing.length > 1 ? "s" : ""})
                </>
              )}
            </button>
          )}

          {done && !hasError && (
            <div className="flex items-center gap-3 bg-green-50 border border-green-200 rounded-xl px-4 py-3">
              <svg className="w-5 h-5 text-green-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <p className="text-sm font-semibold text-green-800">Import terminé — mise à jour en cours…</p>
            </div>
          )}
          {done && hasError && (
            <div className="bg-red-50 border border-red-200 rounded-xl px-4 py-3">
              <div className="flex items-center gap-3">
                <svg className="w-5 h-5 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
                <p className="text-sm font-semibold text-red-800 flex-1">Des erreurs sont survenues — certains paquets n'ont pas pu être importés.</p>
              </div>
              <button
                onClick={() => onResolved(true)}
                className="mt-3 w-full py-2 text-sm font-medium text-red-700 border border-red-300 rounded-lg hover:bg-red-100 transition-colors"
              >
                Fermer
              </button>
            </div>
          )}

          {/* Logs SSE */}
          {logs.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                Progression
              </h3>
              <div className="border border-gray-800 rounded-xl bg-gray-900 p-4">
                <div ref={logsRef} className="max-h-56 overflow-y-auto space-y-0.5">
                  {logs.map((line, i) => <LogLine key={i} line={line} />)}
                </div>
              </div>
            </div>
          )}

          {/* Avertissement index */}
          {!running && logs.length === 0 && (
            <p className="text-xs text-gray-400 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2.5">
              Les paquets seront téléchargés depuis l'index APT synchronisé.
              Si l'index n'est pas à jour, allez dans <strong>Importer → Synchronisation</strong>.
            </p>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Panneau de détail / inspection ──────────────────────────────────────────

const SEV_COLOR = { critical:"#DC2626", high:"#EA580C", medium:"#CA8A04", low:"#16A34A", negligible:"#94A3B8" };
const SEV_BG    = { critical:"#FEF2F2", high:"#FFF7ED", medium:"#FEFCE8", low:"#F0FDF4", negligible:"#F8FAFC" };
const DECISION_COLOR = { accept_risk:"#16A34A", exception:"#2563EB", reject:"#DC2626", upgrade_required:"#0891B2" };
const DECISION_LABEL = { accept_risk:"Risque accepté", exception:"Exception", reject:"Rejeté", upgrade_required:"Upgrade requis" };

function InspectPanel({ pkg, onClose }) {
  const [tab, setTab]         = useState("info");
  const [detail, setDetail]   = useState(null);
  const [deps, setDeps]       = useState(null);
  const [cve, setCve]         = useState(null);
  const [decision, setDecision] = useState(null);
  const [auditHistory, setAudit] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const version = pkg.latest_version || pkg.version || "";
    const arch    = pkg.arch || "amd64";
    Promise.all([
      getArtifact(pkg.name).catch(() => null),
      resolveDependencies(pkg.name).catch(() => null),
      version ? getPackageCve(pkg.name, version, arch).catch(() => null) : Promise.resolve(null),
      version ? getPackageDecision(pkg.name, version, arch).catch(() => null) : Promise.resolve(null),
      getAuditLogs({ package: pkg.name, limit: 50 }).catch(() => ({ logs: [] })),
    ]).then(([d, r, c, dec, audit]) => {
      setDetail(d);
      setDeps(r);
      setCve(c);
      setDecision(dec);
      setAudit(audit?.items || audit?.logs || []);
    }).finally(() => setLoading(false));
  }, [pkg.name, pkg.latest_version, pkg.version, pkg.arch]);

  const latest          = detail?.info?.latest;
  const verInfo         = latest ? detail?.info?.versions?.[latest] : null;
  const allDeps         = deps?.dependencies ?? [];
  const missing         = deps?.missing ?? [];
  const satisfied       = deps?.all_satisfied ?? true;
  const validationSteps = detail?.validation_steps ?? [];
  const cveList         = cve?.cve_results ?? cve?.vulnerabilities ?? [];
  const cveSummary      = cve?.summary ?? {};

  const TABS = [
    { id: "info",     label: "Informations" },
    { id: "cve",      label: `CVE ${cveList.length > 0 ? `(${cveList.length})` : ""}` },
    { id: "decision", label: "Décision RSSI" },
    { id: "history",  label: `Historique ${auditHistory.length > 0 ? `(${auditHistory.length})` : ""}` },
  ];

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      <div className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl bg-white shadow-2xl flex flex-col overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-blue-100 rounded-lg flex items-center justify-center">
              <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10" />
              </svg>
            </div>
            <div>
              <h2 className="font-mono font-semibold text-gray-900">{pkg.name}</h2>
              <p className="text-xs text-gray-400">{pkg.latest_version} · {pkg.arch} · {pkg.distribution || "jammy"}</p>
            </div>
          </div>
          <button onClick={onClose}
            className="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-200 px-6 shrink-0 bg-gray-50">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-4 py-3 text-xs font-semibold border-b-2 transition-colors ${
                tab === t.id
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}>
              {t.label}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-gray-400 text-sm">Chargement...</div>
        ) : (
          <div className="flex-1 overflow-y-auto">

            {/* ── Onglet : Informations ── */}
            {tab === "info" && (
              <>
                <div className={`mx-4 mt-4 rounded-xl px-4 py-3 flex items-center gap-3 ${
                  satisfied ? "bg-green-50 border border-green-200" : "bg-amber-50 border border-amber-200"
                }`}>
                  <div>
                    <p className={`text-sm font-semibold ${satisfied ? "text-green-800" : "text-amber-800"}`}>
                      {satisfied ? "Toutes les dépendances sont présentes" : `${missing.length} dépendance(s) manquante(s)`}
                    </p>
                    {!satisfied && <p className="text-xs text-amber-700 mt-0.5 font-mono">{missing.join(", ")}</p>}
                  </div>
                </div>

                <section className="px-4 mt-5">
                  <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Métadonnées</h3>
                  <div className="bg-white border border-gray-200 rounded-xl divide-y divide-gray-100">
                    {[
                      { label: "Nom",          value: pkg.name },
                      { label: "Version",      value: pkg.latest_version || "–" },
                      { label: "Architecture", value: pkg.arch || "–" },
                      { label: "Distribution", value: pkg.distribution || "–" },
                      { label: "Taille",       value: formatBytes(pkg.size_bytes) },
                      { label: "Section",      value: pkg.section || "–" },
                      { label: "Importé le",   value: formatDate(pkg.imported_at) },
                      { label: "Importé par",  value: pkg.imported_by || "–" },
                      { label: "Méthode",      value: pkg.import_method || "–" },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex items-center px-4 py-2.5 gap-4">
                        <span className="text-xs text-gray-500 w-28 shrink-0">{label}</span>
                        <span className="text-sm text-gray-800 font-mono truncate">{value}</span>
                      </div>
                    ))}
                    {pkg.description && (
                      <div className="flex items-start px-4 py-2.5 gap-4">
                        <span className="text-xs text-gray-500 w-28 shrink-0 mt-0.5">Description</span>
                        <span className="text-sm text-gray-800">{pkg.description}</span>
                      </div>
                    )}
                  </div>
                </section>

                {verInfo?.sha256 && (
                  <section className="px-4 mt-5">
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Intégrité</h3>
                    <div className="bg-white border border-gray-200 rounded-xl px-4 py-3 flex items-start gap-3">
                      <div className="min-w-0 flex-1">
                        <p className="text-xs text-gray-500 mb-0.5">SHA-256</p>
                        <p className="text-xs font-mono text-gray-700 break-all">{verInfo.sha256}</p>
                      </div>
                      <button onClick={() => copyToClipboard(verInfo.sha256)} className="shrink-0 p-1 text-gray-400 hover:text-gray-600" title="Copier">
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                  </section>
                )}

                {validationSteps.length > 0 && (
                  <section className="px-4 mt-5 mb-6">
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Validation à l'import</h3>
                    <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                      <ul className="divide-y divide-gray-100">
                        {validationSteps.map((step, i) => {
                          const isWarning = step.warning && !step.passed;
                          const labels = { format:"Format du paquet", provenance:"Provenance SHA256", antivirus:"Antivirus ClamAV", gpg:"Signature GPG", checksum:"Checksum", dependencies:"Dépendances" };
                          return (
                            <li key={i} className={`flex items-start gap-3 px-4 py-3 ${!step.passed && !isWarning ? "bg-red-50/50" : isWarning ? "bg-amber-50/50" : ""}`}>
                              <svg className={`w-4 h-4 shrink-0 mt-0.5 ${step.passed || isWarning ? isWarning ? "text-amber-500" : "text-green-500" : "text-red-500"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                {step.passed ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />}
                              </svg>
                              <div className="min-w-0 flex-1">
                                <p className="text-xs font-semibold text-gray-700">{labels[step.name] || step.name}</p>
                                <p className="text-xs text-gray-500 mt-0.5">{step.message}</p>
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  </section>
                )}

                <section className="px-4 mt-5 mb-6">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Dépendances</h3>
                    <span className="text-xs text-gray-400">{allDeps.length === 0 ? "Aucune" : `${allDeps.length - missing.length}/${allDeps.length} disponibles`}</span>
                  </div>
                  {allDeps.length === 0 ? (
                    <div className="bg-white border border-gray-200 rounded-xl px-4 py-6 text-center text-sm text-gray-400">Aucune dépendance déclarée</div>
                  ) : (
                    <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
                      <ul className="divide-y divide-gray-100">
                        {allDeps.map((dep) => {
                          const present = dep.available_internally !== false;
                          return (
                            <li key={dep.name} className={`flex items-center justify-between px-4 py-3 ${!present ? "bg-red-50/60" : ""}`}>
                              <div className="flex items-center gap-2.5 min-w-0">
                                <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${present ? "bg-green-100" : "bg-red-100"}`}>
                                  <svg className={`w-3 h-3 ${present ? "text-green-600" : "text-red-500"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    {present ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />}
                                  </svg>
                                </div>
                                <div className="min-w-0">
                                  <p className="font-mono text-sm text-gray-800 truncate">{dep.name}</p>
                                  {dep.version_constraint && <p className="text-xs text-gray-400">{dep.version_constraint}</p>}
                                </div>
                              </div>
                              <span className={`text-xs font-medium shrink-0 ml-3 ${present ? "text-green-600" : "text-red-500"}`}>{present ? "Dans le dépôt" : "Manquante"}</span>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  )}
                </section>
              </>
            )}

            {/* ── Onglet : CVE ── */}
            {tab === "cve" && (
              <section className="px-4 py-5">
                {/* Résumé */}
                {Object.keys(cveSummary).length > 0 && (
                  <div className="flex gap-2 mb-4 flex-wrap">
                    {["critical","high","medium","low","negligible"].map(sev => cveSummary[sev] > 0 && (
                      <span key={sev} style={{ background: SEV_BG[sev], color: SEV_COLOR[sev], border:`1px solid ${SEV_COLOR[sev]}30` }}
                        className="px-3 py-1 rounded-full text-xs font-bold">
                        {cveSummary[sev]} {sev.toUpperCase()}
                      </span>
                    ))}
                  </div>
                )}

                {cveList.length === 0 ? (
                  <div className="bg-green-50 border border-green-200 rounded-xl px-4 py-8 text-center">
                    <p className="text-green-700 font-semibold text-sm">Aucune CVE détectée</p>
                    <p className="text-green-600 text-xs mt-1">Ce paquet est propre selon Grype</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {cveList.map((vuln, i) => {
                      const sev = (vuln.severity || "unknown").toLowerCase();
                      return (
                        <div key={i} className="bg-white border border-gray-200 rounded-xl px-4 py-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="font-mono text-sm font-bold text-gray-900">{vuln.id || vuln.cve_id}</span>
                                <span style={{ background: SEV_BG[sev]||"#F8FAFC", color: SEV_COLOR[sev]||"#64748B" }}
                                  className="px-2 py-0.5 rounded text-xs font-bold">{sev.toUpperCase()}</span>
                                {vuln.kev && <span className="px-2 py-0.5 rounded text-xs font-bold bg-red-100 text-red-700">KEV</span>}
                              </div>
                              <p className="text-xs text-gray-600">{vuln.package} {vuln.installed_version && `(${vuln.installed_version})`}</p>
                              {vuln.fix_version && <p className="text-xs text-green-700 mt-0.5">Fix : {vuln.fix_version}</p>}
                              {vuln.epss_percent > 0 && <p className="text-xs text-gray-400 mt-0.5">EPSS : {vuln.epss_percent}%</p>}
                            </div>
                            {vuln.cvss_score && (
                              <span className="shrink-0 text-sm font-bold text-gray-700">CVSS {vuln.cvss_score}</span>
                            )}
                          </div>
                          {vuln.description && (
                            <p className="text-xs text-gray-500 mt-2 line-clamp-2">{vuln.description}</p>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            )}

            {/* ── Onglet : Décision RSSI ── */}
            {tab === "decision" && (
              <section className="px-4 py-5">
                {!decision?.decision ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl px-4 py-8 text-center">
                    <p className="text-gray-600 font-semibold text-sm">Aucune décision RSSI enregistrée</p>
                    <p className="text-gray-400 text-xs mt-1">Rendez-vous dans la page Sécurité pour traiter ce paquet</p>
                  </div>
                ) : (
                  <>
                    <div style={{ background: `${DECISION_COLOR[decision.decision.action] || "#64748B"}15`, border: `1px solid ${DECISION_COLOR[decision.decision.action] || "#64748B"}30` }}
                      className="rounded-xl px-4 py-4 mb-4">
                      <div className="flex items-center gap-3">
                        <span style={{ background: DECISION_COLOR[decision.decision.action] || "#64748B", color:"#fff" }}
                          className="px-3 py-1 rounded-lg text-sm font-bold">
                          {DECISION_LABEL[decision.decision.action] || decision.decision.action}
                        </span>
                        {decision.sla?.days_remaining != null && (
                          <span className={`text-xs font-medium ${decision.sla.days_remaining < 7 ? "text-red-600" : "text-gray-600"}`}>
                            {decision.sla.days_remaining > 0 ? `Expire dans ${decision.sla.days_remaining}j` : "Expiré"}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="bg-white border border-gray-200 rounded-xl divide-y divide-gray-100">
                      {[
                        { label: "Décidé par",   value: decision.decision.decided_by },
                        { label: "Date",         value: decision.decision.decided_at ? new Date(decision.decision.decided_at).toLocaleString("fr-FR") : "–" },
                        { label: "Expire le",    value: decision.decision.expires_at ? new Date(decision.decision.expires_at).toLocaleDateString("fr-FR") : "Jamais" },
                        { label: "Justification", value: decision.decision.justification || "—" },
                      ].map(({ label, value }) => (
                        <div key={label} className="flex items-start px-4 py-3 gap-4">
                          <span className="text-xs text-gray-500 w-28 shrink-0 mt-0.5">{label}</span>
                          <span className="text-sm text-gray-800">{value}</span>
                        </div>
                      ))}
                    </div>
                    {decision.sla && (
                      <div className={`mt-3 px-4 py-2.5 rounded-xl text-xs font-medium ${
                        decision.sla.status === "expired" ? "bg-red-50 text-red-700 border border-red-200" :
                        decision.sla.status === "expiring_soon" ? "bg-amber-50 text-amber-700 border border-amber-200" :
                        "bg-green-50 text-green-700 border border-green-200"
                      }`}>
                        SLA : {decision.sla.status === "expired" ? "Expiré — révision requise" :
                               decision.sla.status === "expiring_soon" ? `Expire dans ${decision.sla.days_remaining} jour(s)` :
                               decision.sla.status === "no_sla" ? "Pas de SLA défini" :
                               `Valide — ${decision.sla.days_remaining} jour(s) restant(s)`}
                      </div>
                    )}
                  </>
                )}
              </section>
            )}

            {/* ── Onglet : Historique ── */}
            {tab === "history" && (
              <section className="px-4 py-5">
                {auditHistory.length === 0 ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-xl px-4 py-8 text-center">
                    <p className="text-gray-500 text-sm">Aucun historique disponible</p>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {auditHistory.map((entry, i) => {
                      const resultColor = entry.result === "SUCCESS" ? "#16A34A" : entry.result === "FAILURE" ? "#DC2626" : "#CA8A04";
                      return (
                        <div key={i} className="bg-white border border-gray-100 rounded-xl px-4 py-3 flex items-start gap-3">
                          <div className="w-2 h-2 rounded-full shrink-0 mt-1.5" style={{ background: resultColor }} />
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-bold text-gray-700">{entry.action}</span>
                              <span className="text-xs text-gray-400">par {entry.user}</span>
                              <span className="text-xs text-gray-300">·</span>
                              <span className="text-xs text-gray-400">{entry.timestamp ? new Date(entry.timestamp).toLocaleString("fr-FR") : "–"}</span>
                            </div>
                            {entry.detail && <p className="text-xs text-gray-500 mt-0.5 truncate">{entry.detail}</p>}
                          </div>
                          <span className="shrink-0 text-xs font-semibold" style={{ color: resultColor }}>{entry.result}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>
            )}
          </div>
        )}
      </div>
    </>
  );
}

// ─── Composant principal ──────────────────────────────────────────────────────

// Couleurs par codename de distribution (APT + RPM)
const DISTRIB_COLORS = {
  // APT — Debian / Ubuntu
  jammy:           "bg-orange-100 text-orange-700",
  noble:           "bg-green-100 text-green-700",
  focal:           "bg-gray-100  text-gray-600",
  bookworm:        "bg-red-100   text-red-700",
  bullseye:        "bg-red-100   text-red-600",
  buster:          "bg-red-50    text-red-500",
  // RPM — AlmaLinux
  almalinux8:      "bg-blue-100  text-blue-700",
  almalinux9:      "bg-blue-100  text-blue-700",
  // RPM — Rocky Linux
  rocky8:          "bg-emerald-100 text-emerald-700",
  rocky9:          "bg-emerald-100 text-emerald-700",
  // RPM — CentOS Stream
  "centos-stream9": "bg-purple-100 text-purple-700",
  "centos-stream8": "bg-purple-100 text-purple-600",
  // RPM — Oracle Linux
  oraclelinux8:    "bg-red-100   text-red-800",
  oraclelinux9:    "bg-red-100   text-red-800",
  // RPM — Fedora
  fedora:          "bg-indigo-100 text-indigo-700",
  fedora42:        "bg-indigo-100 text-indigo-700",
  // RPM — openSUSE
  "opensuse-leap-15.6":   "bg-teal-100 text-teal-700",
  "opensuse-tumbleweed":  "bg-teal-100 text-teal-600",
};

// Fallback statique si l'API distributions n'est pas disponible
const DISTRIB_TABS_FALLBACK = [
  { id: "all",       label: "Toutes",               group: null   },
  // APT
  { id: "jammy",     label: "Jammy 22.04",           group: "apt"  },
  { id: "noble",     label: "Noble 24.04",           group: "apt"  },
  { id: "focal",     label: "Focal 20.04",           group: "apt"  },
  { id: "bookworm",  label: "Bookworm 12",           group: "apt"  },
  // RPM — RHEL family
  { id: "almalinux9",   label: "AlmaLinux 9",        group: "rpm"  },
  { id: "almalinux8",   label: "AlmaLinux 8",        group: "rpm"  },
  { id: "rocky9",       label: "Rocky 9",            group: "rpm"  },
  { id: "rocky8",       label: "Rocky 8",            group: "rpm"  },
  { id: "centos-stream9", label: "CentOS Stream 9",  group: "rpm"  },
  { id: "oraclelinux9", label: "Oracle Linux 9",     group: "rpm"  },
  { id: "fedora42",     label: "Fedora 42",          group: "rpm"  },
  // RPM — openSUSE
  { id: "opensuse-leap-15.6",   label: "Leap 15.6",       group: "zypper" },
  { id: "opensuse-tumbleweed",  label: "Tumbleweed",       group: "zypper" },
];

/** Retourne la commande d'installation selon le format du paquet */
function getInstallCmd(pkg) {
  const distrib = (pkg.distribution || "").toLowerCase();
  const file    = (pkg.filename    || "").toLowerCase();
  if (file.endsWith(".rpm")) {
    if (distrib.startsWith("opensuse") || distrib.startsWith("suse")) {
      return `sudo zypper install ${pkg.name}`;
    }
    return `sudo dnf install ${pkg.name}`;
  }
  return `sudo apt install ${pkg.name}`;
}

const PER_PAGE = 50;

export default function PackageList() {
  const [packages, setPackages]           = useState([]);
  const [filterInput, setFilterInput]     = useState("");   // saisie immédiate
  const [filter, setFilter]               = useState("");   // valeur debounced → envoyée au backend
  const [distribFilter, setDistribFilter] = useState("all");
  const [distribTabs, setDistribTabs]     = useState(DISTRIB_TABS_FALLBACK);
  const [page, setPage]                   = useState(1);
  const [pagination, setPagination]       = useState({ total: 0, pages: 1 });
  const [loading, setLoading]             = useState(true);
  const [deleting, setDeleting]           = useState("");
  const [syncing, setSyncing]             = useState(false);
  const [inspecting, setInspecting]       = useState(null);
  const [resolving, setResolving]         = useState(null);

  // Charge les distributions depuis l'API pour construire les onglets de filtre
  useEffect(() => {
    getDistributions()
      .then((data) => {
        const distList = Array.isArray(data) ? data : (data?.distributions ?? []);
        if (distList.length === 0) return; // garde le fallback statique
        const tabs = [{ id: "all", label: "Toutes", group: null }];
        distList.forEach((d) => {
          tabs.push({
            id:    d.codename,
            label: d.label || d.codename,
            group: d.format || "apt",
          });
        });
        setDistribTabs(tabs);
      })
      .catch(() => { /* conserve le fallback statique */ });
  }, []);

  // Debounce la saisie — ne recharge que 350 ms après la dernière frappe
  useEffect(() => {
    const t = setTimeout(() => {
      setFilter(filterInput);
      setPage(1);   // retour page 1 à chaque nouveau terme
    }, 350);
    return () => clearTimeout(t);
  }, [filterInput]);

  const fetchPackages = useCallback(() => {
    setLoading(true);
    listArtifacts(page, PER_PAGE, filter, distribFilter !== "all" ? distribFilter : "")
      .then((data) => {
        setPackages(data.items || []);
        setPagination({ total: data.total || 0, pages: data.pages || 1 });
      })
      .catch(() => toast.error("Impossible de charger les paquets"))
      .finally(() => setLoading(false));
  }, [page, filter, distribFilter]);

  useEffect(() => { fetchPackages(); }, [fetchPackages]);

  const handleDistribChange = (id) => {
    setDistribFilter(id);
    setPage(1);
  };

  const handleDelete = async (name) => {
    if (!window.confirm(`Supprimer ${name} du dépôt ?`)) return;
    setDeleting(name);
    try {
      await deleteArtifact(name);
      toast.success(`${name} supprimé`);
      if (inspecting?.name === name) setInspecting(null);
      fetchPackages();
    } catch {
      toast.error(`Impossible de supprimer ${name}`);
    } finally {
      setDeleting("");
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await syncIndex();
      toast.success(`Index synchronisé — ${result.packages_indexed} paquet(s)`);
      setPage(1);
      fetchPackages();
    } catch {
      toast.error("Échec de la synchronisation");
    } finally {
      setSyncing(false);
    }
  };

  const handleResolved = useCallback((hadErrors) => {
    setResolving(null);
    fetchPackages();
    if (hadErrors) {
      toast.error("Des erreurs sont survenues — certains paquets n'ont pas pu être importés.");
    } else {
      toast.success("Dépendances importées — liste mise à jour");
    }
  }, [fetchPackages]);

  // Les paquets affichés sont directement ceux retournés par le backend (déjà filtrés + paginés)
  const visible = packages;

  return (
    <>
      {resolving && (
        <ResolvePanel
          pkg={resolving}
          onClose={() => setResolving(null)}
          onResolved={handleResolved}
        />
      )}
      {inspecting && !resolving && (
        <InspectPanel pkg={inspecting} onClose={() => setInspecting(null)} />
      )}

      <div className="space-y-6 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Paquets disponibles</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              {pagination.total} paquet{pagination.total !== 1 ? "s" : ""} — .deb (apt) et .rpm (dnf / zypper)
            </p>
          </div>
          <button onClick={handleSync} disabled={syncing}
            className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 border rounded-lg
                       hover:bg-gray-50 disabled:opacity-40 transition-colors">
            <svg className={`w-4 h-4 ${syncing ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {syncing ? "Sync..." : "Sync index"}
          </button>
        </div>

        <div className="relative">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
            fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0" />
          </svg>
          <input type="text" placeholder="Rechercher un paquet..." value={filterInput}
            onChange={(e) => setFilterInput(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 border border-gray-300 rounded-lg text-sm
                       focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white" />
        </div>

        {/* Filtre par distribution */}
        <div className="flex items-center gap-2">
          <label htmlFor="distrib-filter" className="text-xs font-medium text-gray-500 shrink-0">
            Distribution
          </label>
          <select
            id="distrib-filter"
            value={distribFilter}
            onChange={(e) => handleDistribChange(e.target.value)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-700
                       cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="all">Toutes ({pagination.total})</option>
            {(() => {
              const GROUP_LABELS = {
                apt: "APT (.deb)", rpm: "RPM (.rpm)", apk: "APK (Alpine)", zypper: "Zypper",
              };
              const groups = [...new Set(
                distribTabs.filter((t) => t.id !== "all").map((t) => t.group || "apt")
              )];
              return groups.map((group) => {
                const tabs = distribTabs.filter((t) => t.id !== "all" && (t.group || "apt") === group);
                return (
                  <optgroup key={group} label={GROUP_LABELS[group] || group}>
                    {tabs.map((tab) => (
                      <option key={tab.id} value={tab.id}>{tab.label}</option>
                    ))}
                  </optgroup>
                );
              });
            })()}
          </select>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
          {loading ? (
            <div className="p-10 text-center text-gray-400 text-sm">Chargement...</div>
          ) : visible.length === 0 ? (
            <div className="p-10 text-center text-gray-400 text-sm">
              {filter ? "Aucun paquet ne correspond." : "Le dépôt est vide."}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-xs text-gray-500 uppercase tracking-wider">
                  <th className="text-left px-5 py-3 font-semibold">Paquet</th>
                  <th className="text-left px-4 py-3 font-semibold">Version</th>
                  <th className="text-left px-4 py-3 font-semibold hidden md:table-cell">Arch</th>
                  <th className="text-left px-4 py-3 font-semibold hidden lg:table-cell">Taille</th>
                  <th className="text-left px-4 py-3 font-semibold hidden lg:table-cell">Importé le</th>
                  <th className="text-left px-4 py-3 font-semibold">Statut</th>
                  <th className="text-left px-4 py-3 font-semibold hidden lg:table-cell">CVE</th>
                  <th className="px-4 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {visible.map((pkg) => {
                  // pool accessible via l'APT nginx pour .deb et .rpm
                  const pkgUrl      = pkg.filename ? `${REPO_URL}/repos/pool/${pkg.filename}` : null;
                  const installCmd  = getInstallCmd(pkg);
                  const isInspecting = inspecting?.name === pkg.name;
                  const isResolving  = resolving?.name === pkg.name;
                  const hasMissing   = pkg.deps_missing?.length > 0;

                  return (
                    <tr key={pkg.name}
                      className={`transition-colors ${
                        isResolving ? "bg-amber-50" : isInspecting ? "bg-blue-50" : "hover:bg-gray-50"
                      }`}>

                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2.5">
                          <div className="w-7 h-7 bg-blue-100 rounded-md flex items-center justify-center shrink-0">
                            <svg className="w-3.5 h-3.5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10" />
                            </svg>
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="font-mono font-medium text-gray-900">{pkg.name}</p>
                              {pkg.distribution && (
                                <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${DISTRIB_COLORS[pkg.distribution] || "bg-gray-100 text-gray-600"}`}>
                                  {pkg.distribution}
                                </span>
                              )}
                            </div>
                            {pkg.description && (
                              <p className="text-xs text-gray-400 truncate max-w-xs">{pkg.description}</p>
                            )}
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <span className="font-mono text-gray-700">{pkg.latest_version || "–"}</span>
                        {pkg.versions?.length > 1 && (
                          <span className="ml-1 text-xs text-gray-400">(+{pkg.versions.length - 1})</span>
                        )}
                      </td>

                      <td className="px-4 py-3.5 hidden md:table-cell">
                        <span className="px-2 py-0.5 bg-gray-100 rounded text-xs text-gray-600 font-mono">
                          {pkg.arch}
                        </span>
                      </td>

                      <td className="px-4 py-3.5 text-gray-500 hidden lg:table-cell">
                        {formatBytes(pkg.size_bytes)}
                      </td>

                      <td className="px-4 py-3.5 text-gray-500 hidden lg:table-cell">
                        {formatDate(pkg.imported_at)}
                      </td>

                      {/* Statut — cliquable si deps manquantes */}
                      <td className="px-4 py-3.5">
                        {hasMissing ? (
                          <button
                            onClick={() => setResolving(isResolving ? null : pkg)}
                            title={`Manquants : ${pkg.deps_missing.join(", ")}`}
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium
                                        transition-colors cursor-pointer ${
                              isResolving
                                ? "bg-amber-300 text-amber-900"
                                : "bg-amber-100 text-amber-700 hover:bg-amber-200"
                            }`}
                          >
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                            {pkg.deps_missing.length} dep{pkg.deps_missing.length > 1 ? "s" : ""} manquante{pkg.deps_missing.length > 1 ? "s" : ""}
                          </button>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-green-100 text-green-700 rounded-full text-xs font-medium">
                            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                            </svg>
                            Disponible
                          </span>
                        )}
                      </td>

                      {/* CVE */}
                      <td className="px-4 py-3.5 hidden lg:table-cell">
                        <CveBadge cve={pkg.cve_summary} />
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3.5">
                        <div className="flex items-center justify-end gap-1.5">

                          {/* Inspecter */}
                          <button
                            onClick={() => setInspecting(isInspecting ? null : pkg)}
                            className={`p-2 rounded-lg transition-colors border ${
                              isInspecting
                                ? "bg-blue-600 text-white border-blue-600"
                                : "text-gray-500 border-gray-200 hover:border-blue-400 hover:text-blue-600 hover:bg-blue-50"
                            }`}
                            title="Inspecter"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                          </button>

                          {/* Résoudre (deps manquantes) ou Copier la commande d'installation */}
                          {hasMissing ? (
                            <button
                              onClick={() => setResolving(isResolving ? null : pkg)}
                              className={`p-2 rounded-lg transition-colors border ${
                                isResolving
                                  ? "bg-amber-500 text-white border-amber-500"
                                  : "text-amber-600 border-amber-200 hover:bg-amber-50 hover:border-amber-400"
                              }`}
                              title="Résoudre les dépendances manquantes"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10" />
                              </svg>
                            </button>
                          ) : (
                            <button
                              onClick={() => copyToClipboard(installCmd)}
                              className="p-2 rounded-lg transition-colors border text-gray-500 border-gray-200
                                         hover:bg-gray-900 hover:text-white hover:border-gray-900"
                              title={`Copier : ${installCmd}`}
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                              </svg>
                            </button>
                          )}

                          {/* Télécharger le paquet (.deb ou .rpm) */}
                          {pkgUrl && (
                            <a href={pkgUrl} download
                              className="p-2 rounded-lg transition-colors border text-gray-500 border-gray-200
                                         hover:bg-gray-50 hover:text-gray-700"
                              title={`Télécharger ${pkg.filename || "le paquet"}`}>
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                              </svg>
                            </a>
                          )}

                          {/* Supprimer */}
                          <button onClick={() => handleDelete(pkg.name)} disabled={deleting === pkg.name}
                            className="p-2 rounded-lg transition-colors border border-transparent
                                       text-red-400 hover:bg-red-50 hover:border-red-200 hover:text-red-600
                                       disabled:opacity-40"
                            title="Supprimer du dépôt">
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <Paginator
            page={page}
            pages={pagination.pages}
            total={pagination.total}
            perPage={PER_PAGE}
            onPageChange={setPage}
            loading={loading}
          />
        </div>
      </div>
    </>
  );
}
