import { useState, useEffect, useRef, useCallback } from "react";
import toast from "react-hot-toast";
import { useAuth } from "../context/AuthContext";
import {
  getClamavStatus, getApiBaseUrl,
  getPackagesPosture, getPackageCve, quarantinePackage,
  submitDecision, rescanPackage, deleteArtifact,
  getSecurityDecisions, getMyDecisions, getUnassignedDecisions,
  searchImportPackages, resolveDecision,
  listGroups, listUsers, assignDecision,
  updateDecision, deleteDecisionById,
} from "../api";
import Paginator from "../components/Paginator";

const API_URL = getApiBaseUrl();

// Comparaison "naturelle" de versions (dpkg/rpm-like) : compare segment par
// segment (numérique vs alphabétique), suffisant pour trier/ordonner des
// versions de paquets APT/RPM sans dépendance externe.
function compareVersions(a, b) {
  const split = (v) => String(v).match(/\d+|\D+/g) || [];
  const pa = split(a), pb = split(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const sa = pa[i] ?? "", sb = pb[i] ?? "";
    const na = /^\d+$/.test(sa) ? parseInt(sa, 10) : null;
    const nb = /^\d+$/.test(sb) ? parseInt(sb, 10) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na - nb;
    } else if (sa !== sb) {
      return sa < sb ? -1 : 1;
    }
  }
  return 0;
}

function formatBytes(bytes) {
  if (!bytes) return "–";
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");
  const styles = {
    info: "text-gray-300", success: "text-green-400",
    error: "text-red-400", warning: "text-yellow-400",
    done: "text-blue-400 font-semibold",
  };
  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

// ─── Helpers CVE ─────────────────────────────────────────────────────────────

const SEV_CONFIG = {
  critical: { label: "CRITICAL", bg: "bg-red-100", text: "text-red-700", dot: "bg-red-500", ring: "ring-red-300" },
  high:     { label: "HIGH",     bg: "bg-orange-100", text: "text-orange-700", dot: "bg-orange-500", ring: "ring-orange-300" },
  medium:   { label: "MEDIUM",   bg: "bg-yellow-100", text: "text-yellow-700", dot: "bg-yellow-400", ring: "ring-yellow-300" },
  low:      { label: "LOW",      bg: "bg-blue-100", text: "text-blue-600", dot: "bg-blue-400", ring: "ring-blue-200" },
  negligible: { label: "NEGLIGIBLE", bg: "bg-gray-100", text: "text-gray-500", dot: "bg-gray-400", ring: "ring-gray-200" },
  unknown:  { label: "UNKNOWN",  bg: "bg-gray-100", text: "text-gray-500", dot: "bg-gray-300", ring: "ring-gray-200" },
};

// Badge "Installé sur N machines" — croise le catalogue du dépôt avec
// l'inventaire réel du parc (services/inventory.py: get_install_summary()).
function InstallBadge({ count, clients }) {
  if (!count) return null;
  const labels = (clients || []).map((c) => c.label).filter(Boolean);
  const title = labels.length
    ? `Installé sur : ${labels.join(", ")}`
    : `Installé sur ${count} machine${count > 1 ? "s" : ""}`;
  return (
    <a
      href="/inventory"
      title={title}
      className="inline-flex items-center gap-1 mt-1 px-1.5 py-0.5 rounded text-[11px] font-medium bg-sky-50 text-sky-700 hover:bg-sky-100 transition-colors w-fit"
    >
      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
      {count} machine{count > 1 ? "s" : ""}
    </a>
  );
}

function SevBadge({ severity, count, size = "sm" }) {
  if (!count) return null;
  const cfg = SEV_CONFIG[severity?.toLowerCase()] || SEV_CONFIG.unknown;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold ${cfg.bg} ${cfg.text} text-xs`}>
      {count} {cfg.label}
    </span>
  );
}

function WorseBadge({ worst }) {
  if (!worst) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-700">
      <svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Clean
    </span>
  );
  const cfg = SEV_CONFIG[worst.toLowerCase()] || SEV_CONFIG.unknown;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${cfg.bg} ${cfg.text}`}>
      {cfg.label}
    </span>
  );
}

// Modal CVE détail
function CveModal({ pkg, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

  useEffect(() => {
    getPackageCve(pkg.name, pkg.version, pkg.arch || "amd64")
      .then(setData)
      .catch(() => toast.error("Impossible de charger les CVE"))
      .finally(() => setLoading(false));
  }, [pkg]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={onClose}>
      <div
        className="bg-white rounded-2xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col m-4"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header modal */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div>
            <h2 className="text-lg font-bold text-gray-900 font-mono">{pkg.name}</h2>
            <p className="text-xs text-gray-400">{pkg.version} · {pkg.arch} · {pkg.distribution}</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-full hover:bg-gray-100 flex items-center justify-center text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {loading ? (
            <div className="text-center text-gray-400 py-12 text-sm">Chargement des CVE...</div>
          ) : !data ? (
            <div className="text-center text-red-400 py-12 text-sm">Erreur de chargement</div>
          ) : (
            <>
              {/* Counts */}
              <div className="flex flex-wrap gap-2 mb-5">
                {_sev_order.map((s) => {
                  const cnt = data.cve_counts?.[s.toLowerCase()];
                  return cnt > 0 ? <SevBadge key={s} severity={s} count={cnt} /> : null;
                })}
                {data.total === 0 && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Aucune CVE détectée
                  </span>
                )}
              </div>

              {/* Absent sur un paquet jamais re-matché (créé avant cette
                  fonctionnalité) — voir services/cve_rematch.py. */}
              {data.last_rematch_at && (
                <p className="text-xs text-gray-400 mb-3"
                   title="Re-matching CVE périodique via SBOM stocké, sans relancer de scan complet">
                  Dernier re-scan CVE : {new Date(data.last_rematch_at).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}
                </p>
              )}

              {!data.has_structured_data && data.total === 0 && (
                <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 mb-4 text-xs text-amber-700">
                  <svg className="w-3.5 h-3.5 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> Ce paquet a été importé avant la collecte structurée des CVE. Ré-importez-le pour obtenir la liste détaillée.
                </div>
              )}

              {/* Liste CVE */}
              {data.cve_results?.length > 0 && (
                <div className="space-y-2">
                  {data.cve_results.map((cve, i) => {
                    const cfg = SEV_CONFIG[cve.severity?.toLowerCase()] || SEV_CONFIG.unknown;
                    return (
                      <div key={i} className={`border rounded-lg p-3 ${cfg.bg} border-opacity-50`}>
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`font-mono font-bold text-sm ${cfg.text}`}>{cve.id}</span>
                              <WorseBadge worst={cve.severity} />
                              {cve.cvss && (
                                <span className="text-xs text-gray-500 font-mono">CVSS {cve.cvss}</span>
                              )}
                              <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                                cve.fix_state === "fixed" ? "bg-green-100 text-green-700" :
                                cve.fix_state === "not-fixed" ? "bg-red-100 text-red-600" :
                                "bg-gray-100 text-gray-500"
                              }`}>
                                {cve.fix_state === "fixed" ? <><svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Fix disponible</> :
                                 cve.fix_state === "not-fixed" ? <><svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Pas de fix</> : "Fix inconnu"}
                              </span>
                            </div>
                            <p className="text-xs text-gray-600 mt-1 line-clamp-2">{cve.description || "Pas de description."}</p>
                            <p className="text-xs text-gray-400 mt-1">
                              Composant : <span className="font-mono">{cve.package_name} {cve.package_version}</span>
                              {cve.fix_versions?.length > 0 && (
                                <> · Fix : <span className="font-mono text-green-600">{cve.fix_versions.join(", ")}</span></>
                              )}
                            </p>
                          </div>
                          {cve.urls?.[0] && (
                            <a href={cve.urls[0]} target="_blank" rel="noopener noreferrer"
                               className="shrink-0 text-xs text-blue-500 hover:underline">
                              NVD →
                            </a>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Modal de décision RSSI ──────────────────────────────────────────────────

const ACTIONS = [
  {
    key: "accept_risk",
    label: "Accepter le risque",
    color: "bg-amber-600 hover:bg-amber-700",
    icon: <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    desc: "Le paquet est publié dans le dépôt (APT/RPM/APK). La décision est tracée avec justification et expiration.",
    needsExpiry: true,
  },
  {
    key: "exception",
    label: "Exception temporaire",
    color: "bg-blue-600 hover:bg-blue-700",
    icon: <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/><rect x="9" y="3" width="6" height="4" rx="1"/></svg>,
    desc: "Exception formelle limitée dans le temps. Identique à l'acceptation mais avec cadre réglementaire.",
    needsExpiry: true,
  },
  {
    key: "upgrade_required",
    label: "Exiger une mise à jour",
    color: "bg-blue-600 hover:bg-blue-700",
    icon: <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>,
    desc: "Le paquet reste hors dépôt jusqu'à la version cible. SLA de mise à jour imposé.",
    needsVersion: true,
  },
  {
    key: "reject",
    label: "Rejeter définitivement",
    color: "bg-red-600 hover:bg-red-700",
    icon: <svg className="w-4 h-4 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
    desc: "Le paquet est déplacé en quarantaine définitive. Ne peut plus être utilisé.",
    needsExpiry: false,
  },
];

function DecisionModal({ pkg, onClose, onDecided }) {
  const [action, setAction]           = useState(null);
  const [justification, setJust]      = useState("");
  const [expiryDays, setExpiryDays]   = useState(30);
  const [targetVersion, setTargetV]   = useState("");
  const [submitting, setSubmitting]   = useState(false);
  const [searching, setSearching]     = useState(false);
  const [searchResults, setSearchResults] = useState(null);
  const [assignedTo, setAssignedTo]   = useState("");
  const [assignedToType, setAssignedToType] = useState("user");
  const [groups, setGroups]           = useState([]);
  const [users, setUsers]             = useState([]);

  useEffect(() => {
    Promise.all([listGroups().catch(() => ({ groups: [] })), listUsers().catch(() => ({ users: [] }))])
      .then(([gRes, uRes]) => { setGroups(gRes.groups || []); setUsers(uRes.users || []); });
  }, []);

  const _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
  const kev  = (pkg.cve_results || []).filter((c) => c.in_kev);
  const epssHigh = (pkg.cve_results || []).filter((c) => (c.epss_percent || 0) >= 10);
  const selectedAction = ACTIONS.find((a) => a.key === action);

  // Versions de correction connues via le scan CVE (Grype peut en remonter plusieurs),
  // triées de la plus ancienne à la plus récente
  const fixVersions = Array.from(new Set(
    (pkg.cve_results || []).flatMap((c) => c.fix_versions || [])
  )).sort(compareVersions);

  // Version minimale à installer pour corriger l'ensemble des CVE détectées :
  // la plus petite version corrective qui soit strictement supérieure à la
  // version actuellement installée.
  const recommendedFix = fixVersions.find((v) => compareVersions(v, pkg.version) > 0)
    || fixVersions[fixVersions.length - 1];

  const handleSearchSources = async () => {
    setSearching(true);
    setSearchResults(null);
    try {
      const data = await searchImportPackages(pkg.name, 40);
      let exact = (data.results || []).filter((r) => r.name === pkg.name);

      // Restreindre aux résultats de la même distribution/arch que le paquet
      // décidé — un "fix" remonté depuis une autre distro n'est pas pertinent
      // (numérotation de versions différente, dépôt différent).
      const sameDistro = exact.filter((r) =>
        (!pkg.distribution || r.distro === pkg.distribution) &&
        (!pkg.arch || r.arch === pkg.arch)
      );
      const usable = sameDistro.length > 0 ? sameDistro : exact;
      const otherDistro = sameDistro.length === 0 && exact.length > 0;

      const versions = Array.from(new Set(usable.map((r) => r.version)))
        .filter(Boolean)
        .sort(compareVersions);

      setSearchResults({ versions, otherDistro });
      if (versions.length === 0) toast.error("Aucune version trouvée dans les sources importées");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de la recherche");
    } finally {
      setSearching(false);
    }
  };

  // Version recommandée parmi les résultats disponibles dans les sources
  // importées : la plus petite version qui couvre le correctif minimal connu.
  // Si aucun correctif n'est connu via le scan CVE (fixVersions vide), on ne
  // recommande rien ici — sinon on retomberait sur la version déjà installée.
  const recommendedAvailable = recommendedFix
    ? searchResults?.versions?.find((v) => compareVersions(v, recommendedFix) >= 0)
    : undefined;

  const handleSubmit = async () => {
    if (!action)          return toast.error("Choisissez une action");
    if (!justification.trim()) return toast.error("La justification est obligatoire");
    if (selectedAction?.needsVersion && !targetVersion.trim())
      return toast.error("La version cible est obligatoire");

    setSubmitting(true);
    try {
      await submitDecision(pkg.name, pkg.version, {
        action,
        justification: justification.trim(),
        expires_in_days: selectedAction?.needsExpiry ? expiryDays : null,
        target_version:  selectedAction?.needsVersion ? targetVersion.trim() : null,
        arch: pkg.arch || "amd64",
        assigned_to:      assignedTo || null,
        assigned_to_type: assignedTo ? assignedToType : null,
      });
      toast.success(`Décision "${action}" enregistrée pour ${pkg.name}`);
      onDecided();
      onClose();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de l'enregistrement");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] flex flex-col"
           onClick={(e) => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-100">
          <div>
            <h2 className="text-lg font-bold text-gray-900">Décision de sécurité</h2>
            <p className="text-sm text-gray-500 font-mono">{pkg.name} {pkg.version}</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 rounded-full hover:bg-gray-100 flex items-center justify-center text-gray-400">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-6 space-y-5">
          {/* Résumé du risque */}
          <div className="bg-gray-50 rounded-xl p-4 space-y-2">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Contexte du risque</p>
            <div className="flex flex-wrap gap-2">
              {_sev_order.map((s) => {
                const cnt = pkg.cve_counts?.[s.toLowerCase()];
                return cnt > 0 ? <SevBadge key={s} severity={s} count={cnt} /> : null;
              })}
            </div>
            {kev.length > 0 && (
              <div className="flex items-center gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                <span className="text-red-600 font-bold text-sm flex items-center gap-1"><svg className="w-3.5 h-3.5 inline text-red-600" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> KEV CISA</span>
                <span className="text-xs text-red-700">
                  {kev.length} CVE activement exploitée{kev.length > 1 ? "s" : ""} en ce moment :
                  <span className="font-mono ml-1">{kev.slice(0, 3).map((c) => c.id).join(", ")}{kev.length > 3 ? "…" : ""}</span>
                </span>
              </div>
            )}
            {epssHigh.length > 0 && (
              <div className="flex items-center gap-2 bg-orange-50 border border-orange-200 rounded-lg px-3 py-2">
                <span className="text-orange-600 font-semibold text-sm flex items-center gap-1"><svg className="w-3.5 h-3.5 inline text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> EPSS élevé</span>
                <span className="text-xs text-orange-700">
                  {epssHigh.length} CVE avec probabilité d'exploitation ≥ 10%
                </span>
              </div>
            )}
          </div>

          {/* Choix de l'action */}
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">Action</p>
            <div className="grid grid-cols-2 gap-2">
              {ACTIONS.map((a) => (
                <button
                  key={a.key}
                  onClick={() => setAction(a.key)}
                  className={`text-left p-3 rounded-xl border-2 transition-all ${
                    action === a.key
                      ? "border-blue-500 bg-blue-50"
                      : "border-gray-200 hover:border-gray-300 hover:bg-gray-50"
                  }`}
                >
                  <p className="text-sm font-semibold text-gray-900">{a.icon} {a.label}</p>
                  <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{a.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Justification */}
          <div>
            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
              Justification <span className="text-red-500">*</span>
            </label>
            <textarea
              value={justification}
              onChange={(e) => setJust(e.target.value)}
              rows={3}
              placeholder="Ex : Cette CVE n'est pas exploitable dans notre contexte car le service n'est pas exposé réseau. Mitigations en place : WAF, isolation réseau."
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
            />
          </div>

          {/* Expiration (accept_risk / exception) */}
          {selectedAction?.needsExpiry && (
            <div>
              <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
                Expiration (SLA)
              </label>
              <div className="flex items-center gap-3">
                {[7, 14, 30, 60, 90].map((d) => (
                  <button key={d}
                    onClick={() => setExpiryDays(d)}
                    className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                      expiryDays === d ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                    }`}
                  >{d}j</button>
                ))}
              </div>
              <p className="text-xs text-gray-400 mt-1">
                La décision expire le{" "}
                <strong>{new Date(Date.now() + expiryDays * 86400000).toLocaleDateString("fr-FR")}</strong>.
                Une alerte sera envoyée à J-7.
              </p>
            </div>
          )}

          {/* Version cible (upgrade_required) */}
          {selectedAction?.needsVersion && (
            <div>
              <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">
                Version cible <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={targetVersion}
                onChange={(e) => setTargetV(e.target.value)}
                placeholder="Ex: 3.0.7-1ubuntu0.4"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
              />

              {/* Versions de correction connues via les CVE détectées */}
              {fixVersions.length > 0 && (
                <div className="mt-2">
                  <p className="text-[11px] text-gray-400 mb-1">
                    Versions corrigées connues (scan CVE) — du plus ancien au plus récent :
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {fixVersions.map((v) => {
                      const isRecommended = v === recommendedFix;
                      const isOlder = compareVersions(v, pkg.version) <= 0;
                      return (
                        <button
                          key={v}
                          type="button"
                          onClick={() => setTargetV(v)}
                          title={isOlder
                            ? "Version ≤ version installée — probablement non pertinente"
                            : isRecommended
                              ? "Version minimale corrigeant les CVE détectées"
                              : undefined}
                          className={`px-2 py-1 rounded-md text-xs font-mono border transition-colors flex items-center gap-1 ${
                            targetVersion === v
                              ? "border-blue-500 bg-blue-50 text-blue-700"
                              : isRecommended
                                ? "border-amber-300 bg-amber-50 text-amber-700 hover:border-amber-400"
                                : isOlder
                                  ? "border-gray-100 bg-gray-50 text-gray-400 hover:border-gray-200"
                                  : "border-gray-200 text-gray-600 hover:border-blue-300 hover:bg-blue-50"
                          }`}
                        >
                          {v}
                          {isRecommended && <span className="text-[10px] uppercase font-semibold">Recommandé</span>}
                        </button>
                      );
                    })}
                  </div>
                  {recommendedFix && (
                    <p className="text-[11px] text-amber-600 mt-1">
                      <strong>{recommendedFix}</strong> est la version minimale corrigeant l&apos;ensemble
                      des CVE détectées (au-dessus de la version installée {pkg.version}).
                    </p>
                  )}
                </div>
              )}

              {/* Recherche automatique dans les sources importées */}
              <div className="mt-2">
                <button
                  type="button"
                  onClick={handleSearchSources}
                  disabled={searching}
                  className="text-xs font-medium text-blue-600 hover:text-blue-800 disabled:opacity-50 flex items-center gap-1.5"
                >
                  {searching && (
                    <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                    </svg>
                  )}
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                  </svg>
                  Rechercher dans les sources importées
                </button>
                {searchResults?.versions?.length > 0 && (
                  <div className="mt-1.5">
                    <p className="text-[11px] text-gray-400 mb-1">
                      Versions disponibles dans les sources configurées
                      {pkg.distribution && !searchResults.otherDistro && <> (distribution <span className="font-mono">{pkg.distribution}</span>)</>}
                      {searchResults.otherDistro && <> — aucune trouvée pour <span className="font-mono">{pkg.distribution}</span>, résultats toutes distributions</>}
                      — du plus ancien au plus récent :
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {searchResults.versions.map((v) => {
                        const isInstalled = compareVersions(v, pkg.version) === 0;
                        const isOlder = compareVersions(v, pkg.version) < 0;
                        const isRecommended = !isInstalled && !!recommendedFix && v === recommendedAvailable;
                        return (
                          <button
                            key={v}
                            type="button"
                            onClick={() => setTargetV(v)}
                            title={isInstalled
                              ? "Version actuellement installée"
                              : isOlder
                                ? "Version < version installée — probablement non pertinente"
                                : isRecommended
                                  ? "Plus petite version disponible couvrant le correctif minimal"
                                  : undefined}
                            className={`px-2 py-1 rounded-md text-xs font-mono border transition-colors flex items-center gap-1 ${
                              targetVersion === v
                                ? "border-blue-500 bg-blue-50 text-blue-700"
                                : isRecommended
                                  ? "border-amber-300 bg-amber-50 text-amber-700 hover:border-amber-400"
                                  : isInstalled || isOlder
                                    ? "border-gray-100 bg-gray-50 text-gray-400 hover:border-gray-200"
                                    : "border-green-200 text-green-700 bg-green-50 hover:border-green-400"
                            }`}
                          >
                            {v}
                            {isRecommended && <span className="text-[10px] uppercase font-semibold">Recommandé</span>}
                            {isInstalled && <span className="text-[10px] uppercase font-semibold">Installée</span>}
                          </button>
                        );
                      })}
                    </div>
                    {recommendedFix ? (
                      recommendedAvailable ? (
                        <p className="text-[11px] text-amber-600 mt-1">
                          <strong>{recommendedAvailable}</strong> est la version la plus ancienne disponible
                          qui corrige les CVE détectées — recommandée pour limiter l&apos;écart avec la version
                          installée.
                        </p>
                      ) : (
                        <p className="text-[11px] text-gray-400 mt-1">
                          Aucune version ≥ <strong>{recommendedFix}</strong> (correctif recommandé) n&apos;est
                          encore disponible dans les sources configurées.
                        </p>
                      )
                    ) : (
                      <p className="text-[11px] text-gray-400 mt-1">
                        Aucun correctif connu via le scan CVE pour cette version — vérifiez manuellement la
                        version cible à utiliser.
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Assignation */}
        <div className="px-6 pb-4">
          <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Assigner à (optionnel)
          </label>
          <div className="flex gap-2">
            <select
              value={assignedToType}
              onChange={(e) => { setAssignedToType(e.target.value); setAssignedTo(""); }}
              className="border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            >
              <option value="user">Utilisateur</option>
              <option value="group">Groupe</option>
            </select>
            <select
              value={assignedTo}
              onChange={(e) => setAssignedTo(e.target.value)}
              className="flex-1 border border-gray-300 rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            >
              <option value="">— Aucune assignation —</option>
              {assignedToType === "group"
                ? groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)
                : users.map((u) => <option key={u.username} value={u.username}>{u.username}{u.full_name ? ` (${u.full_name})` : ""}</option>)
              }
            </select>
          </div>
          {assignedTo && (
            <p className="text-[11px] text-blue-600 mt-1">
              Une notification sera envoyée à l'assigné.
            </p>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-100 flex items-center justify-between">
          <p className="text-xs text-gray-400">
            Décision tracée, horodatée et auditée en tant que <strong>{/* currentUser */}</strong>
          </p>
          <div className="flex gap-2">
            <button onClick={onClose}
                    className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 transition-colors">
              Annuler
            </button>
            <button
              onClick={handleSubmit}
              disabled={submitting || !action || !justification.trim()}
              className={`px-5 py-2 text-sm font-semibold text-white rounded-lg transition-colors disabled:opacity-50 ${
                selectedAction?.color || "bg-blue-600 hover:bg-blue-700"
              }`}
            >
              {submitting
                ? "Enregistrement..."
                : selectedAction
                  ? <>{selectedAction.icon} {selectedAction.label}</>
                  : "Confirmer"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Section Suivi des décisions RSSI (audit) ────────────────────────────────

const DECISION_FILTERS = [
  { key: "all",              label: "Toutes" },
  { key: "upgrade_required", label: "Upgrade requis" },
  { key: "accept_risk",      label: "Risque accepté" },
  { key: "exception",        label: "Exception" },
  { key: "reject",           label: "Rejeté" },
  { key: "resolved",         label: "Résolu" },
];

function AssignedBadge({ assignedTo, assignedToType }) {
  if (!assignedTo) return <span className="text-gray-300 text-xs">—</span>;
  const icon = assignedToType === "group" ? "👥" : "👤";
  return (
    <span className="inline-flex items-center gap-1 text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5">
      {icon} {assignedTo}
    </span>
  );
}

// ─── Icônes d'action ─────────────────────────────────────────────────────────
const IconEye = () => (
  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
  </svg>
);
const IconPencil = () => (
  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
  </svg>
);
const IconTrash = () => (
  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
  </svg>
);

// ─── Modal lecture seule + assignation ───────────────────────────────────────
function DecisionViewModal({ decision: initialDecision, onClose, canAssign, onAssigned }) {
  const [decision, setDecision]   = useState(initialDecision);
  const [assigning, setAssigning] = useState(false);
  const [asnType, setAsnType]     = useState(initialDecision.assigned_to_type || "user");
  const [asnTarget, setAsnTarget] = useState(initialDecision.assigned_to || "");
  const [groups, setGroups]       = useState([]);
  const [users, setUsers]         = useState([]);
  const [saving, setSaving]       = useState(false);

  useEffect(() => {
    if (!assigning) return;
    Promise.all([
      listGroups().catch(() => ({ groups: [] })),
      listUsers().catch(() => ({ users: [] })),
    ]).then(([g, u]) => { setGroups(g.groups || []); setUsers(u.users || []); });
    setAsnType(decision.assigned_to_type || "user");
    setAsnTarget(decision.assigned_to || "");
  }, [assigning, decision.assigned_to, decision.assigned_to_type]);

  const handleAssign = async () => {
    setSaving(true);
    try {
      const res = await assignDecision(decision.id, asnTarget || null, asnTarget ? asnType : null);
      setDecision(res.decision);
      toast.success(asnTarget ? `Assigné à ${asnTarget}` : "Assignation retirée");
      setAssigning(false);
      onAssigned?.();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de l'assignation");
    } finally {
      setSaving(false);
    }
  };

  if (!decision) return null;
  const sla = decision.sla || {};
  const asnOptions  = asnType === "group" ? groups : users;
  const asnOptKey   = asnType === "group" ? "id" : "username";
  const asnOptLabel = asnType === "group"
    ? (o) => o.name
    : (o) => o.username + (o.full_name ? ` (${o.full_name})` : "");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between px-6 pt-5 pb-4 border-b border-gray-100">
          <div>
            <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">Décision RSSI</p>
            <h3 className="text-base font-semibold text-gray-900 font-mono">{decision.package}</h3>
            <p className="text-xs text-gray-400 font-mono">{decision.version}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors mt-1">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-4">
          {/* Décision + statut */}
          <div className="flex flex-wrap gap-3">
            <div>
              <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">Décision</p>
              <DecisionBadge action={decision.action} />
            </div>
            {decision.action === "upgrade_required" && decision.target_version && (
              <div>
                <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">Version cible</p>
                <span className="text-xs font-mono text-gray-700 bg-gray-100 px-2 py-0.5 rounded">→ {decision.target_version}</span>
              </div>
            )}
          </div>

          {/* Méta */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">Décidé par</p>
              <p className="text-sm text-gray-700">{decision.decided_by || "—"}</p>
            </div>
            <div>
              <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">Le</p>
              <p className="text-sm text-gray-700">
                {decision.decided_at ? new Date(decision.decided_at).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" }) : "—"}
              </p>
            </div>
            {sla.has_sla && (
              <div className="col-span-2">
                <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">SLA</p>
                <span className={`text-xs font-medium ${sla.expired ? "text-red-600" : sla.warning ? "text-amber-600" : "text-green-600"}`}>
                  {sla.expired ? "Expiré" : `${sla.remaining_days}j restants`}
                  {sla.expires_at && <span className="text-gray-400 font-normal ml-1">({new Date(sla.expires_at).toLocaleDateString("fr-FR")})</span>}
                </span>
              </div>
            )}
          </div>

          {/* ── Assignation ── */}
          <div className="border border-gray-200 rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-200">
              <div className="flex items-center gap-2">
                <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Assignation</p>
                {decision.assigned_to && !assigning && (
                  <AssignedBadge assignedTo={decision.assigned_to} assignedToType={decision.assigned_to_type} />
                )}
                {!decision.assigned_to && !assigning && (
                  <span className="text-xs text-gray-300 italic">Non assignée</span>
                )}
              </div>
              {canAssign && !assigning && (
                <button onClick={() => setAssigning(true)}
                  className="text-[11px] font-medium text-blue-600 hover:text-blue-700 transition-colors">
                  {decision.assigned_to ? "Modifier" : "Assigner"}
                </button>
              )}
            </div>

            {assigning && (
              <div className="px-4 py-3 space-y-3">
                {/* Type user / groupe */}
                <div className="flex gap-2">
                  {["user", "group"].map((t) => (
                    <button key={t} onClick={() => { setAsnType(t); setAsnTarget(""); }}
                      className={`flex-1 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
                        asnType === t
                          ? "bg-blue-600 text-white border-blue-600"
                          : "border-gray-200 text-gray-600 hover:bg-gray-50"
                      }`}>
                      {t === "user" ? "Utilisateur" : "Groupe"}
                    </button>
                  ))}
                </div>

                {/* Sélecteur */}
                <select value={asnTarget} onChange={(e) => setAsnTarget(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="">— Retirer l'assignation —</option>
                  {asnOptions.map((o) => (
                    <option key={o[asnOptKey]} value={o[asnOptKey]}>{asnOptLabel(o)}</option>
                  ))}
                </select>

                {/* Actions */}
                <div className="flex gap-2">
                  <button onClick={() => setAssigning(false)}
                    className="flex-1 py-1.5 text-xs text-gray-500 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                    Annuler
                  </button>
                  <button onClick={handleAssign} disabled={saving}
                    className="flex-1 py-1.5 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors disabled:opacity-50">
                    {saving ? "…" : "Confirmer"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* CVEs */}
          {(decision.cve_ids || []).length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-gray-400 uppercase mb-2">CVE couverts</p>
              <div className="flex flex-wrap gap-1.5">
                {decision.cve_ids.map((id) => (
                  <span key={id} className="text-[11px] font-mono bg-red-50 text-red-700 border border-red-100 px-2 py-0.5 rounded">{id}</span>
                ))}
              </div>
            </div>
          )}

          {/* Justification */}
          <div>
            <p className="text-[10px] font-semibold text-gray-400 uppercase mb-2">Justification</p>
            <div className="bg-gray-50 border border-gray-200 rounded-xl px-4 py-3 text-sm text-gray-700 whitespace-pre-wrap leading-relaxed">
              {decision.justification || <span className="text-gray-300 italic">Aucune justification</span>}
            </div>
          </div>

          {/* Résolution */}
          {decision.resolved_at && (
            <div className="bg-gray-50 border border-gray-200 rounded-xl px-4 py-3">
              <p className="text-[10px] font-semibold text-gray-400 uppercase mb-1">Résolu</p>
              <p className="text-xs text-gray-600">
                {new Date(decision.resolved_at).toLocaleDateString("fr-FR")} par <strong>{decision.resolved_by}</strong>
              </p>
              {decision.resolution_note && <p className="text-xs text-gray-500 mt-1 italic">{decision.resolution_note}</p>}
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-gray-100">
          <button onClick={onClose} className="w-full py-2 text-sm text-gray-500 hover:text-gray-700 transition-colors">
            Fermer
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Modal d'édition ─────────────────────────────────────────────────────────
const ACTIONS_OPTS = [
  { value: "accept_risk",      label: "Accepter le risque" },
  { value: "exception",        label: "Exception temporaire" },
  { value: "reject",           label: "Rejeter" },
  { value: "upgrade_required", label: "Upgrade requis" },
];

function DecisionEditModal({ decision, onClose, onSaved }) {
  const [action, setAction]         = useState(decision.action);
  const [justif, setJustif]         = useState(decision.justification || "");
  const [expires, setExpires]       = useState(decision.expires_in_days ?? "");
  const [target, setTarget]         = useState(decision.target_version || "");
  const [asnType, setAsnType]       = useState(decision.assigned_to_type || "user");
  const [asnTarget, setAsnTarget]   = useState(decision.assigned_to || "");
  const [groups, setGroups]         = useState([]);
  const [users, setUsers]           = useState([]);
  const [saving, setSaving]         = useState(false);

  const needsExpiry = action === "accept_risk" || action === "exception";
  const needsTarget = action === "upgrade_required";

  useEffect(() => {
    Promise.all([
      listGroups().catch(() => ({ groups: [] })),
      listUsers().catch(() => ({ users: [] })),
    ]).then(([g, u]) => { setGroups(g.groups || []); setUsers(u.users || []); });
  }, []);

  const handleSave = async () => {
    if (!justif.trim()) { toast.error("La justification est obligatoire"); return; }
    setSaving(true);
    try {
      await updateDecision(decision.id, {
        action,
        justification: justif.trim(),
        expires_in_days: needsExpiry && expires ? parseInt(expires, 10) : null,
        target_version:  needsTarget ? target.trim() || null : null,
      });
      // Assignation si changée
      const asnChanged = asnTarget !== (decision.assigned_to || "") || asnType !== (decision.assigned_to_type || "user");
      if (asnChanged) {
        await assignDecision(decision.id, asnTarget || null, asnTarget ? asnType : null);
      }
      toast.success("Décision mise à jour");
      onSaved();
      onClose();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de la mise à jour");
    } finally {
      setSaving(false);
    }
  };

  const asnOptions  = asnType === "group" ? groups : users;
  const asnOptKey   = asnType === "group" ? "id" : "username";
  const asnOptLabel = asnType === "group"
    ? (o) => o.name
    : (o) => o.username + (o.full_name ? ` (${o.full_name})` : "");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between px-6 pt-5 pb-4 border-b border-gray-100 shrink-0">
          <div>
            <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">Modifier la décision</p>
            <h3 className="text-base font-semibold text-gray-900 font-mono">{decision.package} <span className="text-gray-400 font-normal">{decision.version}</span></h3>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors mt-1">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>
          </button>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-4">
          {/* Action */}
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Décision</label>
            <div className="grid grid-cols-2 gap-2">
              {ACTIONS_OPTS.map((opt) => (
                <button key={opt.value} onClick={() => setAction(opt.value)}
                  className={`py-2 px-3 rounded-xl text-xs font-medium border transition-colors text-left ${
                    action === opt.value
                      ? "border-blue-400 bg-blue-50 text-blue-700"
                      : "border-gray-200 text-gray-600 hover:border-gray-300 hover:bg-gray-50"
                  }`}>
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {needsExpiry && (
            <div>
              <label className="block text-xs font-semibold text-gray-500 mb-1.5">Expiration (jours)</label>
              <input type="number" min="1" value={expires} onChange={(e) => setExpires(e.target.value)}
                placeholder="ex: 90"
                className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
          )}

          {needsTarget && (
            <div>
              <label className="block text-xs font-semibold text-gray-500 mb-1.5">Version cible (correctif)</label>
              <input type="text" value={target} onChange={(e) => setTarget(e.target.value)}
                placeholder="ex: 2.35-0ubuntu3.4"
                className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
          )}

          {/* Justification */}
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Justification <span className="text-red-500">*</span></label>
            <textarea rows={4} value={justif} onChange={(e) => setJustif(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
              placeholder="Justification de la décision..." />
          </div>

          {/* Assignation */}
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Assignation</label>
            <div className="border border-gray-200 rounded-xl overflow-hidden">
              {/* Toggle user / groupe */}
              <div className="flex border-b border-gray-200">
                {["user", "group"].map((t) => (
                  <button key={t} onClick={() => { setAsnType(t); setAsnTarget(""); }}
                    className={`flex-1 py-2 text-xs font-medium transition-colors ${
                      asnType === t
                        ? "bg-blue-600 text-white"
                        : "bg-white text-gray-500 hover:bg-gray-50"
                    }`}>
                    {t === "user" ? "Utilisateur" : "Groupe"}
                  </button>
                ))}
              </div>
              <div className="p-2">
                <select value={asnTarget} onChange={(e) => setAsnTarget(e.target.value)}
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-xs bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="">— Aucune assignation —</option>
                  {asnOptions.map((o) => (
                    <option key={o[asnOptKey]} value={o[asnOptKey]}>{asnOptLabel(o)}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>

        <div className="px-6 pb-5 pt-3 flex gap-3 border-t border-gray-100 shrink-0">
          <button onClick={onClose}
            className="flex-1 py-2 text-sm text-gray-500 border border-gray-200 rounded-xl hover:border-gray-300 hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-colors disabled:opacity-50">
            {saving ? "Enregistrement…" : "Enregistrer"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Boutons d'actions par ligne ──────────────────────────────────────────────
function DecisionRowActions({ decision, canEdit, canDelete, onView, onEdit, onDeleted, onRefresh }) {
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting]     = useState(false);
  const ref                         = useRef(null);

  useEffect(() => {
    if (!confirming) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setConfirming(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [confirming]);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await deleteDecisionById(decision.id);
      toast.success(`Décision supprimée (${decision.package} ${decision.version})`);
      setConfirming(false);
      onDeleted();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de la suppression");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex items-center gap-1" ref={ref}>
      {/* Voir */}
      <button onClick={onView} title="Voir les détails"
        className="p-1.5 rounded-lg text-gray-400 hover:text-blue-600 hover:bg-blue-50 transition-colors">
        <IconEye />
      </button>

      {/* Modifier */}
      {canEdit && (
        <button onClick={onEdit} title="Modifier la décision"
          className="p-1.5 rounded-lg text-gray-400 hover:text-amber-600 hover:bg-amber-50 transition-colors">
          <IconPencil />
        </button>
      )}

      {/* Supprimer */}
      {canDelete && (
        <div className="relative">
          {confirming ? (
            <div className="absolute z-20 right-0 top-full mt-1 bg-white border border-red-200 rounded-xl shadow-lg p-3 w-52">
              <p className="text-xs text-gray-700 font-medium mb-2">Supprimer cette décision ?</p>
              <p className="text-[11px] text-gray-400 mb-3">Cette action est irréversible.</p>
              <div className="flex gap-2">
                <button onClick={() => setConfirming(false)}
                  className="flex-1 py-1 text-xs text-gray-500 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  Annuler
                </button>
                <button onClick={handleDelete} disabled={deleting}
                  className="flex-1 py-1 text-xs font-medium bg-red-600 hover:bg-red-500 text-white rounded-lg transition-colors disabled:opacity-50">
                  {deleting ? "…" : "Supprimer"}
                </button>
              </div>
            </div>
          ) : (
            <button onClick={() => setConfirming(true)} title="Supprimer la décision"
              className="p-1.5 rounded-lg text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors">
              <IconTrash />
            </button>
          )}
        </div>
      )}
    </div>
  );
}

const VIEW_TABS = [
  { key: "all",        label: "Toutes" },
  { key: "mine",       label: "Mes décisions" },
  { key: "unassigned", label: "Non assignées" },
];

function DecisionsTrackingSection() {
  const { user } = useAuth();
  const [decisions, setDecisions]   = useState(null);
  const [loading, setLoading]       = useState(true);
  const [filter, setFilter]         = useState("all");
  const [viewTab, setViewTab]       = useState("all");
  const [unassignedCount, setUnassignedCount] = useState(0);
  const [viewDecision, setViewDecision]   = useState(null);
  const [editDecision, setEditDecision]   = useState(null);

  const loadDecisions = useCallback(async (tab) => {
    setLoading(true);
    try {
      let data;
      if (tab === "mine")       data = await getMyDecisions();
      else if (tab === "unassigned") data = await getUnassignedDecisions();
      else                      data = await getSecurityDecisions();
      setDecisions(data.decisions || []);
      // Compte non assignées pour badge
      if (tab !== "unassigned") {
        getUnassignedDecisions().then((d) => setUnassignedCount(d.count || 0)).catch(() => {});
      } else {
        setUnassignedCount(data.count || 0);
      }
    } catch {
      toast.error("Impossible de charger le suivi des décisions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadDecisions(viewTab); }, [viewTab, loadDecisions]);

  const handleTabChange = (tab) => { setViewTab(tab); setFilter("all"); };

  const filtered = (decisions || []).filter(
    (d) => filter === "all"
      || (filter === "resolved" ? !!d.resolved_at : d.action === filter)
  );

  return (
    <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
      <div className="w-full flex items-center justify-between px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center">
            <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
            </svg>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-gray-900">Suivi des décisions RSSI</h2>
            <p className="text-xs text-gray-400">
              Historique des décisions de sécurité, statut SLA et disponibilité des correctifs — pour audit.
            </p>
          </div>
        </div>
      </div>

      <div className="border-t border-gray-100">
          {/* Onglets vue */}
          <div className="flex items-center gap-1 px-6 pt-3 pb-0">
            {VIEW_TABS.map((tab) => (
              <button key={tab.key} onClick={() => handleTabChange(tab.key)}
                className={`relative px-3 py-1.5 text-xs font-medium rounded-t-lg border-b-2 transition-colors ${
                  viewTab === tab.key
                    ? "border-blue-500 text-blue-700 bg-blue-50"
                    : "border-transparent text-gray-500 hover:text-gray-700"
                }`}>
                {tab.label}
                {tab.key === "unassigned" && unassignedCount > 0 && (
                  <span className="ml-1 bg-red-500 text-white text-[10px] rounded-full px-1.5 py-0.5">
                    {unassignedCount}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Filtres */}
          <div className="flex items-center gap-2 px-6 py-3 flex-wrap border-b border-gray-100">
            {DECISION_FILTERS.map((f) => (
              <button
                key={f.key}
                onClick={() => setFilter(f.key)}
                className={`px-2.5 py-1 rounded-full text-xs font-medium border transition-colors ${
                  filter === f.key
                    ? "border-blue-300 bg-blue-50 text-blue-700"
                    : "border-gray-200 text-gray-500 hover:border-gray-300"
                }`}
              >
                {f.label}
              </button>
            ))}
            <span className="ml-auto text-xs text-gray-400 tabular-nums">
              {loading ? "…" : `${filtered.length} décision${filtered.length > 1 ? "s" : ""}`}
            </span>
          </div>

          {loading ? (
            <div className="p-8 text-center text-gray-400 text-sm">Chargement...</div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center text-gray-400 text-sm">Aucune décision enregistrée.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-100 bg-gray-50/50">
                    <th className="px-6 py-2.5">Paquet</th>
                    <th className="px-3 py-2.5">Décision</th>
                    <th className="px-3 py-2.5">Par</th>
                    <th className="px-3 py-2.5">Assigné à</th>
                    <th className="px-3 py-2.5 whitespace-nowrap">Le</th>
                    <th className="px-3 py-2.5">Suivi</th>
                    <th className="px-3 py-2.5">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {filtered.map((d) => {
                    const isOwn = d.decided_by === user?.username;
                    const isAdmin = user?.role === "admin";
                    const isMaintainer = user?.role === "maintainer";
                    const canEdit   = isAdmin || (isMaintainer && isOwn);
                    const canDelete = isAdmin || (isMaintainer && isOwn);
                    const canAssign = isAdmin || isMaintainer;
                    return (
                      <tr key={d.id || `${d.package}-${d.version}-${d.decided_at}`}
                        className="hover:bg-blue-50/30 transition-colors group">
                        {/* Paquet */}
                        <td className="px-6 py-3">
                          <p className="font-mono text-xs font-semibold text-gray-800 leading-tight">{d.package}</p>
                          <p className="text-[11px] text-gray-400 font-mono mt-0.5">{d.version}</p>
                          <InstallBadge count={d.install_count} clients={d.install_clients} />
                        </td>
                        {/* Décision */}
                        <td className="px-3 py-3">
                          <DecisionBadge action={d.action} />
                          {d.action === "upgrade_required" && d.target_version && (
                            <p className="text-[11px] text-gray-400 font-mono mt-1">→ {d.target_version}</p>
                          )}
                        </td>
                        {/* Par */}
                        <td className="px-3 py-3">
                          <p className="text-xs text-gray-600 font-medium">{d.decided_by || "—"}</p>
                        </td>
                        {/* Assigné à */}
                        <td className="px-3 py-3">
                          <AssignedBadge assignedTo={d.assigned_to} assignedToType={d.assigned_to_type} />
                        </td>
                        {/* Date */}
                        <td className="px-3 py-3">
                          <p className="text-xs text-gray-400 whitespace-nowrap">
                            {d.decided_at ? new Date(d.decided_at).toLocaleDateString("fr-FR") : "—"}
                          </p>
                          {d.sla?.has_sla && (
                            <p className={`text-[11px] mt-0.5 ${d.sla.expired ? "text-red-500" : d.sla.warning ? "text-amber-500" : "text-green-600"}`}>
                              {d.sla.expired ? "SLA expiré" : `${d.sla.remaining_days}j SLA`}
                            </p>
                          )}
                        </td>
                        {/* Suivi */}
                        <td className="px-3 py-3">
                          <DecisionTrackingStatus decision={d} onImported={() => loadDecisions(viewTab)} />
                        </td>
                        {/* Actions */}
                        <td className="px-3 py-3">
                          <DecisionRowActions
                            decision={d}
                            canEdit={canEdit}
                            canDelete={canDelete}
                            onView={() => setViewDecision(d)}
                            onEdit={() => setEditDecision(d)}
                            onDeleted={() => loadDecisions(viewTab)}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
      </div>

      {/* Modales */}
      {viewDecision && (
        <DecisionViewModal
          decision={viewDecision}
          onClose={() => setViewDecision(null)}
          canAssign={["admin","maintainer"].includes(user?.role)}
          onAssigned={() => loadDecisions(viewTab)}
        />
      )}
      {editDecision && (
        <DecisionEditModal
          decision={editDecision}
          onClose={() => setEditDecision(null)}
          onSaved={() => loadDecisions(viewTab)}
        />
      )}
    </div>
  );
}

function DecisionTrackingStatus({ decision, onImported }) {
  const sla = decision.sla;
  const patch = decision.patch_status;
  const indexStatus = decision.index_status;

  if (decision.action === "upgrade_required") {
    if (decision.resolved_at) {
      return (
        <div className="flex flex-col gap-1 items-start">
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-gray-100 text-gray-600">
            Résolu
          </span>
          <p className="text-[11px] text-gray-400">
            {new Date(decision.resolved_at).toLocaleDateString("fr-FR")} par {decision.resolved_by}
          </p>
        </div>
      );
    }
    if (patch?.available) {
      return (
        <div className="flex flex-col gap-1.5 items-start">
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-green-100 text-green-700">
            Correctif disponible ({patch.depot_version})
          </span>
          <ResolveDecisionButton decision={decision} onResolved={onImported} />
        </div>
      );
    }
    return (
      <div className="flex flex-col gap-1.5 items-start">
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-100 text-amber-700">
          En attente du correctif
        </span>
        {indexStatus?.available && (
          <ImportNowButton decision={decision} onImported={onImported} />
        )}
      </div>
    );
  }

  if (sla?.has_sla) {
    if (sla.expired) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-red-100 text-red-700">
          Expiré ({sla.expires_at?.slice(0, 10)})
        </span>
      );
    }
    if (sla.warning) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-orange-100 text-orange-700">
          Expire dans {sla.remaining_days}j
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-blue-100 text-blue-700">
        Valide ({sla.remaining_days}j restants)
      </span>
    );
  }

  return <span className="text-xs text-gray-300">—</span>;
}

// ─── Bouton "Marquer comme résolu" — clôture une décision upgrade_required ──
function ResolveDecisionButton({ decision, onResolved }) {
  const [open, setOpen]       = useState(false);
  const [note, setNote]       = useState("");
  const [submitting, setSubmitting] = useState(false);

  const confirm = () => {
    setSubmitting(true);
    resolveDecision(decision.package, decision.version, decision.arch || "amd64", note)
      .then(() => {
        toast.success(`${decision.package} marqué comme résolu`);
        setOpen(false);
        onResolved?.();
      })
      .catch((e) => {
        toast.error(e?.response?.data?.detail || "Impossible de marquer comme résolu");
      })
      .finally(() => setSubmitting(false));
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="text-[11px] font-semibold px-2 py-0.5 rounded-full border border-gray-200 bg-gray-50 text-gray-600 hover:bg-gray-100 transition-colors"
      >
        Marquer comme résolu
      </button>

      {open && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-md flex flex-col">
            <div className="px-5 py-3 border-b border-gray-100">
              <h3 className="text-sm font-semibold text-gray-900">
                Clôturer le suivi de {decision.package} {decision.version}
              </h3>
            </div>
            <div className="px-5 py-4 space-y-3">
              <p className="text-xs text-gray-500">
                Le correctif {decision.target_version} est disponible dans le dépôt
                ({decision.patch_status?.depot_version}).
                {decision.install_count > 0 && (
                  <> {decision.install_count} machine{decision.install_count > 1 ? "s" : ""} {decision.install_count > 1 ? "restent" : "reste"} sur l&apos;ancienne version.</>
                )}
              </p>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Note de clôture (optionnel)"
                rows={3}
                className="w-full text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-200"
              />
            </div>
            <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-end gap-2">
              <button
                onClick={() => setOpen(false)}
                disabled={submitting}
                className="text-xs font-semibold text-gray-500 hover:text-gray-700 px-3 py-1.5"
              >
                Annuler
              </button>
              <button
                onClick={confirm}
                disabled={submitting}
                className="text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg px-3 py-1.5 disabled:opacity-50"
              >
                {submitting ? "..." : "Confirmer"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ─── Bouton "Importer maintenant" — récupère le correctif depuis l'index sync ─
function ImportNowButton({ decision, onImported }) {
  const [open, setOpen]     = useState(false);
  const [logs, setLogs]     = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone]     = useState(false);

  const start = () => {
    setOpen(true);
    setLogs([]);
    setDone(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    fetch(`${API_URL}/import/fetch`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ package: decision.package, distribution: decision.distribution || null }),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur inconnue" }));
        setLogs((prev) => [...prev, `error|${err.detail || "Erreur serveur"}`]);
        setRunning(false);
        return;
      }
      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let streamDone = false;
      while (!streamDone) {
        const { value, done: chunkDone } = await reader.read();
        if (chunkDone) { streamDone = true; break; }
        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n\n");
        buffer = parts.pop();
        for (const part of parts) {
          const dataLine = part.split("\n").find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          const payload = dataLine.slice(5).trim();
          setLogs((prev) => [...prev, payload]);
          if (payload.startsWith("done|")) setDone(true);
        }
      }
      setRunning(false);
      onImported?.();
    }).catch((e) => {
      setLogs((prev) => [...prev, `error|${e.message}`]);
      setRunning(false);
    });
  };

  return (
    <>
      <button
        onClick={start}
        className="text-[11px] font-semibold px-2 py-0.5 rounded-full border border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 transition-colors"
      >
        Importer {decision.index_status?.indexed_version} maintenant
      </button>

      {open && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl shadow-xl w-full max-w-lg max-h-[80vh] flex flex-col">
            <div className="px-5 py-3 border-b border-gray-100 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-gray-900">
                Import de {decision.package} {decision.index_status?.indexed_version}
              </h3>
              {!running && (
                <button onClick={() => setOpen(false)} className="text-gray-400 hover:text-gray-600">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
              )}
            </div>
            <div className="flex-1 overflow-y-auto bg-gray-900 p-4 space-y-1">
              {logs.map((l, i) => <LogLine key={i} line={l} />)}
              {running && <p className="text-xs text-gray-400 animate-pulse">En cours...</p>}
            </div>
            {done && !running && (
              <div className="px-5 py-3 border-t border-gray-100 text-right">
                <button onClick={() => setOpen(false)} className="text-xs font-semibold text-blue-600 hover:text-blue-700">
                  Fermer
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

// ─── Décision badge ──────────────────────────────────────────────────────────
const DECISION_META = {
  accept_risk:      { label: "Risque accepté", bg: "#F0FDF4", color: "#15803D", border: "#86EFAC" },
  exception:        { label: "Exception",       bg: "#EFF6FF", color: "#1D4ED8", border: "#93C5FD" },
  upgrade_required: { label: "Upgrade requis",  bg: "#F0F9FF", color: "#0369A1", border: "#7DD3FC" },
  reject:           { label: "Rejeté",          bg: "#FEF2F2", color: "#DC2626", border: "#FCA5A5" },
};
function DecisionBadge({ action, slaStatus, slaDays }) {
  if (!action) return <span className="text-xs text-gray-300">—</span>;
  const m = DECISION_META[action] || { label: action, bg: "#F8FAFC", color: "#64748B", border: "#CBD5E1" };
  const expiring = slaStatus === "expiring_soon";
  const expired  = slaStatus === "expired";
  return (
    <div>
      <span style={{ background: m.bg, color: m.color, border: `1px solid ${m.border}`, padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600 }}>
        {m.label}
      </span>
      {slaDays != null && (
        <p style={{ fontSize: 10, color: expired ? "#DC2626" : expiring ? "#D97706" : "#94A3B8", marginTop: 2 }}>
          {expired ? "Expiré" : `J-${slaDays}`}
        </p>
      )}
    </div>
  );
}

// ─── Section posture CVE ─────────────────────────────────────────────────────
const POSTURE_PER_PAGE = 25;

function CvePostureSection({ onDecideRequest }) {
  const [posture, setPosture]   = useState(null);
  const [loading, setLoading]   = useState(true);
  const [selectedPkg, setSelected] = useState(null);
  const [actionLoading, setActL]   = useState(null);
  const [confirmPkg, setConfirm]   = useState(null);  // quarantine confirm
  const [checkedKeys, setChecked]  = useState(new Set()); // suppression multiple — clé "name@version"
  const [bulkDeleting, setBulkDeleting] = useState(false);
  // Filtres
  const [sevFilter, setSev]        = useState("all");  // all|critical|high|medium|low|unscanned
  const [kevFilter, setKev]        = useState(false);
  const [decisFilter, setDecis]    = useState("all");  // all|pending|decided|expiring
  const [distFilter, setDist]      = useState("all");
  const [fmtFilter, setFmt]        = useState("all"); // all|deb|rpm|apk
  // Pagination client-side (appliquée sur les résultats filtrés)
  const [pkgPage, setPkgPage]      = useState(1);

  const _sev_order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

  useEffect(() => { loadPosture(); }, []);

  const loadPosture = async () => {
    setLoading(true);
    try { setPosture(await getPackagesPosture()); }
    catch { toast.error("Impossible de charger la posture CVE"); }
    finally { setLoading(false); }
  };

  const handleQuarantine = async (pkg) => {
    if (confirmPkg?.name !== pkg.name) { setConfirm(pkg); return; }
    setActL(`q:${pkg.name}`); setConfirm(null);
    try {
      await quarantinePackage(pkg.name, pkg.version, pkg.arch || "amd64");
      toast.success(`${pkg.name} mis en quarantaine`);
      loadPosture();
    } catch (e) { toast.error(e.response?.data?.detail || "Erreur quarantaine"); }
    finally { setActL(null); }
  };

  const handleRescan = async (pkg) => {
    setActL(`r:${pkg.name}`);
    try {
      const r = await rescanPackage(pkg.name, pkg.version, pkg.arch || "amd64");
      toast.success(`Rescan terminé — ${r.cve_count} CVE trouvée(s)`);
      loadPosture();
    } catch (e) { toast.error(e.response?.data?.detail || "Erreur rescan"); }
    finally { setActL(null); }
  };

  const handleDelete = async (pkg) => {
    if (!window.confirm(`Supprimer définitivement ${pkg.name} ${pkg.version} du dépôt ?`)) return;
    setActL(`d:${pkg.name}`);
    try {
      await deleteArtifact(pkg.name, pkg.version);
      toast.success(`${pkg.name} supprimé`);
      loadPosture();
    } catch (e) { toast.error(e.response?.data?.detail || "Erreur suppression"); }
    finally { setActL(null); }
  };

  const toggleChecked = (pkey) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(pkey)) next.delete(pkey); else next.add(pkey);
      return next;
    });
  };

  const toggleCheckAll = (pkgsOnPage) => {
    const pageKeys = pkgsOnPage.map((p) => `${p.name}@${p.version}`);
    const allChecked = pageKeys.every((k) => checkedKeys.has(k));
    setChecked((prev) => {
      const next = new Set(prev);
      pageKeys.forEach((k) => (allChecked ? next.delete(k) : next.add(k)));
      return next;
    });
  };

  const handleBulkDelete = async (checkedPkgs) => {
    if (checkedPkgs.length === 0) return;
    if (!window.confirm(
      `Supprimer définitivement ${checkedPkgs.length} paquet${checkedPkgs.length > 1 ? "s" : ""} du dépôt ?`
    )) return;
    setBulkDeleting(true);
    let ok = 0;
    const failed = [];
    for (const pkg of checkedPkgs) {
      try {
        await deleteArtifact(pkg.name, pkg.version);
        ok++;
      } catch (e) {
        failed.push(`${pkg.name} ${pkg.version}`);
      }
    }
    setBulkDeleting(false);
    setChecked(new Set());
    if (failed.length === 0) {
      toast.success(`${ok} paquet${ok > 1 ? "s" : ""} supprimé${ok > 1 ? "s" : ""}`);
    } else {
      toast.error(`${ok} supprimé(s), ${failed.length} échec(s) : ${failed.join(", ")}`);
    }
    loadPosture();
  };

  if (loading) return <div className="bg-white border border-gray-200 rounded-xl p-8 text-center text-gray-400 text-sm">Chargement de la posture CVE...</div>;
  if (!posture) return null;

  const { summary, total_packages, scanned_packages, unscanned_packages, packages } = posture;
  const distributions = ["all", ...new Set(packages.map(p => p.distribution).filter(Boolean))];

  // Infer pkg_format from filename extension for each package
  const packagesWithFmt = packages.map(pkg => {
    if (pkg.pkg_format) return pkg;
    const fn = (pkg.filename || "").toLowerCase();
    const fmt = fn.endsWith(".rpm") ? "rpm" : fn.endsWith(".apk") ? "apk" : "deb";
    return { ...pkg, pkg_format: fmt };
  });

  // Filtrage
  const visible = packagesWithFmt.filter(pkg => {
    if (distFilter !== "all" && pkg.distribution !== distFilter) return false;
    if (fmtFilter !== "all" && pkg.pkg_format !== fmtFilter) return false;
    if (kevFilter && !pkg.kev_count) return false;
    if (sevFilter === "unscanned" && pkg.scanned) return false;
    if (sevFilter === "critical" && !(pkg.cve_counts?.critical > 0)) return false;
    if (sevFilter === "high"     && !(pkg.cve_counts?.high > 0)) return false;
    if (sevFilter === "medium"   && !(pkg.cve_counts?.medium > 0)) return false;
    if (sevFilter === "low"      && !(pkg.cve_counts?.low > 0)) return false;
    if (decisFilter === "pending"  && pkg.decision_action) return false;
    if (decisFilter === "decided"  && !pkg.decision_action) return false;
    if (decisFilter === "expiring" && pkg.sla_status !== "expiring_soon" && pkg.sla_status !== "expired") return false;
    if (decisFilter === "queue"    && pkg.status !== "pending_review" && pkg.status !== "blocked") return false;
    return true;
  });

  // File de révision : tri par score de risque combiné (sévérité + KEV + EPSS + exposition parc)
  if (decisFilter === "queue") {
    visible.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  }

  // Pagination client-side (pas de useEffect ici : on reset pkgPage dans chaque handler de filtre)
  const posturePages = Math.ceil(visible.length / POSTURE_PER_PAGE) || 1;
  const pageItems    = visible.slice((pkgPage - 1) * POSTURE_PER_PAGE, pkgPage * POSTURE_PER_PAGE);

  const hasCritical = (summary.critical || 0) > 0;
  const hasHigh = (summary.high || 0) > 0;
  const totalKev = packagesWithFmt.reduce((s, p) => s + (p.kev_count || 0), 0);
  const expiring = packagesWithFmt.filter(p => p.sla_status === "expiring_soon" || p.sla_status === "expired").length;
  const queueCount = packagesWithFmt.filter(p => p.status === "pending_review" || p.status === "blocked").length;
  const blockedCount = packagesWithFmt.filter(p => p.status === "blocked").length;

  return (
    <>
      {selectedPkg && <CveModal pkg={selectedPkg} onClose={() => setSelected(null)} />}

      {/* ── Bandeau "File de révision" — raccourci vers les paquets à décider ── */}
      {queueCount > 0 && decisFilter !== "queue" && (
        <button
          onClick={() => { setDecis("queue"); setSev("all"); setKev(false); setPkgPage(1); }}
          className="w-full flex items-center justify-between px-6 py-3 mb-4 rounded-xl border border-red-200 bg-red-50 hover:bg-red-100 transition-colors text-left"
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-red-100 rounded-xl flex items-center justify-center">
              <svg className="w-4.5 h-4.5 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-semibold text-red-900">
                {queueCount} paquet{queueCount > 1 ? "s" : ""} nécessite{queueCount > 1 ? "nt" : ""} une décision RSSI
              </p>
              <p className="text-xs text-red-600">
                {blockedCount > 0 && `${blockedCount} bloqué${blockedCount > 1 ? "s" : ""} · `}
                Décision requise avant publication dans le dépôt
              </p>
            </div>
          </div>
          <span className="text-xs font-semibold text-red-700">Voir la file de révision →</span>
        </button>
      )}

      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">

        {/* ── En-tête section ── */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${hasCritical ? "bg-red-50" : hasHigh ? "bg-orange-50" : "bg-green-50"}`}>
              <svg className={`w-5 h-5 ${hasCritical ? "text-red-500" : hasHigh ? "text-orange-500" : "text-green-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-semibold text-gray-900">Posture de sécurité — Inventaire CVE</h2>
              <p className="text-xs text-gray-400">
                {scanned_packages}/{total_packages} paquets scannés par Grype
                {unscanned_packages > 0 && <span className="text-amber-500 ml-1">· {unscanned_packages} non scanné{unscanned_packages > 1 ? "s" : ""}</span>}
                {totalKev > 0 && <span className="text-red-500 ml-1">· {totalKev} KEV CISA</span>}
                {expiring > 0 && <span className="text-orange-500 ml-1">· {expiring} décision{expiring > 1 ? "s" : ""} expir{expiring > 1 ? "ant" : "e"}</span>}
              </p>
            </div>
          </div>
          <button onClick={loadPosture} className="text-xs text-gray-400 hover:text-gray-600 flex items-center gap-1">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Actualiser
          </button>
        </div>

        {/* ── Bandeau compteurs par sévérité ── */}
        <div className="grid grid-cols-4 divide-x divide-gray-100">
          {[
            { key:"critical", label:"CRITICAL", bg:"bg-red-50",     dot:"bg-red-500",    num:"text-red-700",    text:"text-red-600"    },
            { key:"high",     label:"HIGH",     bg:"bg-orange-50",  dot:"bg-orange-500", num:"text-orange-700", text:"text-orange-600" },
            { key:"medium",   label:"MEDIUM",   bg:"bg-yellow-50",  dot:"bg-yellow-500", num:"text-yellow-700", text:"text-yellow-600" },
            { key:"low",      label:"LOW",      bg:"bg-blue-50",    dot:"bg-blue-400",   num:"text-blue-700",   text:"text-blue-600"   },
          ].map(({ key, label, bg, dot, num, text }) => (
            <button key={key} onClick={() => { setSev(sevFilter === key ? "all" : key); setPkgPage(1); }}
              className={`p-4 text-left transition-all ${bg} ${sevFilter === key ? "ring-2 ring-inset ring-blue-400" : "hover:brightness-95"}`}>
              <div className="flex items-center gap-1.5 mb-1">
                <span className={`text-xs font-bold uppercase tracking-wider ${text}`}>{label}</span>
              </div>
              <p className={`text-2xl font-bold font-mono ${num}`}>{summary[key] || 0}</p>
              <p className="text-xs text-gray-400 mt-0.5">CVE{(summary[key]||0)>1?"s":""} — cliquer pour filtrer</p>
            </button>
          ))}
        </div>

        {/* ── Séparateur avec titre table ── */}
        <div className="flex items-center gap-4 px-6 py-3 bg-gray-50 border-y border-gray-100">
          <div className="flex items-center gap-2 flex-1">
            <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16"/>
            </svg>
            <span className="text-xs font-bold text-gray-600 uppercase tracking-wider">
              Liste des paquets
            </span>
            <span className="text-xs text-gray-400">
              — {visible.length} / {packages.length} paquet{visible.length > 1 ? "s" : ""}
            </span>
          </div>
          {/* Filtres */}
          <div className="flex items-center gap-2 flex-wrap">
            {/* Format */}
            <select value={fmtFilter} onChange={e => { setFmt(e.target.value); setPkgPage(1); }}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 cursor-pointer">
              <option value="all">Tous formats</option>
              <option value="deb">DEB</option>
              <option value="rpm">RPM</option>
              <option value="apk">APK</option>
            </select>
            {/* Distribution */}
            {distributions.length > 2 && (
              <select value={distFilter} onChange={e => { setDist(e.target.value); setPkgPage(1); }}
                className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 cursor-pointer">
                {distributions.map(d => <option key={d} value={d}>{d === "all" ? "Toutes distrib." : d}</option>)}
              </select>
            )}
            {/* Statut décision */}
            <select value={decisFilter} onChange={e => { setDecis(e.target.value); setPkgPage(1); }}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 cursor-pointer">
              <option value="all">Toutes décisions</option>
              <option value="queue">File de révision</option>
              <option value="pending">Sans décision</option>
              <option value="decided">Décision prise</option>
              <option value="expiring">SLA expirant</option>
            </select>
            {/* Sévérité */}
            <select value={sevFilter} onChange={e => { setSev(e.target.value); setPkgPage(1); }}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 cursor-pointer">
              <option value="all">Toutes sévérités</option>
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
              <option value="unscanned">Non scanné</option>
            </select>
            {/* KEV toggle */}
            <button onClick={() => { setKev(!kevFilter); setPkgPage(1); }}
              className={`text-xs px-2.5 py-1.5 rounded-lg font-medium border transition-colors ${
                kevFilter ? "bg-red-600 text-white border-red-600" : "bg-white text-gray-500 border-gray-200 hover:border-red-300 hover:text-red-600"
              }`}>
              <svg className="w-3.5 h-3.5 inline" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> KEV seulement
            </button>
            {/* Reset filtres */}
            {(sevFilter !== "all" || kevFilter || decisFilter !== "all" || distFilter !== "all" || fmtFilter !== "all") && (
              <button onClick={() => { setSev("all"); setKev(false); setDecis("all"); setDist("all"); setFmt("all"); setPkgPage(1); }}
                className="text-xs text-gray-400 hover:text-gray-600 px-1">
                <svg className="w-3.5 h-3.5 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Réinitialiser
              </button>
            )}
          </div>
        </div>

        {/* ── Barre d'action groupée (suppression multiple) ── */}
        {checkedKeys.size > 0 && (
          <div className="flex items-center justify-between px-6 py-2.5 bg-red-50 border-y border-red-100">
            <span className="text-xs font-medium text-red-700">
              {checkedKeys.size} paquet{checkedKeys.size > 1 ? "s" : ""} sélectionné{checkedKeys.size > 1 ? "s" : ""}
            </span>
            <div className="flex items-center gap-2">
              <button onClick={() => setChecked(new Set())} className="text-xs text-gray-500 hover:text-gray-700 px-2 py-1">
                Désélectionner
              </button>
              <button
                onClick={() => handleBulkDelete(visible.filter((p) => checkedKeys.has(`${p.name}@${p.version}`)))}
                disabled={bulkDeleting}
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-white bg-red-600 hover:bg-red-700 disabled:opacity-40 px-3 py-1.5 rounded-lg transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                {bulkDeleting ? "Suppression..." : `Supprimer (${checkedKeys.size})`}
              </button>
            </div>
          </div>
        )}

        {/* ── Table ── */}
        {visible.length === 0 ? (
          <div className="p-10 text-center text-gray-400 text-sm">
            Aucun paquet ne correspond aux filtres sélectionnés.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-100">
                <tr>
                  <th className="px-4 py-3 w-8">
                    <input
                      type="checkbox"
                      className="rounded border-gray-300 text-red-600 focus:ring-red-200"
                      checked={pageItems.length > 0 && pageItems.every((p) => checkedKeys.has(`${p.name}@${p.version}`))}
                      onChange={() => toggleCheckAll(pageItems)}
                      title="Sélectionner tout (page courante)"
                    />
                  </th>
                  {[
                    { label: "Paquet / Version",     w: "w-48" },
                    { label: "Distrib.",              w: "w-24" },
                    { label: "CVE (Grype)",           w: "w-40" },
                    { label: "KEV / EPSS",            w: "w-28" },
                    { label: "Décision RSSI",         w: "w-36" },
                    { label: "Intégrité",             w: "w-24" },
                    { label: "Actions",               w: "",    right: true },
                  ].map(({ label, w, right }) => (
                    <th key={label} className={`px-4 py-3 ${right ? "text-right" : "text-left"} text-xs font-semibold text-gray-500 uppercase tracking-wider ${w}`}>
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {pageItems.map((pkg) => {
                  const pkey = `${pkg.name}@${pkg.version}`;
                  const isConfirming = confirmPkg?.name === pkg.name;
                  const isLoading = (k) => actionLoading === `${k}:${pkg.name}`;
                  const needsDecision = !pkg.decision_action && pkg.scanned && pkg.total_cve > 0 && pkg.status !== "superseded";
                  const rowBg =
                    pkg.status === "quarantined"    ? "bg-blue-50/40" :
                    pkg.cve_counts?.critical > 0   ? "bg-red-50/30 hover:bg-red-50/60" :
                    pkg.cve_counts?.high > 0       ? "bg-orange-50/20 hover:bg-orange-50/50" :
                    "hover:bg-gray-50/60";

                  return (
                    <tr key={pkey} className={`transition-colors ${rowBg}`}>

                      {/* Sélection (suppression multiple) */}
                      <td className="px-4 py-3">
                        <input
                          type="checkbox"
                          className="rounded border-gray-300 text-red-600 focus:ring-red-200"
                          checked={checkedKeys.has(pkey)}
                          onChange={() => toggleChecked(pkey)}
                        />
                      </td>

                      {/* Paquet */}
                      <td className="px-4 py-3">
                        <div>
                          <p className="font-mono font-semibold text-gray-900 text-sm">{pkg.name}</p>
                          <p className="font-mono text-xs text-gray-400">{pkg.version}</p>
                          {pkg.status === "quarantined" && (
                            <span className="text-xs px-1.5 py-0.5 bg-blue-100 text-blue-700 rounded font-medium">Quarantaine</span>
                          )}
                          {pkg.status === "pending_review" && (
                            <span className="text-xs px-1.5 py-0.5 bg-amber-100 text-amber-700 rounded font-medium">En révision</span>
                          )}
                          {pkg.status === "blocked" && (
                            <span className="text-xs px-1.5 py-0.5 bg-red-100 text-red-700 rounded font-medium">Bloqué</span>
                          )}
                          {pkg.status === "superseded" && (
                            <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded font-medium" title="Une version plus récente est déjà validée et publiée dans le dépôt">Remplacé</span>
                          )}
                          {decisFilter === "queue" && (
                            <span className="text-xs px-1.5 py-0.5 bg-slate-100 text-slate-600 rounded font-medium font-mono ml-1" title="Score de risque (sévérité + KEV + EPSS + exposition parc)">
                              Risque {pkg.risk_score}
                            </span>
                          )}
                          <InstallBadge count={pkg.install_count} clients={pkg.install_clients} />
                        </div>
                      </td>

                      {/* Distribution + Format */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs px-2 py-0.5 bg-gray-100 text-gray-600 rounded-full font-mono w-fit">
                            {pkg.distribution || "—"}
                          </span>
                          {pkg.pkg_format && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wide w-fit" style={{
                              backgroundColor: pkg.pkg_format === "rpm" ? "#ffedd5" : pkg.pkg_format === "apk" ? "#ccfbf1" : "#ede9fe",
                              color:           pkg.pkg_format === "rpm" ? "#ea580c" : pkg.pkg_format === "apk" ? "#0d9488" : "#7c3aed",
                            }}>
                              {pkg.pkg_format.toUpperCase()}
                            </span>
                          )}
                        </div>
                      </td>

                      {/* CVE */}
                      <td className="px-4 py-3">
                        {!pkg.scanned ? (
                          <span className="text-xs text-amber-500 font-medium">Non scanné</span>
                        ) : pkg.total_cve === 0 ? (
                          <span className="inline-flex items-center gap-1 text-xs text-green-600 font-medium">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7"/>
                            </svg>
                            Clean
                          </span>
                        ) : (
                          <div className="flex flex-wrap gap-1">
                            {_sev_order.slice(0,4).map(s => {
                              const cnt = pkg.cve_counts?.[s.toLowerCase()];
                              return cnt > 0 ? <SevBadge key={s} severity={s} count={cnt} /> : null;
                            })}
                          </div>
                        )}
                      </td>

                      {/* KEV / EPSS */}
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          {pkg.kev_count > 0 && (
                            <span className="inline-flex items-center gap-1 text-xs font-bold text-red-700 bg-red-50 px-1.5 py-0.5 rounded">
                              <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> {pkg.kev_count} KEV
                            </span>
                          )}
                          {pkg.high_epss_count > 0 && (
                            <span className="inline-flex items-center gap-1 text-xs font-semibold text-orange-700 bg-orange-50 px-1.5 py-0.5 rounded">
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> EPSS ≥10% ({pkg.high_epss_count})
                            </span>
                          )}
                          {!pkg.kev_count && !pkg.high_epss_count && (
                            <span className="text-xs text-gray-300">—</span>
                          )}
                        </div>
                      </td>

                      {/* Décision RSSI */}
                      <td className="px-4 py-3">
                        {needsDecision ? (
                          <span className="text-xs text-orange-600 font-medium bg-orange-50 px-2 py-0.5 rounded inline-flex items-center gap-1">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> À traiter
                          </span>
                        ) : (
                          <DecisionBadge
                            action={pkg.decision_action}
                            slaStatus={pkg.sla_status}
                            slaDays={pkg.sla_days}
                          />
                        )}
                      </td>

                      {/* Intégrité */}
                      <td className="px-4 py-3">
                        {pkg.hash_verified ? (
                          <span className="text-xs text-green-600 font-medium flex items-center gap-1">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7"/>
                            </svg>
                            SHA-256
                          </span>
                        ) : <span className="text-xs text-gray-300">—</span>}
                      </td>

                      {/* Actions */}
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1.5 flex-wrap">

                          {/* Voir CVE */}
                          {pkg.scanned && (
                            <button onClick={() => setSelected(pkg)}
                              title="Voir le détail des CVE"
                              className="inline-flex items-center gap-1 px-2 py-1.5 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0zM2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                              </svg>
                              CVE
                            </button>
                          )}

                          {/* Décider (RSSI) */}
                          {(needsDecision || pkg.status === "pending_review" || pkg.status === "blocked") && (
                            <button onClick={() => onDecideRequest(pkg)}
                              title="Prendre une décision RSSI"
                              className="inline-flex items-center gap-1 px-2 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                              </svg>
                              Décider
                            </button>
                          )}

                          {/* Quarantaine */}
                          {pkg.status !== "quarantined" && (pkg.cve_counts?.critical > 0 || pkg.status === "blocked") && (
                            <button onClick={() => handleQuarantine(pkg)} disabled={isLoading("q")}
                              title={isConfirming ? "Cliquer à nouveau pour confirmer" : "Mettre en quarantaine"}
                              className={`inline-flex items-center gap-1 px-2 py-1.5 text-xs font-medium rounded-lg transition-colors disabled:opacity-40 ${
                                isConfirming ? "bg-red-600 text-white" : "text-red-600 bg-red-50 hover:bg-red-100"
                              }`}>
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                              </svg>
                              {isConfirming ? "Confirmer ?" : "Quarantaine"}
                            </button>
                          )}
                          {isConfirming && (
                            <button onClick={() => setConfirm(null)} className="text-xs text-gray-400 hover:text-gray-600 px-1"><svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
                          )}

                          {/* Rescanner */}
                          <button onClick={() => handleRescan(pkg)} disabled={isLoading("r")}
                            title="Relancer le scan CVE Grype"
                            className="inline-flex items-center gap-1 px-2 py-1.5 text-xs font-medium text-gray-500 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors disabled:opacity-40">
                            {isLoading("r") ? (
                              <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                              </svg>
                            ) : (
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                              </svg>
                            )}
                            Rescanner
                          </button>

                          {/* Supprimer */}
                          <button onClick={() => handleDelete(pkg)} disabled={isLoading("d")}
                            title="Supprimer définitivement du dépôt"
                            className="p-1.5 text-gray-300 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-40">
                            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {/* Pagination posture (client-side sur résultats filtrés) */}
        <Paginator
          page={pkgPage}
          pages={posturePages}
          total={visible.length}
          perPage={POSTURE_PER_PAGE}
          onPageChange={setPkgPage}
        />
      </div>
    </>
  );
}

function StatusBadge({ ok, label }) {
  return ok ? (
    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
      {label}
    </span>
  ) : (
    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-red-100 text-red-600">
      {label}
    </span>
  );
}

export default function SecurityPage() {
  const [status, setStatus]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [logs, setLogs]       = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone]       = useState(false);
  const [postureKey, setPostureKey] = useState(0);
  const [directDecide, setDirectDecide] = useState(null);  // pkg à décider depuis le tableau posture
  const logsRef = useRef(null);

  useEffect(() => { loadStatus(); }, []);

  useEffect(() => {
    if (done) {
      setTimeout(() => loadStatus(), 1000);
    }
  }, [done]);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const loadStatus = async () => {
    setLoading(true);
    try {
      const data = await getClamavStatus();
      setStatus(data);
    } catch {
      toast.error("Impossible de charger le statut ClamAV");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = () => {
    setLogs([]);
    setDone(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    fetch(`${API_URL}/security/clamav/update`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    }).then(async (resp) => {
      if (!resp.ok) {
        setLogs([`error|Erreur serveur (${resp.status})`]);
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
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
          if (payload.startsWith("done|")) { setDone(true); setRunning(false); }
        }
      }
      setRunning(false);
    }).catch((e) => {
      setLogs([`error|${e.message}`]);
      setRunning(false);
    });
  };

  return (
    <div className="space-y-6 max-w-full p-6">
      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Sécurité</h1>
          <p className="text-sm text-gray-500 mt-1">
            Posture CVE des paquets, antivirus et contrôles de sécurité des binaires.
          </p>
        </div>
        <button
          onClick={() => window.open("/security/report", "_blank")}
          className="flex items-center gap-2 text-sm font-medium text-gray-600 hover:text-blue-700 bg-white border border-gray-200 hover:border-blue-300 rounded-xl px-4 py-2 transition-colors shadow-sm"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3M3 17V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
          </svg>
          Rapport PDF
        </button>
      </div>

      {/* Modal décision directe depuis le tableau posture */}
      {directDecide && (
        <DecisionModal
          pkg={directDecide}
          onClose={() => setDirectDecide(null)}
          onDecided={() => { setDirectDecide(null); setPostureKey(k => k + 1); }}
        />
      )}

      {/* Section Posture CVE */}
      <CvePostureSection key={postureKey} onDecideRequest={setDirectDecide} />

      {/* Suivi des décisions RSSI (audit) */}
      <DecisionsTrackingSection />

      {/* Carte ClamAV */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        {/* En-tête carte */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center">
              <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h2 className="text-sm font-semibold text-gray-900">ClamAV</h2>
              <p className="text-xs text-gray-400">Antivirus open-source — scan des binaires à l'import</p>
            </div>
          </div>
          {!loading && status && (
            <div className="flex items-center gap-2">
              <StatusBadge ok={status.available} label={status.available ? "Actif" : "Inactif"} />
              <StatusBadge ok={status.daemon_running} label={status.daemon_running ? "Daemon actif" : "Daemon arrêté"} />
            </div>
          )}
        </div>

        {loading ? (
          <div className="p-8 text-center text-gray-400 text-sm">Chargement...</div>
        ) : !status?.available ? (
          <div className="p-8 text-center text-red-400 text-sm">
            ClamAV n'est pas disponible dans ce conteneur.
          </div>
        ) : (
          <div className="p-6 space-y-6">
            {/* Infos version */}
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Version</p>
                <p className="text-lg font-bold text-gray-900 font-mono">{status.version || "–"}</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Version DB</p>
                <p className="text-lg font-bold text-gray-900 font-mono">{status.db_version || "–"}</p>
              </div>
              <div className="bg-gray-50 rounded-lg p-4">
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Date DB</p>
                <p className="text-sm font-semibold text-gray-700">{status.db_date || "–"}</p>
              </div>
            </div>

            {/* Fichiers de la DB */}
            {status.db_files?.length > 0 && (
              <div>
                <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                  Fichiers de signatures ({status.db_files.length})
                </h3>
                <div className="border border-gray-200 rounded-lg overflow-hidden">
                  <table className="w-full">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Fichier</th>
                        <th className="px-4 py-2 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider">Taille</th>
                        <th className="px-4 py-2 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider">Modifié</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {status.db_files.map((f, i) => (
                        <tr key={i} className="hover:bg-gray-50">
                          <td className="px-4 py-2.5 text-sm font-mono text-gray-800">{f.name}</td>
                          <td className="px-4 py-2.5 text-xs text-right text-gray-500 font-mono">{formatBytes(f.size_bytes)}</td>
                          <td className="px-4 py-2.5 text-xs text-right text-gray-400">
                            {new Date(f.modified_at).toLocaleString("fr-FR")}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p className="text-xs text-gray-400 mt-1.5">
                  Stockés sur le volume hôte — persistants entre les redémarrages.
                </p>
              </div>
            )}

            {/* Mise à jour manuelle */}
            <div className="border-t border-gray-100 pt-5">
              {/* Cooldown warning */}
              {status?.cooldown_until && new Date(status.cooldown_until) > new Date() && (
                <div className="mb-4 flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg px-4 py-3">
                  <svg className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <div>
                    <p className="text-xs font-semibold text-amber-800">Rate limit CDN ClamAV</p>
                    <p className="text-xs text-amber-700 mt-0.5">
                      Trop de requêtes récentes. Mise à jour disponible après{" "}
                      <strong>{new Date(status.cooldown_until).toLocaleTimeString("fr-FR")}</strong>.
                      Le daemon mettra à jour automatiquement dès que possible.
                    </p>
                  </div>
                </div>
              )}
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold text-gray-800">Mise à jour manuelle</h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    La base se met aussi à jour automatiquement toutes les 12h via le daemon.
                  </p>
                </div>
                <button
                  onClick={handleUpdate}
                  disabled={running || (status?.cooldown_until && new Date(status.cooldown_until) > new Date())}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium
                             rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  {running ? (
                    <>
                      <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      Mise à jour...
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      Mettre à jour maintenant
                    </>
                  )}
                </button>
              </div>

              {/* Logs SSE */}
              {logs.length > 0 && (
                <div className="border border-gray-800 rounded-xl bg-gray-900 p-4">
                  <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    Progression
                    {done && <span className="text-green-400 ml-2">— Terminé</span>}
                    {running && <span className="text-yellow-400 ml-2">— En cours...</span>}
                  </p>
                  <div ref={logsRef} className="max-h-56 overflow-y-auto space-y-0.5">
                    {logs.map((line, i) => <LogLine key={i} line={line} />)}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

    </div>
  );
}
