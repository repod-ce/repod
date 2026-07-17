import { useState, useEffect, useRef } from "react";
import toast from "react-hot-toast";
import {
  getDistributions, getDistribPackages,
  promotePackage, migrateDistrib, initDistributions,
} from "../api";
import {
  SiUbuntu, SiDebian, SiAlmalinux, SiRockylinux,
  SiCentos, SiFedora, SiOpensuse,
} from "react-icons/si";

// Couleurs officielles de marque
const OS_COLORS = {
  ubuntu:      { bg: "bg-orange-50",  border: "border-orange-200",  badge: "bg-orange-100 text-orange-700",   icon: "#E95420" },
  debian:      { bg: "bg-red-50",     border: "border-red-200",     badge: "bg-red-100 text-red-700",         icon: "#A80030" },
  almalinux:   { bg: "bg-blue-50",    border: "border-blue-200",    badge: "bg-blue-100 text-blue-700",       icon: "#0F4266" },
  rocky:       { bg: "bg-green-50",   border: "border-green-200",   badge: "bg-green-100 text-green-700",     icon: "#10B981" },
  centos:      { bg: "bg-purple-50",  border: "border-purple-200",  badge: "bg-purple-100 text-purple-700",   icon: "#262577" },
  oraclelinux: { bg: "bg-red-50",     border: "border-red-200",     badge: "bg-red-100 text-red-800",         icon: "#F80000" },
  fedora:      { bg: "bg-indigo-50",  border: "border-indigo-200",  badge: "bg-indigo-100 text-indigo-700",   icon: "#51A2DA" },
  opensuse:    { bg: "bg-teal-50",    border: "border-teal-200",    badge: "bg-teal-100 text-teal-700",       icon: "#73BA25" },
  alpine:      { bg: "bg-emerald-50", border: "border-emerald-200", badge: "bg-emerald-100 text-emerald-700", icon: "#0D597F" },
};

// Logo officiel par OS — Oracle Linux n'a pas d'icône simple-icons → tour serveur SVG
function OsIcon({ os, size = 22 }) {
  const color = OS_COLORS[os]?.icon || "#6B7280";
  const props = { size, color };
  switch (os) {
    case "ubuntu":      return <SiUbuntu      {...props} />;
    case "debian":      return <SiDebian      {...props} />;
    case "almalinux":   return <SiAlmalinux   {...props} />;
    case "rocky":       return <SiRockylinux  {...props} />;
    case "centos":      return <SiCentos      {...props} />;
    case "fedora":      return <SiFedora      {...props} />;
    case "opensuse":    return <SiOpensuse    {...props} />;
    case "alpine":
      // Montagne SVG (Alpine Linux)
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill={color}>
          <path d="M12 2L2 20h20L12 2z" fillOpacity="0.15" stroke={color} strokeWidth="1.5" strokeLinejoin="round"/>
          <path d="M8 20L12 10l4 10" fillOpacity="0.35" fill={color} stroke={color} strokeWidth="0.5"/>
        </svg>
      );
    default:
      // Tour serveur SVG générique (Oracle Linux + inconnus)
      return (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
          <rect x="3" y="2" width="18" height="20" rx="2" stroke={color} strokeWidth="1.5" fill={color} fillOpacity="0.08"/>
          <rect x="5.5" y="5"  width="13" height="3.5" rx="1" fill={color} fillOpacity="0.35"/>
          <rect x="5.5" y="10" width="13" height="3.5" rx="1" fill={color} fillOpacity="0.35"/>
          <rect x="5.5" y="15" width="13" height="3.5" rx="1" fill={color} fillOpacity="0.20"/>
          <circle cx="16.5" cy="6.75"  r="1" fill={color}/>
          <circle cx="16.5" cy="11.75" r="1" fill="#22C55E"/>
          <circle cx="16.5" cy="16.75" r="1" fill={color} fillOpacity="0.4"/>
        </svg>
      );
  }
}

function FormatBadge({ format }) {
  if (format === "rpm")
    return <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-red-100 text-red-700">RPM</span>;
  if (format === "apk")
    return <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700">APK</span>;
  return <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700">DEB</span>;
}

function DistribCard({ distrib, onSelect, selected }) {
  const c = OS_COLORS[distrib.os] || OS_COLORS.ubuntu;
  return (
    <button
      onClick={() => onSelect(distrib.codename)}
      className={`text-left w-full rounded-xl border-2 p-5 transition-all ${
        selected ? "border-blue-500 bg-blue-50" : `${c.border} ${c.bg} hover:border-blue-300`
      }`}
    >
      <div className="flex items-start justify-between mb-3">
        <div className={`w-10 h-10 rounded-xl ${selected ? "bg-blue-100" : "bg-white"} flex items-center justify-center shadow-sm border border-gray-100`}>
          <OsIcon os={distrib.os} size={22} />
        </div>
        <div className="flex flex-col items-end gap-1">
          {distrib.badge && <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${c.badge}`}>{distrib.badge}</span>}
          {distrib.format && <FormatBadge format={distrib.format} />}
        </div>
      </div>
      <p className="font-bold text-gray-900">{distrib.name}</p>
      <p className="text-xs text-gray-500 font-mono mt-0.5">{distrib.codename}</p>
      <p className="text-2xl font-bold text-gray-800 mt-3">{distrib.package_count}</p>
      <p className="text-xs text-gray-400">paquet(s)</p>
    </button>
  );
}

// ─── Ligne compacte style GitHub ─────────────────────────────────────────────

function DistribRow({ distrib, onSelect, selected }) {
  const c = OS_COLORS[distrib.os] || OS_COLORS.ubuntu;
  return (
    <button
      onClick={() => onSelect(distrib.codename)}
      className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl border transition-all text-left ${
        selected
          ? "border-blue-400 bg-blue-50 ring-1 ring-blue-300"
          : "border-gray-200 bg-white hover:border-gray-300 hover:bg-gray-50"
      }`}
    >
      {/* Icône ronde */}
      <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 border ${
        selected ? "border-blue-200 bg-blue-100" : `border-gray-100 ${c.bg}`
      }`}>
        <OsIcon os={distrib.os} size={18} />
      </div>
      {/* Nom + slug */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-sm text-gray-900">{distrib.name}</span>
          <code className="text-xs text-gray-400 font-mono">{distrib.codename}</code>
        </div>
      </div>
      {/* Badge + compteur + chevron */}
      <div className="flex items-center gap-2 shrink-0">
        {distrib.badge && (
          <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${c.badge}`}>
            {distrib.badge}
          </span>
        )}
        {distrib.format && <FormatBadge format={distrib.format} />}
        <span className="flex items-center gap-1 text-xs text-gray-500">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10" />
          </svg>
          {distrib.package_count}
        </span>
        <svg className={`w-4 h-4 transition-colors ${selected ? "text-blue-500" : "text-gray-300"}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </button>
  );
}

// ─── Panneau latéral slide-in ─────────────────────────────────────────────────

function DistribPanel({ distrib, packages, loading, onClose, onPromote }) {
  const [search, setSearch] = useState("");
  if (!distrib) return null;
  const c = OS_COLORS[distrib.os] || OS_COLORS.ubuntu;
  const filtered = packages.filter(
    (p) => !search || p.name.toLowerCase().includes(search.toLowerCase())
  );
  return (
    <div
      className="min-w-0 bg-white border border-gray-200 rounded-xl overflow-hidden flex flex-col"
      style={{ flex: "3 1 0%", minWidth: "400px", position: "sticky", top: "1rem", height: "calc(100vh - 5rem)" }}
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3.5 border-b border-gray-100">
        <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${c.bg} border border-gray-100`}>
          <OsIcon os={distrib.os} size={18} />
        </div>
        <p className="flex-1 font-semibold text-sm text-gray-900 truncate">{distrib.name}</p>
        <button onClick={onClose}
          className="p-1.5 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100 transition-colors">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Meta : slug / type / paquets */}
      <div className="grid grid-cols-3 divide-x divide-gray-100 border-b border-gray-100 bg-gray-50">
        <div className="px-2 py-2.5 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide font-medium">SLUG</p>
          <p className="font-mono text-xs text-gray-700 mt-0.5 truncate">{distrib.codename}</p>
        </div>
        <div className="px-2 py-2.5 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide font-medium">TYPE</p>
          <p className="mt-0.5 flex justify-center">
            <FormatBadge format={distrib.format || (distrib.os === "alpine" ? "apk" : "deb")} />
          </p>
        </div>
        <div className="px-2 py-2.5 text-center">
          <p className="text-xs text-gray-400 uppercase tracking-wide font-medium">PAQUETS</p>
          <p className="text-sm font-bold text-gray-800 mt-0.5">{distrib.package_count}</p>
        </div>
      </div>

      {/* Snippet de configuration client APK */}
      {(distrib.format === "apk" || distrib.os === "alpine") && (
        <div className="px-3 py-2.5 border-b border-emerald-100 bg-emerald-50">
          <p className="text-xs font-bold text-emerald-700 uppercase tracking-wide mb-1">
            Configuration client Alpine
          </p>
          <code className="block text-xs font-mono text-emerald-800 bg-white border border-emerald-100 rounded px-2 py-1.5 select-all whitespace-pre-wrap break-all">
            {`echo "https://<HOST>/apk/${distrib.codename}/main" >> /etc/apk/repositories\napk update`}
          </code>
        </div>
      )}

      {/* Barre de recherche */}
      <div className="px-3 py-2 border-b border-gray-100">
        <div className="relative">
          <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-400"
            fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0" />
          </svg>
          <input
            type="text"
            placeholder="Rechercher un paquet..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-2 text-xs border border-gray-200 rounded-lg
                       focus:outline-none focus:ring-1 focus:ring-blue-400 bg-gray-50"
          />
        </div>
      </div>

      {/* Liste scrollable des paquets */}
      <div className="overflow-y-auto flex-1">
        {loading ? (
          <p className="text-xs text-gray-400 text-center p-6">Chargement...</p>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-8 text-gray-400 gap-2">
            <svg className="w-8 h-8 text-gray-200" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
            </svg>
            <p className="text-xs">
              {search ? "Aucun résultat" : "Aucun paquet pour cette distribution"}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {filtered.map((pkg) => (
              <div key={pkg.name}
                className="group flex items-center justify-between px-4 py-2.5 hover:bg-blue-50 transition-colors">
                <div className="min-w-0 flex items-center gap-2 flex-1">
                  <span className="font-mono text-xs font-medium text-gray-900 truncate">{pkg.name}</span>
                  <span className="text-xs text-gray-400 shrink-0">{pkg.version}</span>
                </div>
                {onPromote && (
                  <button
                    onClick={() => onPromote(pkg.name)}
                    className="ml-2 shrink-0 opacity-0 group-hover:opacity-100 flex items-center gap-1
                               text-xs font-medium text-blue-600 hover:text-blue-800 transition-opacity"
                    title={`Promouvoir ${pkg.name}`}
                  >
                    Promouvoir
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                    </svg>
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Panneau promotion ────────────────────────────────────────────────────────

function PromotePanel({ distribs, onClose, onDone, initialPkg = "", initialFromDist = "" }) {
  const firstDist = initialFromDist || distribs[0]?.codename || "";
  const [pkg, setPkg] = useState(initialPkg);
  const [fromDist, setFromDist] = useState(firstDist);
  // toDist : première distrib du même format ≠ fromDist
  const [toDist, setToDist] = useState(() => {
    const fromFmt = distribs.find((d) => d.codename === firstDist)?.format;
    const candidates = distribs.filter((d) => d.codename !== firstDist && (!fromFmt || !d.format || d.format === fromFmt));
    return candidates[0]?.codename || distribs[1]?.codename || "";
  });
  const [loading, setLoading] = useState(false);
  const [packages, setPackages] = useState([]);
  const [loadingPkgs, setLoadingPkgs] = useState(false);

  // Quand fromDist change, recalculer toDist dans le même format
  const fromFormat = distribs.find((d) => d.codename === fromDist)?.format;
  const sameFormatDists = distribs.filter((d) => !d.format || !fromFormat || d.format === fromFormat);
  const codenames = sameFormatDists.map((d) => d.codename);

  useEffect(() => {
    const candidates = sameFormatDists.filter((d) => d.codename !== fromDist);
    if (candidates.length > 0 && !candidates.find((d) => d.codename === toDist)) {
      setToDist(candidates[0].codename);
    }
  }, [fromDist]); // eslint-disable-line

  useEffect(() => {
    if (!fromDist) return;
    setLoadingPkgs(true);
    getDistribPackages(fromDist)
      .then((d) => setPackages(d.packages || []))
      .catch(() => setPackages([]))
      .finally(() => setLoadingPkgs(false));
  }, [fromDist]);

  const handlePromote = async () => {
    if (!pkg) { toast.error("Sélectionnez un paquet"); return; }
    if (fromDist === toDist) { toast.error("Source et destination identiques"); return; }
    setLoading(true);
    try {
      const res = await promotePackage(pkg, fromDist, toDist);
      toast.success(res.message);
      onDone();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la promotion");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      <div className="fixed inset-0 z-50 flex items-center justify-center p-6">
        <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md">
          <div className="flex items-center justify-between p-6 border-b border-gray-100">
            <div>
              <h2 className="font-bold text-gray-900">Promouvoir un paquet</h2>
              <p className="text-xs text-gray-500 mt-0.5">Copie un paquet d'une distribution vers une autre</p>
            </div>
            <button onClick={onClose} className="p-1.5 text-gray-400 hover:text-gray-600 rounded-lg">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="p-6 space-y-4">
            {/* From */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Distribution source</label>
              <select value={fromDist} onChange={(e) => { setFromDist(e.target.value); setPkg(""); }}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                {codenames.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            {/* Package */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Paquet</label>
              {loadingPkgs ? (
                <p className="text-xs text-gray-400 italic">Chargement...</p>
              ) : (
                <select value={pkg} onChange={(e) => setPkg(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option value="">-- Sélectionner --</option>
                  {packages.map((p) => <option key={p.name} value={p.name}>{p.name} ({p.version})</option>)}
                </select>
              )}
            </div>
            {/* To */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1.5">Distribution destination</label>
              <select value={toDist} onChange={(e) => setToDist(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                {codenames.filter((c) => c !== fromDist).map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            {/* Arrow visual */}
            <div className="flex items-center gap-3 bg-gray-50 border border-gray-200 rounded-lg px-4 py-3 text-sm">
              <span className="font-mono font-semibold text-gray-700">{pkg || "…"}</span>
              <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
              <span className="font-mono text-blue-600 font-semibold">{toDist}</span>
            </div>
            <button
              onClick={handlePromote}
              disabled={loading || !pkg}
              className="w-full py-3 bg-blue-600 text-white text-sm font-medium rounded-xl hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {loading ? "Promotion en cours..." : "Promouvoir"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function DistributionsPage() {
  const [distribs, setDistribs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDist, setSelectedDist] = useState(null);
  const [distPackages, setDistPackages] = useState([]);
  const [loadingPkgs, setLoadingPkgs] = useState(false);
  const [showPromote, setShowPromote]   = useState(false);
  const [promoteInit, setPromoteInit]   = useState({ pkg: "", fromDist: "" });
  const [migrating, setMigrating] = useState(false);
  const [initing, setIniting] = useState(false);
  const [formatFilter, setFormatFilter] = useState("all"); // "all" | "deb" | "rpm" | "apk"

  // Évite de relancer l'auto-init en boucle sur le même montage
  const autoInitDone = useRef(false);

  useEffect(() => { load(); }, []);

  // Auto-init silencieux : uniquement pour les distributions APT (reprepro)
  useEffect(() => {
    if (autoInitDone.current) return;
    const aptDists = distribs.filter((d) => d.format !== "rpm");
    if (aptDists.length > 0 && aptDists.every((d) => d.package_count === 0)) {
      autoInitDone.current = true;
      initDistributions()
        .then(() => load())
        .catch(() => {}); // silencieux — l'utilisateur peut relancer manuellement
    }
  }, [distribs]); // eslint-disable-line

  useEffect(() => {
    if (!selectedDist) return;
    setLoadingPkgs(true);
    getDistribPackages(selectedDist)
      .then((d) => setDistPackages(d.packages || []))
      .catch(() => setDistPackages([]))
      .finally(() => setLoadingPkgs(false));
  }, [selectedDist]);

  const load = async () => {
    setLoading(true);
    try {
      const data = await getDistributions();
      setDistribs(data.distributions || []);
    } catch {
      toast.error("Impossible de charger les distributions");
    } finally {
      setLoading(false);
    }
  };

  const handleInit = async () => {
    if (!window.confirm("Initialiser les distributions (APT, RPM, APK) ?")) return;
    setIniting(true);
    try {
      const res = await initDistributions();
      // La réponse peut être à plat {results:[]} ou multi-format {apt:{results:[]}, rpm:{...}, apk:{...}}
      let allResults = [];
      if (Array.isArray(res.results)) {
        allResults = res.results;
      } else {
        ["apt", "rpm", "apk"].forEach((fmt) => {
          if (Array.isArray(res[fmt]?.results)) allResults.push(...res[fmt].results);
        });
      }
      const ok    = allResults.filter((r) => r.ok).length;
      const total = allResults.length;
      const fails = allResults.filter((r) => !r.ok).length;
      if (fails === 0) {
        toast.success(`${ok}/${total} distributions initialisées`);
      } else {
        toast.success(`${ok}/${total} initialisées (${fails} ignorées — format non applicable)`);
      }
      load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur d'initialisation");
    } finally {
      setIniting(false);
    }
  };

  const handleMigrate = async () => {
    if (!window.confirm("Migrer tous les paquets de bookworm → jammy ?\n\nCela copiera les paquets existants et mettra à jour les manifests.")) return;
    setMigrating(true);
    try {
      const res = await migrateDistrib("bookworm", "jammy");
      toast.success(`Migration terminée : ${res.migrated} paquet(s) copié(s), ${res.manifests_updated} manifest(s) mis à jour`);
      load();
      if (selectedDist) {
        getDistribPackages(selectedDist)
          .then((d) => setDistPackages(d.packages || []));
      }
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la migration");
    } finally {
      setMigrating(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-gray-400 text-sm">Chargement...</div>;
  }

  return (
    <div className="space-y-6 p-6">
      {showPromote && (
        <PromotePanel
          distribs={distribs}
          initialPkg={promoteInit.pkg}
          initialFromDist={promoteInit.fromDist}
          onClose={() => { setShowPromote(false); setPromoteInit({ pkg: "", fromDist: "" }); }}
          onDone={() => { setShowPromote(false); setPromoteInit({ pkg: "", fromDist: "" }); load(); }}
        />
      )}

      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Distributions</h1>
          <p className="text-sm text-gray-500 mt-1">
            Gestion des distributions APT, RPM et APK.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* Onglets filtre format */}
          <div className="flex gap-1 bg-gray-100 rounded-lg p-1 mr-2">
            {[["all", "Tout"], ["deb", "DEB"], ["rpm", "RPM"], ["apk", "APK"]].map(([val, label]) => (
              <button
                key={val}
                onClick={() => { setFormatFilter(val); setSelectedDist(null); }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  formatFilter === val
                    ? "bg-white shadow text-gray-900"
                    : "text-gray-500 hover:text-gray-700"
                }`}
              >{label}</button>
            ))}
          </div>
          <button
            onClick={handleInit}
            disabled={initing}
            className="flex items-center gap-2 px-3 py-2 text-sm text-gray-600 border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-40 transition-colors"
            title="Initialise les distributions APT, RPM et APK"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            {initing ? "Init..." : "Init dists"}
          </button>
          <button
            onClick={() => setShowPromote(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-white border border-gray-200 rounded-lg hover:bg-gray-50 hover:border-blue-400 hover:text-blue-600 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
            Promouvoir un paquet
          </button>
        </div>
      </div>

      {/* Bannnière migration */}
      {distribs.find((d) => d.codename === "bookworm")?.package_count > 0 &&
       distribs.find((d) => d.codename === "jammy")?.package_count === 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
          <svg className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div className="flex-1">
            <p className="text-sm font-semibold text-amber-800">Migration recommandée</p>
            <p className="text-xs text-amber-700 mt-0.5">
              Vos paquets sont dans <span className="font-mono font-bold">bookworm</span> mais ce sont des paquets Ubuntu Jammy.
              Migrez-les vers <span className="font-mono font-bold">jammy</span> pour une cohérence correcte.
            </p>
          </div>
          <button
            onClick={handleMigrate}
            disabled={migrating}
            className="shrink-0 px-4 py-2 bg-amber-600 text-white text-xs font-medium rounded-lg hover:bg-amber-700 disabled:opacity-50 transition-colors"
          >
            {migrating ? "Migration..." : "Migrer bookworm → jammy"}
          </button>
        </div>
      )}

      {/* Layout flex : liste des distributions à gauche, panneau détail à droite */}
      <div className="flex gap-4 items-start">

        {/* ── Colonne liste ── */}
        <div className="min-w-0 space-y-5" style={{ flex: "2 1 0%" }}>
          {formatFilter === "all" ? (
            <div className="space-y-5">

              {/* DEBIAN / UBUNTU */}
              {distribs.some((d) => d.format === "deb" || (!d.format && d.os !== "alpine")) && (
                <div>
                  <div className="flex items-center gap-3 mb-2.5">
                    <span className="text-xs font-bold uppercase tracking-widest text-gray-500 whitespace-nowrap">
                      Debian / Ubuntu
                    </span>
                    <div className="flex-1 h-px bg-gray-200" />
                  </div>
                  <div className="space-y-1.5">
                    {distribs
                      .filter((d) => d.format === "deb" || (!d.format && d.os !== "alpine"))
                      .map((d) => (
                        <DistribRow key={d.codename} distrib={d}
                          selected={selectedDist === d.codename}
                          onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)} />
                      ))}
                  </div>
                </div>
              )}

              {/* RHEL / COMPATIBLE */}
              {distribs.some((d) => d.format === "rpm" && d.os !== "opensuse") && (
                <div>
                  <div className="flex items-center gap-3 mb-2.5">
                    <span className="text-xs font-bold uppercase tracking-widest text-gray-500 whitespace-nowrap">
                      RHEL / Compatible
                    </span>
                    <div className="flex-1 h-px bg-gray-200" />
                  </div>
                  <div className="space-y-1.5">
                    {distribs.filter((d) => d.format === "rpm" && d.os !== "opensuse").map((d) => (
                      <DistribRow key={d.codename} distrib={d}
                        selected={selectedDist === d.codename}
                        onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)} />
                    ))}
                  </div>
                </div>
              )}

              {/* SUSE */}
              {distribs.some((d) => d.os === "opensuse") && (
                <div>
                  <div className="flex items-center gap-3 mb-2.5">
                    <span className="text-xs font-bold uppercase tracking-widest text-gray-500 whitespace-nowrap">
                      SUSE
                    </span>
                    <div className="flex-1 h-px bg-gray-200" />
                  </div>
                  <div className="space-y-1.5">
                    {distribs.filter((d) => d.os === "opensuse").map((d) => (
                      <DistribRow key={d.codename} distrib={d}
                        selected={selectedDist === d.codename}
                        onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)} />
                    ))}
                  </div>
                </div>
              )}

              {/* ALPINE LINUX */}
              {distribs.some((d) => d.os === "alpine" || d.format === "apk") && (
                <div>
                  <div className="flex items-center gap-3 mb-2.5">
                    <span className="text-xs font-bold uppercase tracking-widest text-emerald-600 whitespace-nowrap">
                      Alpine Linux
                    </span>
                    <div className="flex-1 h-px bg-emerald-100" />
                    <span className="text-xs text-emerald-500 font-medium whitespace-nowrap">
                      APK
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {distribs.filter((d) => d.os === "alpine" || d.format === "apk").map((d) => (
                      <DistribRow key={d.codename} distrib={d}
                        selected={selectedDist === d.codename}
                        onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)} />
                    ))}
                  </div>
                </div>
              )}

            </div>
          ) : (
            <div className="space-y-1.5">
              {distribs
                .filter((d) => {
                  if (formatFilter === "deb") return d.format === "deb" || (!d.format && d.os !== "alpine");
                  if (formatFilter === "rpm") return d.format === "rpm";
                  if (formatFilter === "apk") return d.format === "apk" || d.os === "alpine";
                  return true;
                })
                .map((d) => (
                  <DistribRow key={d.codename} distrib={d}
                    selected={selectedDist === d.codename}
                    onSelect={(c) => setSelectedDist(selectedDist === c ? null : c)} />
                ))}
            </div>
          )}
        </div>

        {/* ── Panneau slide-in ── */}
        {selectedDist && (
          <DistribPanel
            distrib={distribs.find((d) => d.codename === selectedDist)}
            packages={distPackages}
            loading={loadingPkgs}
            onClose={() => setSelectedDist(null)}
            onPromote={(pkgName) => {
              setPromoteInit({ pkg: pkgName, fromDist: selectedDist });
              setShowPromote(true);
            }}
          />
        )}

      </div>
    </div>
  );
}
