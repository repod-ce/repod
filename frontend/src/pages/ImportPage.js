import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import {
  searchImportPackages,
  resolveImportDeps,
  getImportGroups,
  deleteImportGroup,
  getApiBaseUrl,
} from "../api";

const API_URL = getApiBaseUrl();

// ─── Helpers ─────────────────────────────────────────────────────────────────

function Badge({ children, color = "gray" }) {
  const colors = {
    gray: "bg-gray-100 text-gray-600",
    green: "bg-green-100 text-green-700",
    yellow: "bg-yellow-100 text-yellow-700",
    red: "bg-red-100 text-red-700",
    blue: "bg-blue-100 text-blue-700",
    orange: "bg-orange-100 text-orange-700",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors[color]}`}>
      {children}
    </span>
  );
}

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");

  const styles = {
    info: "text-gray-300",
    success: "text-green-400",
    error: "text-red-400",
    warning: "text-yellow-400",
    skip: "text-gray-500",
    done: "text-blue-400 font-semibold",
  };

  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

function IconArrowRight({ className = "w-3.5 h-3.5" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/></svg>;
}

function Spinner({ className = "w-3.5 h-3.5" }) {
  return <div className={`${className} rounded-full border-2 border-white border-t-transparent animate-spin flex-shrink-0`} />;
}

// Les trois importeurs (APT/RPM/APK) émettent le même vocabulaire de log SSE
// pour ces deux issues — voir services/importer_{apt,rpm,apk}.py:import_one().
// "[ADD] ..." = publié dans le dépôt ; "en attente révision RSSI" = envoyé en
// révision CVE, pas encore publié (routers/decision_router.py).
function summarizeImportOutcome(logs) {
  const hasPending   = logs.some((l) => l.includes("en attente révision RSSI"));
  const hasPublished = logs.some((l) => l.includes("[ADD]"));
  if (hasPending) return "pending_review";
  if (hasPublished) return "published";
  return null;
}

function ImportOutcomeButton({ logs, done }) {
  const navigate = useNavigate();
  if (!done) return null;
  const outcome = summarizeImportOutcome(logs);
  if (!outcome) return null;
  const isPending = outcome === "pending_review";
  return (
    <button
      type="button"
      onClick={() => navigate(isPending ? "/security" : "/packages")}
      className={`inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-2 border transition-colors mt-3
        ${isPending
          ? "bg-white text-amber-700 border-amber-200 hover:bg-amber-50"
          : "bg-white text-emerald-700 border-emerald-200 hover:bg-emerald-50"}`}
    >
      {isPending ? "Voir dans Décisions CVE" : "Voir dans Paquets"}
      <IconArrowRight />
    </button>
  );
}

// ─── SSE streaming ────────────────────────────────────────────────────────────

function useSSEStream() {
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const esRef = useRef(null);

  const start = (url) => {
    if (esRef.current) esRef.current.close();
    setLogs([]);
    setDone(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    // EventSource ne supporte pas les headers custom — on utilise fetch + ReadableStream
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({}),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur inconnue" }));
        setLogs((prev) => [...prev, `error|${err.detail || "Erreur serveur"}`]);
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
          if (payload.startsWith("done|")) {
            setDone(true);
            setRunning(false);
          }
        }
      }
      setRunning(false);
    }).catch((e) => {
      setLogs((prev) => [...prev, `error|${e.message}`]);
      setRunning(false);
    });
  };

  const startWithBody = (url, body) => {
    if (esRef.current) esRef.current.close();
    setLogs([]);
    setDone(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur inconnue" }));
        setLogs((prev) => [...prev, `error|${err.detail || "Erreur serveur"}`]);
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
          if (payload.startsWith("done|")) {
            setDone(true);
            setRunning(false);
          }
        }
      }
      setRunning(false);
    }).catch((e) => {
      setLogs((prev) => [...prev, `error|${e.message}`]);
      setRunning(false);
    });
  };

  return { logs, running, done, start, startWithBody };
}

// ─── Tab: Recherche & Import ──────────────────────────────────────────────────

const DISTRIBUTIONS = [
  // APT
  { codename: "jammy",           label: "Jammy 22.04 (LTS)",    format: "deb" },
  { codename: "noble",           label: "Noble 24.04",           format: "deb" },
  { codename: "focal",           label: "Focal 20.04",           format: "deb" },
  { codename: "bookworm",        label: "Bookworm 12",           format: "deb" },
  // RPM — RHEL family
  { codename: "almalinux9",      label: "AlmaLinux 9",           format: "rpm" },
  { codename: "almalinux8",      label: "AlmaLinux 8",           format: "rpm" },
  { codename: "rocky9",          label: "Rocky 9",               format: "rpm" },
  { codename: "rocky8",          label: "Rocky 8",               format: "rpm" },
  { codename: "centos-stream9",  label: "CentOS Stream 9",       format: "rpm" },
  { codename: "oraclelinux9",    label: "Oracle Linux 9",        format: "rpm" },
  { codename: "fedora",          label: "Fedora",                format: "rpm" },
  // RPM — openSUSE
  { codename: "opensuse-leap-15.6",  label: "openSUSE Leap 15.6",   format: "rpm" },
  { codename: "opensuse-tumbleweed", label: "openSUSE Tumbleweed",  format: "rpm" },
  // APK — Alpine Linux
  { codename: "alpine3.21",  label: "Alpine 3.21",  format: "apk" },
  { codename: "alpine3.20",  label: "Alpine 3.20",  format: "apk" },
  { codename: "alpine3.19",  label: "Alpine 3.19",  format: "apk" },
  { codename: "alpine3.18",  label: "Alpine 3.18",  format: "apk" },
];

function guessDistrib(distro) {
  if (!distro) return "jammy";
  // APT
  if (distro.startsWith("focal"))    return "focal";
  if (distro.startsWith("noble"))    return "noble";
  if (distro.startsWith("bookworm")) return "bookworm";
  if (distro.startsWith("jammy"))    return "jammy";
  // RPM
  if (distro.includes("almalinux9")) return "almalinux9";
  if (distro.includes("almalinux8")) return "almalinux8";
  if (distro.includes("rocky9"))     return "rocky9";
  if (distro.includes("rocky8"))     return "rocky8";
  if (distro.includes("centos"))     return "centos-stream9";
  if (distro.includes("oracle") && distro.includes("9")) return "oraclelinux9";
  if (distro.includes("fedora"))     return "fedora";
  if (distro.includes("tumbleweed")) return "opensuse-tumbleweed";
  if (distro.includes("leap"))       return "opensuse-leap-15.6";
  // APK — Alpine
  if (distro.includes("alpine3.21")) return "alpine3.21";
  if (distro.includes("alpine3.20")) return "alpine3.20";
  if (distro.includes("alpine3.19")) return "alpine3.19";
  if (distro.includes("alpine3.18")) return "alpine3.18";
  if (distro.includes("alpine"))     return "alpine3.21";
  return "jammy";
}

// Format metadata for distribution selector
const FMT_META = {
  deb: { label: "APT — DEBIAN / UBUNTU",         accent: "text-blue-600",   activeBg: "bg-blue-600 text-white border-blue-600",   hover: "hover:border-blue-400 hover:text-blue-600"   },
  rpm: { label: "RPM — RHEL / FEDORA / OPENSUSE", accent: "text-orange-600", activeBg: "bg-orange-600 text-white border-orange-600", hover: "hover:border-orange-400 hover:text-orange-600" },
  apk: { label: "APK — ALPINE LINUX",             accent: "text-emerald-600",activeBg: "bg-emerald-600 text-white border-emerald-600", hover: "hover:border-emerald-400 hover:text-emerald-600" },
};

function DistSelector({ distribution, onChange }) {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-4 space-y-3">
      <p className="text-xs font-bold text-gray-500 uppercase tracking-widest">Distribution cible</p>
      {["deb","rpm","apk"].map(fmt => {
        const meta = FMT_META[fmt];
        return (
          <div key={fmt}>
            <p className={`text-[10px] font-bold uppercase tracking-widest mb-1.5 ${meta.accent}`}>{meta.label}</p>
            <div className="flex flex-wrap gap-1.5">
              {DISTRIBUTIONS.filter(d => d.format === fmt).map(d => (
                <button key={d.codename} type="button" onClick={() => onChange(d.codename)}
                  className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
                    distribution === d.codename ? meta.activeBg : `text-gray-500 border-gray-200 ${meta.hover}`
                  }`}>{d.label}</button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SearchImportTab() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [selected, setSelected] = useState(null);
  const [deps, setDeps] = useState(null);
  const [resolvingDeps, setResolvingDeps] = useState(false);
  const [distribution, setDistribution] = useState("jammy");
  const { logs, running, done, startWithBody } = useSSEStream();
  const logsRef = useRef(null);

  const currentFormat = DISTRIBUTIONS.find(d => d.codename === distribution)?.format || "deb";

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const handleSetDistribution = (codename) => {
    const newFmt = DISTRIBUTIONS.find(d => d.codename === codename)?.format;
    if (newFmt !== currentFormat) { setResults([]); setSelected(null); setDeps(null); }
    setDistribution(codename);
  };

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    setSelected(null);
    setDeps(null);
    try {
      const data = await searchImportPackages(query.trim(), 60, null, currentFormat, distribution);
      setResults(data.results || []);
      if ((data.results || []).length === 0) toast(`Aucun résultat ${currentFormat.toUpperCase()} trouvé`);
    } catch (err) {
      if (err.response?.status === 424) {
        toast.error("Index non synchronisé. Utilisez l'onglet Synchronisation d'abord.");
      } else {
        toast.error("Erreur lors de la recherche");
      }
    } finally {
      setSearching(false);
    }
  };

  const handleSelect = async (pkg) => {
    setSelected(pkg);
    setDeps(null);
    setResolvingDeps(true);
    const guessed = guessDistrib(pkg.distro);
    const guessedFmt = DISTRIBUTIONS.find(d => d.codename === guessed)?.format;
    if (guessedFmt === currentFormat) setDistribution(guessed);
    try {
      const data = await resolveImportDeps(pkg.name);
      setDeps(data);
    } catch {
      setDeps(null);
    } finally {
      setResolvingDeps(false);
    }
  };

  const handleImport = () => {
    if (!selected) return;
    startWithBody(`${API_URL}/import/fetch`, { package: selected.name, distribution });
  };

  const fmtMeta = FMT_META[currentFormat] || FMT_META.deb;

  return (
    <div className="space-y-4">
      {/* 1. Distribution d'abord — scope la recherche */}
      <DistSelector distribution={distribution} onChange={handleSetDistribution} />

      {/* 2. Barre de recherche scopée au format sélectionné */}
      <form onSubmit={handleSearch} className="flex gap-3">
        <div className="relative flex-1">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Rechercher un paquet ${currentFormat.toUpperCase()} pour ${distribution}…`}
            className="w-full px-4 py-2.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 pr-16"
          />
          <span className={`absolute right-3 top-1/2 -translate-y-1/2 text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${fmtMeta.activeBg}`}>
            {currentFormat.toUpperCase()}
          </span>
        </div>
        <button type="submit" disabled={searching}
          className="px-5 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors">
          {searching ? "Recherche..." : "Rechercher"}
        </button>
      </form>

      <div className="grid grid-cols-2 gap-6">
        {/* 3. Résultats filtrés par format */}
        <div>
          {results.length > 0 ? (
            <div className="border border-gray-200 rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2.5 border-b border-gray-200 flex items-center gap-2">
                <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider flex-1">{results.length} résultat(s)</p>
                <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${fmtMeta.activeBg}`}>{currentFormat.toUpperCase()}</span>
              </div>
              <div className="divide-y divide-gray-100 max-h-[28rem] overflow-y-auto">
                {results.map((pkg, i) => (
                  <button key={i} onClick={() => handleSelect(pkg)}
                    className={`w-full text-left px-4 py-3 hover:bg-blue-50 transition-colors ${
                      selected?.name === pkg.name && selected?.distro === pkg.distro ? "bg-blue-50 border-l-2 border-l-blue-500" : ""
                    } ${pkg.security ? "border-l-2 border-l-red-300" : ""}`}>
                    <div className="flex items-center justify-between mb-0.5 gap-2">
                      <span className="text-sm font-medium text-gray-900 truncate">{pkg.name}</span>
                      <div className="flex items-center gap-1.5 shrink-0">
                        {pkg.security && <Badge color="red">Sécurité</Badge>}
                        <Badge color="gray">{pkg.version}</Badge>
                      </div>
                    </div>
                    <p className="text-xs text-gray-500 line-clamp-1">{pkg.description}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{pkg.distro}</p>
                  </button>
                ))}
              </div>
            </div>
          ) : query && !searching ? (
            <div className="border border-dashed border-gray-200 rounded-lg p-8 text-center text-gray-400 text-sm">
              Aucun résultat {currentFormat.toUpperCase()} — vérifiez la synchronisation
            </div>
          ) : null}
        </div>

        {/* 4. Détail + dépendances */}
        <div className="space-y-4">
          {selected && (
            <div className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-900">{selected.name}</h3>
                    {selected.security && <Badge color="red">Patch sécurité</Badge>}
                  </div>
                  <p className="text-sm text-gray-500">{selected.version} · {selected.arch}</p>
                  <p className="text-xs text-gray-400 mt-0.5">→ <strong>{distribution}</strong></p>
                </div>
                <button onClick={handleImport} disabled={running}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 disabled:opacity-50 transition-colors">
                  {running && <Spinner />}
                  {running ? "Import en cours..." : "Importer"}
                </button>
              </div>
              {selected.description && (
                <p className="text-sm text-gray-600 mb-3">{selected.description}</p>
              )}
              {resolvingDeps && <p className="text-xs text-gray-400 italic">Résolution des dépendances...</p>}
              {deps && (
                <div>
                  <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">
                    Dépendances — {deps.already_in_repo}/{deps.total_deps} dans le dépôt, {deps.to_download} à télécharger
                  </p>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {deps.packages.map((p, i) => (
                      <div key={i} className="flex items-center justify-between text-xs">
                        <span className="text-gray-700">{p.name}</span>
                        {p.already_in_repo ? <Badge color="green">dans le dépôt</Badge> : <Badge color="yellow">à télécharger</Badge>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Logs SSE */}
          {logs.length > 0 && (
            <div className="border border-gray-800 rounded-lg bg-gray-900 p-4">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                Logs d'import {done && <span className="text-green-400">— Terminé</span>}
              </p>
              <div ref={logsRef} className="max-h-48 overflow-y-auto space-y-0.5">
                {logs.map((line, i) => <LogLine key={i} line={line} />)}
              </div>
              <ImportOutcomeButton logs={logs} done={done} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Tab: Import par lot ──────────────────────────────────────────────────────

function BatchImportTab() {
  const [input, setInput] = useState("");
  const [distribution, setDistribution] = useState("jammy");
  const { logs, running, done, startWithBody } = useSSEStream();
  const logsRef = useRef(null);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [logs]);

  const handleBatch = () => {
    const packages = input
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (packages.length === 0) {
      toast.error("Entrez au moins un nom de paquet");
      return;
    }
    if (packages.length > 50) {
      toast.error("Maximum 50 paquets par batch");
      return;
    }
    startWithBody(`${API_URL}/import/batch`, { packages, distribution });
  };

  return (
    <div className="space-y-6 p-6">
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 text-sm text-blue-800">
        Entrez un paquet par ligne (ou séparés par des virgules). Maximum 50 paquets par import.
      </div>

      {/* Distribution */}
      <div>
        <p className="text-sm font-medium text-gray-700 mb-2">Distribution cible</p>
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {DISTRIBUTIONS.filter((d) => d.format === "deb").map((d) => (
              <button key={d.codename} type="button"
                onClick={() => setDistribution(d.codename)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  distribution === d.codename
                    ? "bg-blue-600 text-white border-blue-600"
                    : "text-gray-500 border-gray-200 hover:border-blue-400 hover:text-blue-600"
                }`}>{d.label}</button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {DISTRIBUTIONS.filter((d) => d.format === "rpm").map((d) => (
              <button key={d.codename} type="button"
                onClick={() => setDistribution(d.codename)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  distribution === d.codename
                    ? "bg-orange-600 text-white border-orange-600"
                    : "text-gray-500 border-gray-200 hover:border-orange-400 hover:text-orange-600"
                }`}>{d.label}</button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {DISTRIBUTIONS.filter((d) => d.format === "apk").map((d) => (
              <button key={d.codename} type="button"
                onClick={() => setDistribution(d.codename)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
                  distribution === d.codename
                    ? "bg-emerald-600 text-white border-emerald-600"
                    : "text-gray-500 border-gray-200 hover:border-emerald-400 hover:text-emerald-600"
                }`}>{d.label}</button>
            ))}
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <label className="block text-sm font-medium text-gray-700">
          Liste de paquets
        </label>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={"nginx\ncurl\npython3\njq"}
          rows={8}
          className="w-full px-4 py-3 border border-gray-300 rounded-lg text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
        />
        <div className="flex items-center justify-between">
          <p className="text-xs text-gray-500">
            {input.split(/[\n,]+/).filter((s) => s.trim()).length} paquet(s) détecté(s)
          </p>
          <button
            onClick={handleBatch}
            disabled={running || !input.trim()}
            className="flex items-center gap-2 px-5 py-2.5 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700 disabled:opacity-50 transition-colors"
          >
            {running && <Spinner />}
            {running ? "Import en cours..." : "Lancer l'import"}
          </button>
        </div>
      </div>

      {logs.length > 0 && (
        <div className="border border-gray-800 rounded-lg bg-gray-900 p-4">
          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
            Logs {done && <span className="text-green-400">— Import terminé</span>}
            {running && <span className="text-yellow-400 ml-1">— En cours...</span>}
          </p>
          <div ref={logsRef} className="max-h-80 overflow-y-auto space-y-0.5">
            {logs.map((line, i) => <LogLine key={i} line={line} />)}
          </div>
          <ImportOutcomeButton logs={logs} done={done} />
        </div>
      )}
    </div>
  );
}

// ─── Tab: Groupes d'import ────────────────────────────────────────────────────

function GroupsTab() {
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [deleting, setDeleting] = useState(null);

  const loadGroups = () => {
    getImportGroups()
      .then((d) => setGroups(d.groups || []))
      .catch(() => toast.error("Impossible de charger les groupes"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadGroups(); }, []);

  const handleDelete = async (name) => {
    if (!window.confirm(`Supprimer le groupe "${name}" et tous ses fichiers ?`)) return;
    setDeleting(name);
    try {
      await deleteImportGroup(name);
      toast.success(`Groupe "${name}" supprimé`);
      if (expanded === name) setExpanded(null);
      loadGroups();
    } catch {
      toast.error("Impossible de supprimer le groupe");
    } finally {
      setDeleting(null);
    }
  };

  const fmt = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  if (loading) return <div className="text-center text-gray-400 text-sm py-12">Chargement...</div>;

  if (groups.length === 0) {
    return (
      <div className="text-center py-16 text-gray-400">
        <svg className="w-12 h-12 mx-auto mb-3 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
            d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
        <p className="text-sm">Aucun groupe d'import pour le moment.</p>
        <p className="text-xs mt-1">Les paquets importés apparaîtront ici, regroupés par paquet principal.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-gray-500">
        {groups.length} groupe(s) — chaque groupe contient le paquet importé et toutes ses dépendances.
      </p>
      {groups.map((g) => (
        <div key={g.name} className="border border-gray-200 rounded-lg overflow-hidden">
          {/* En-tête du groupe */}
          <button
            onClick={() => setExpanded(expanded === g.name ? null : g.name)}
            className="w-full flex items-center justify-between px-5 py-4 bg-white hover:bg-gray-50 transition-colors"
          >
            <div className="flex items-center gap-4">
              <div className="w-9 h-9 bg-blue-100 rounded-lg flex items-center justify-center shrink-0">
                <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
              </div>
              <div className="text-left">
                <p className="text-sm font-semibold text-gray-900">{g.name}</p>
                <p className="text-xs text-gray-400">
                  {g.package_count} fichier(s) · {fmt(g.total_size_bytes)} ·{" "}
                  importé le {new Date(g.imported_at).toLocaleDateString("fr-FR")}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge color="blue">{g.package_count} paquet{g.package_count > 1 ? "s" : ""}</Badge>
              <button
                onClick={(e) => { e.stopPropagation(); handleDelete(g.name); }}
                disabled={deleting === g.name}
                className="p-1.5 text-red-400 hover:bg-red-50 hover:text-red-600 rounded-lg transition-colors disabled:opacity-40"
                title="Supprimer ce groupe"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                    d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
              <svg
                className={`w-4 h-4 text-gray-400 transition-transform ${expanded === g.name ? "rotate-180" : ""}`}
                fill="none" viewBox="0 0 24 24" stroke="currentColor"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </button>

          {/* Liste des fichiers */}
          {expanded === g.name && (
            <div className="border-t border-gray-100 bg-gray-50">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="px-5 py-2 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Fichier</th>
                    <th className="px-5 py-2 text-right text-xs font-semibold text-gray-500 uppercase tracking-wider">Taille</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {g.packages.map((p, i) => (
                    <tr key={i} className="bg-white">
                      <td className="px-5 py-2.5">
                        <span className={`text-sm font-mono ${p.filename.startsWith(g.name + "_") ? "text-blue-700 font-semibold" : "text-gray-700"}`}>
                          {p.filename}
                        </span>
                        {p.filename.startsWith(g.name + "_") && (
                          <span className="ml-2 text-xs text-blue-500">(principal)</span>
                        )}
                      </td>
                      <td className="px-5 py-2.5 text-right text-xs text-gray-500 font-mono">
                        {fmt(p.size_bytes)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

const TABS = [
  { id: "search", label: "Recherche & Import", icon: "M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" },
  { id: "batch", label: "Import par lot", icon: "M4 6h16M4 10h16M4 14h16M4 18h16" },
  { id: "groups", label: "Groupes d'import", icon: "M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" },
];

export default function ImportPage() {
  const [activeTab, setActiveTab] = useState("search");

  return (
    <div className="space-y-6 p-6">
      {/* En-tête */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Import depuis internet</h1>
        <p className="text-sm text-gray-500 mt-1">
          Recherchez, résolvez les dépendances et importez des paquets <strong>.deb</strong> (APT), <strong>.rpm</strong> (DNF/Zypper) et <strong>.apk</strong> (Alpine) directement dans votre dépôt privé.
        </p>
      </div>

      {/* Onglets */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 pb-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
              </svg>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Contenu des onglets */}
      <div>
        {activeTab === "search" && <SearchImportTab />}
        {activeTab === "batch" && <BatchImportTab />}
        {activeTab === "groups" && <GroupsTab />}
      </div>

      {/* Pipeline de sécurité */}
      <div className="bg-white border border-gray-200 rounded-xl p-6">
        <h2 className="text-sm font-semibold text-gray-800 mb-4">Pipeline de sécurité à l'import</h2>
        <div className="space-y-3">
          {[
            { step: "1", name: "Format .deb / .rpm / .apk", desc: "Vérification que le fichier est un paquet valide.", color: "bg-blue-100 text-blue-700", blocking: true },
            { step: "2", name: "Provenance SHA256", desc: "Comparaison du SHA256 avec celui du manifeste source.", color: "bg-blue-100 text-blue-700", blocking: true },
            { step: "3", name: "Antivirus ClamAV", desc: "Scan complet contre la base de signatures ClamAV.", color: "bg-red-100 text-red-700", blocking: true },
            { step: "4", name: "Analyse CVE (Grype)", desc: "Scan des vulnérabilités selon la politique CVE configurée.", color: "bg-orange-100 text-orange-700", blocking: true },
            { step: "5", name: "Signature GPG", desc: "Vérification de la signature GPG si présente. Non bloquant si absent.", color: "bg-yellow-100 text-yellow-700", blocking: false },
            { step: "6", name: "Dépendances", desc: "Vérification des dépendances dans le dépôt interne.", color: "bg-green-100 text-green-700", blocking: false },
          ].map((item) => (
            <div key={item.step} className="flex items-start gap-4">
              <span className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${item.color}`}>
                {item.step}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-semibold text-gray-800">{item.name}</p>
                  {item.blocking
                    ? <span className="text-xs px-1.5 py-0.5 bg-red-50 text-red-600 rounded font-medium">Bloquant</span>
                    : <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded font-medium">Avertissement</span>
                  }
                </div>
                <p className="text-xs text-gray-500 mt-0.5">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
