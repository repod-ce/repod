/**
 * DockerfilePage.js
 * ==================
 * Analyseur de Dockerfile multi-format : détecte les paquets APT (apt-get/apt),
 * RPM (dnf/yum/microdnf) et APK (Alpine apk add), vérifie leur présence dans
 * repod et propose d'importer les manquants en un clic.
 *
 * Flux :
 *  1. Coller le Dockerfile → distribution auto-détectée depuis la ligne FROM
 *  2. Cliquer Analyser → résultats : Disponibles / Importables / Inconnus
 *  3. Sélectionner les paquets à importer → Importer (SSE streaming)
 */
import { useState, useRef, useEffect, useCallback } from "react";
import { analyzeDockerfile, getApiBaseUrl } from "../api";

const API_URL = getApiBaseUrl();

// ─── Distributions supportées (groupées par gestionnaire) ─────────────────────

const DISTRIBUTION_GROUPS = [
  {
    group: "APT — Ubuntu / Debian",
    pm: "apt",
    items: [
      { codename: "jammy",    label: "Ubuntu 22.04 LTS (Jammy)" },
      { codename: "noble",    label: "Ubuntu 24.04 (Noble)"      },
      { codename: "focal",    label: "Ubuntu 20.04 LTS (Focal)"  },
      { codename: "bookworm", label: "Debian 12 (Bookworm)"      },
      { codename: "bullseye", label: "Debian 11 (Bullseye)"      },
    ],
  },
  {
    group: "RPM — RHEL / AlmaLinux / Rocky / Fedora",
    pm: "rpm",
    items: [
      { codename: "el9",  label: "RHEL / AlmaLinux / Rocky 9"    },
      { codename: "el8",  label: "RHEL / AlmaLinux / Rocky 8"    },
      { codename: "fc41", label: "Fedora 41"                      },
      { codename: "fc40", label: "Fedora 40"                      },
    ],
  },
  {
    group: "APK — Alpine Linux",
    pm: "apk",
    items: [
      { codename: "alpine-3.20", label: "Alpine 3.20" },
      { codename: "alpine-3.19", label: "Alpine 3.19" },
      { codename: "alpine-edge", label: "Alpine Edge" },
    ],
  },
];

// Flat list for quick lookup
const ALL_DISTRIBUTIONS = DISTRIBUTION_GROUPS.flatMap((g) => g.items);

// PM label + color
const PM_META = {
  apt: { label: "APT",  bg: "bg-purple-100", text: "text-purple-700", border: "border-purple-200" },
  rpm: { label: "RPM",  bg: "bg-orange-100", text: "text-orange-700", border: "border-orange-200" },
  apk: { label: "APK",  bg: "bg-teal-100",   text: "text-teal-700",   border: "border-teal-200"   },
};

// ─── Auto-détection de l'image de base (client-side) ─────────────────────────

function detectBaseImage(content) {
  // ── Étape 1 : commandes RUN — source de vérité absolue ───────────────────────
  // "mycompany/app:v2" ne dit rien sur le PM, mais "apk add nginx" est sans
  // ambiguïté. On regarde les commandes en premier.
  const hasApk = /\bapk\s+add\b/i.test(content);
  const hasApt = /\b(?:apt-get|apt)\s+(?:install|upgrade)\b/i.test(content);
  const hasRpm = /\b(?:dnf|yum|microdnf)\s+install\b/i.test(content);
  const pmCount = [hasApk, hasApt, hasRpm].filter(Boolean).length;
  // Un seul PM dans les commandes → certitude
  const pmFromCmds = pmCount === 1
    ? (hasApk ? "apk" : hasApt ? "apt" : "rpm")
    : null;

  // ── Étape 2 : ligne FROM — utile pour version/distribution ───────────────────
  const fromMatch = content.match(/^FROM\s+([^\s\n]+)/im);
  let pmFromImage = null;
  let distribution = null;

  if (fromMatch) {
    // "FROM image:tag AS alias" → on garde juste "image:tag"
    const ref   = fromMatch[1].toLowerCase().split(/\s+as\s+/i)[0].trim();
    // Dernier segment du chemin (registry.io/org/image:tag → "image")
    const image = ref.split(":")[0].split("/").pop();

    if (ref.includes("alpine")) {
      pmFromImage = "apk";
      const ver = (ref.match(/alpine[-:/]?(\d+\.\d+)/) || [])[1] || "3.20";
      distribution = `alpine-${ver}`;
    } else if (/\b(almalinux|rockylinux|rhel|ubi\d+|centos|oraclelinux)\b/.test(ref)) {
      pmFromImage = "rpm";
      const ubiVer = (ref.match(/\bubi(\d+)\b/)  || [])[1];
      const imgVer = (ref.match(/(?:almalinux|rockylinux|rhel|centos|oraclelinux)[:/](\d+)/) || [])[1];
      distribution = `el${ubiVer || imgVer || "9"}`;
    } else if (ref.includes("fedora")) {
      pmFromImage = "rpm";
      const ver = (ref.match(/[:/](\d+)/) || [])[1] || "41";
      distribution = `fc${ver}`;
    } else {
      const aptCodenames = {
        "noble": "noble",    "24.04": "noble",
        "jammy": "jammy",    "22.04": "jammy",
        "focal":  "focal",   "20.04": "focal",
        "bookworm": "bookworm", "bullseye": "bullseye", "buster": "buster",
      };
      for (const [key, codename] of Object.entries(aptCodenames)) {
        if (ref.includes(key)) { pmFromImage = "apt"; distribution = codename; break; }
      }
      // Images officielles connues pour utiliser APT (node, python, golang…)
      if (!pmFromImage && /\b(ubuntu|debian|node|python|ruby|php|nginx|openjdk|golang|gradle|maven)\b/.test(image)) {
        pmFromImage = "apt";
        distribution = "bookworm";
      }
    }
  }

  // ── Étape 3 : résolution finale ───────────────────────────────────────────────
  // Priorité : commandes RUN > nom d'image FROM
  const pkgManager = pmFromCmds || pmFromImage;
  if (!pkgManager) return null;

  // Si les commandes contredisent l'image FROM (ex: FROM node:22 + apk add),
  // la distribution déduite du FROM n'est plus cohérente → on la jette
  if (pmFromCmds && pmFromCmds !== pmFromImage) distribution = null;

  // Distribution par défaut si FROM ne l'indique pas
  if (!distribution) {
    if (pkgManager === "apk") distribution = "alpine-3.20";
    else if (pkgManager === "rpm") distribution = "el9";
    else distribution = "bookworm";
  }

  return { pkgManager, distribution };
}

// ─── SVG Icons ────────────────────────────────────────────────────────────────

const Icon = {
  Check: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  ),
  Download: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Search: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="11" cy="11" r="8"/>
      <line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
  ),
  Upload: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <polyline points="16 16 12 12 8 16"/>
      <line x1="12" y1="12" x2="12" y2="21"/>
      <path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/>
    </svg>
  ),
  X: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  ),
  ChevronDown: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <polyline points="6 9 12 15 18 9"/>
    </svg>
  ),
  Docker: (props) => (
    <svg viewBox="0 0 24 24" fill="currentColor" {...props}>
      <path d="M13.982 10.645h1.99v-1.99h-1.99v1.99zm-2.22 0h1.99v-1.99h-1.99v1.99zm-2.21 0h1.99v-1.99h-1.99v1.99zm-2.21 0h1.99v-1.99H7.342v1.99zm4.42-2.21h1.99V6.445h-1.99v1.99zm-2.21 0h1.99V6.445h-1.99v1.99zm2.21-2.21h1.99V4.235h-1.99v1.99zM22.67 10.4a3.59 3.59 0 00-2.565-.89 3.865 3.865 0 00-.1-.865 4.87 4.87 0 00-2.13-3.185l-.43-.27-.285.42a5.295 5.295 0 00-.73 2.405c-.065.745.095 1.635.5 2.3A5.26 5.26 0 0115.4 11.2H.87l-.055.325a7.95 7.95 0 00.59 4.42l.22.46.035.065c1.44 2.44 3.985 3.68 7.35 3.68 5.835 0 10.62-2.62 12.82-8.385a5.345 5.345 0 001.565.34l.015-.005a4.15 4.15 0 001.255-.27l.39-.155-.35-.43a3.665 3.665 0 00-2.055-1.045z"/>
    </svg>
  ),
  Info: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <circle cx="12" cy="12" r="10"/>
      <line x1="12" y1="16" x2="12" y2="12"/>
      <line x1="12" y1="8" x2="12.01" y2="8"/>
    </svg>
  ),
  Wand: (props) => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
      strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M15 4V2M15 16v-2M8 9h2M20 9h2M17.8 11.8L19 13M17.8 6.2L19 5M3 21l9-9M12.2 6.2L11 5"/>
    </svg>
  ),
};

// ─── SSE streaming hook ───────────────────────────────────────────────────────

function useSSEStream() {
  const [logs, setLogs]       = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone]       = useState(false);

  const startWithBody = useCallback((url, body) => {
    setLogs([]);
    setDone(false);
    setRunning(true);

    const token = localStorage.getItem("token");
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    }).then(async (resp) => {
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur inconnue" }));
        setLogs((prev) => [...prev, `error|${err.detail || "Erreur serveur"}`]);
        setRunning(false);
        return;
      }
      const reader  = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer    = "";
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
      setLogs((prev) => [...prev, `error|${e.message}`]);
      setRunning(false);
    });
  }, []);

  return { logs, running, done, startWithBody };
}

// ─── Log line renderer ────────────────────────────────────────────────────────

function LogLine({ line }) {
  if (!line) return null;
  const [level, ...rest] = line.split("|");
  const msg = rest.join("|");
  const styles = {
    info:    "text-gray-300", success: "text-green-400",
    error:   "text-red-400",  warning: "text-yellow-400",
    skip:    "text-gray-500", done:    "text-blue-400 font-semibold",
  };
  return (
    <p className={`text-xs font-mono leading-relaxed ${styles[level] || "text-gray-300"}`}>
      {msg}
    </p>
  );
}

// ─── PM badge ─────────────────────────────────────────────────────────────────

function PmBadge({ pm }) {
  const m = PM_META[pm] || { label: pm, bg: "bg-gray-100", text: "text-gray-600", border: "border-gray-200" };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold
                      border ${m.bg} ${m.text} ${m.border}`}>
      {m.label}
    </span>
  );
}

// ─── Status badge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }) {
  const cfg = {
    available:  { bg: "bg-green-100", text: "text-green-800", label: "Disponible"  },
    importable: { bg: "bg-blue-100",  text: "text-blue-800",  label: "Importable"  },
    unknown:    { bg: "bg-gray-100",  text: "text-gray-600",  label: "Inconnu"     },
  }[status] || { bg: "bg-gray-100", text: "text-gray-600", label: status };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium
                      ${cfg.bg} ${cfg.text}`}>
      {cfg.label}
    </span>
  );
}

// ─── Package row in results table ─────────────────────────────────────────────

function PackageRow({ pkg, selected, onToggle, showCheckbox }) {
  const isSelectable = pkg.status === "importable";
  return (
    <tr className={`border-b border-gray-100 last:border-0 ${isSelectable ? "hover:bg-gray-50" : ""}`}>
      {showCheckbox && (
        <td className="pl-4 pr-2 py-2.5 w-8">
          {isSelectable ? (
            <input
              type="checkbox" checked={selected} onChange={() => onToggle(pkg.name)}
              className="w-3.5 h-3.5 rounded border-gray-300 text-blue-600
                         focus:ring-blue-500 cursor-pointer"
            />
          ) : <span className="w-3.5 h-3.5 block"/>}
        </td>
      )}
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-2">
          <PmBadge pm={pkg.pkg_manager}/>
          <span className="font-mono text-sm text-gray-900 font-medium">{pkg.name}</span>
        </div>
      </td>
      <td className="px-4 py-2.5"><StatusBadge status={pkg.status}/></td>
      <td className="px-4 py-2.5 text-xs text-gray-500">
        {pkg.status === "available" && "Déjà dans repod — aucune action requise"}
        {pkg.status === "importable" && pkg.upstream_info && (
          <span>
            v{pkg.upstream_info.version}
            {pkg.upstream_info.section && (
              <span className="ml-1 text-gray-400">[{pkg.upstream_info.section}]</span>
            )}
            {pkg.upstream_info.size && (
              <span className="ml-1 text-gray-400">
                — {(pkg.upstream_info.size / 1024).toFixed(0)} Ko
              </span>
            )}
          </span>
        )}
        {pkg.status === "importable" && !pkg.upstream_info && "Disponible dans l'index upstream"}
        {pkg.status === "unknown" && (
          <span className="text-orange-600">Introuvable dans l'index upstream</span>
        )}
      </td>
    </tr>
  );
}

// ─── Result summary bar ───────────────────────────────────────────────────────

function ResultSummary({ result }) {
  const items = [
    { label: `${result.total} paquet${result.total > 1 ? "s" : ""} détecté${result.total > 1 ? "s" : ""}`,
      dot: "bg-gray-400", text: "text-gray-600" },
    { label: `${result.available} dans repod`,
      dot: "bg-green-500", text: "text-green-700" },
    { label: `${result.importable} importable${result.importable > 1 ? "s" : ""}`,
      dot: "bg-blue-500",  text: "text-blue-700" },
    ...(result.unknown > 0
      ? [{ label: `${result.unknown} inconnu${result.unknown > 1 ? "s" : ""}`,
           dot: "bg-orange-400", text: "text-orange-700" }]
      : []),
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 px-4 py-2.5
                    border-b border-gray-100 bg-gray-50 text-xs font-medium">
      {items.map((item, i) => (
        <span key={i} className={`flex items-center gap-1.5 ${item.text}`}>
          <span className={`w-2 h-2 rounded-full shrink-0 ${item.dot}`}/>
          {item.label}
        </span>
      ))}
    </div>
  );
}

// ─── Auto-detect banner ───────────────────────────────────────────────────────

function AutoDetectBanner({ detected, onApply }) {
  if (!detected) return null;
  const pm = PM_META[detected.pkgManager];
  const distLabel = ALL_DISTRIBUTIONS.find((d) => d.codename === detected.distribution)?.label
    || detected.distribution;
  return (
    <div className="flex items-center gap-3 bg-amber-50 border border-amber-200 rounded-lg
                    px-3 py-2 text-xs text-amber-800">
      <Icon.Wand className="w-3.5 h-3.5 shrink-0 text-amber-500"/>
      <span>
        Image détectée&nbsp;: gestionnaire{" "}
        {pm && (
          <span className={`inline-flex items-center px-1.5 py-0.5 rounded font-bold border
                            ${pm.bg} ${pm.text} ${pm.border} mx-0.5`}>
            {pm.label}
          </span>
        )}
        — distribution suggérée <strong>{distLabel}</strong>
      </span>
      <button
        onClick={onApply}
        className="ml-auto shrink-0 px-2 py-0.5 bg-amber-600 text-white rounded text-[11px]
                   font-semibold hover:bg-amber-700 transition-colors"
      >
        Appliquer
      </button>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function DockerfilePage() {
  const [content,      setContent]      = useState("");
  const [distribution, setDistribution] = useState("jammy");
  const [analyzing,    setAnalyzing]    = useState(false);
  const [result,       setResult]       = useState(null);
  const [error,        setError]        = useState(null);
  const [selected,     setSelected]     = useState(new Set());
  const [filter,       setFilter]       = useState("all");
  const [importing,    setImporting]    = useState(false);
  const [detected,     setDetected]     = useState(null);   // image auto-détectée

  const { logs, running, done: importDone, startWithBody } = useSSEStream();
  const logsRef     = useRef(null);
  const textareaRef = useRef(null);

  // Auto-scroll logs
  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  // Auto-détection depuis la ligne FROM dès que le contenu change
  useEffect(() => {
    if (!content.trim()) { setDetected(null); return; }
    const d = detectBaseImage(content);
    setDetected(d);
  }, [content]);

  // ── Analyse ──────────────────────────────────────────────────────────────────

  const handleAnalyze = async () => {
    if (!content.trim()) return;
    setAnalyzing(true);
    setError(null);
    setResult(null);
    setSelected(new Set());
    setFilter("all");
    try {
      const data = await analyzeDockerfile(content.trim(), distribution);
      setResult(data);
      // Si le backend confirme un PM, mettre à jour la distribution affichée
      if (data.base_image?.distribution) {
        const exists = ALL_DISTRIBUTIONS.find((d) => d.codename === data.base_image.distribution);
        if (exists) setDistribution(data.base_image.distribution);
      }
      // Pré-sélectionner tous les importables
      const importables = (data.packages_found || [])
        .filter((p) => p.status === "importable")
        .map((p) => p.name);
      setSelected(new Set(importables));
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || "Erreur inconnue");
    } finally {
      setAnalyzing(false);
    }
  };

  // ── Sélection ────────────────────────────────────────────────────────────────

  const togglePackage = (name) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const toggleAllImportable = () => {
    if (!result) return;
    const importables = result.packages_found
      .filter((p) => p.status === "importable").map((p) => p.name);
    if (importables.every((n) => selected.has(n))) {
      setSelected((prev) => {
        const next = new Set(prev);
        importables.forEach((n) => next.delete(n));
        return next;
      });
    } else {
      setSelected((prev) => {
        const next = new Set(prev);
        importables.forEach((n) => next.add(n));
        return next;
      });
    }
  };

  // ── Import ───────────────────────────────────────────────────────────────────

  const handleImport = () => {
    if (selected.size === 0 || running) return;
    setImporting(true);
    startWithBody(`${API_URL}/import/batch`, {
      packages:     Array.from(selected),
      distribution: distribution,
    });
  };

  // Reset import state when done
  useEffect(() => {
    if (importDone && importing) {
      setImporting(false);
      const hasErrors = logs.some((l) => l.startsWith("error|"));
      if (!hasErrors && result) {
        setResult((prev) => {
          if (!prev) return prev;
          const updated = prev.packages_found.map((p) =>
            selected.has(p.name) ? { ...p, status: "available", upstream_info: null } : p
          );
          return {
            ...prev,
            packages_found: updated,
            available:  updated.filter((p) => p.status === "available").length,
            importable: updated.filter((p) => p.status === "importable").length,
            unknown:    updated.filter((p) => p.status === "unknown").length,
          };
        });
        setSelected(new Set());
      }
    }
  }, [importDone]); // eslint-disable-line

  // ── Drag-and-drop ─────────────────────────────────────────────────────────────

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setContent(ev.target.result || "");
    reader.readAsText(file);
  };

  // ── Filtrage ─────────────────────────────────────────────────────────────────

  const filteredPkgs = result
    ? result.packages_found.filter((p) => filter === "all" || p.status === filter)
    : [];

  const importableCount = result
    ? result.packages_found.filter((p) => p.status === "importable").length
    : 0;

  const allImportableSelected =
    importableCount > 0 &&
    result?.packages_found
      .filter((p) => p.status === "importable")
      .every((p) => selected.has(p.name));

  // ─────────────────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-full bg-slate-50 px-6 pt-5 pb-12 space-y-6">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Analyseur de Dockerfile</h1>
        <p className="text-sm text-slate-500 mt-0.5">
          Détecte les paquets <strong>APT</strong> (apt/apt-get), <strong>RPM</strong> (dnf/yum/microdnf)
          et <strong>APK</strong> (Alpine) dans un Dockerfile, vérifie leur présence dans repod
          et importe les manquants en un clic.
        </p>
      </div>

      {/* ── Info banner ────────────────────────────────────────────────────── */}
      <div className="flex items-start gap-3 bg-blue-50 border border-blue-200 rounded-xl
                      px-4 py-3 text-sm text-blue-800">
        <Icon.Info className="w-4 h-4 mt-0.5 shrink-0 text-blue-500"/>
        <span>
          Les images Docker sont <strong>immuables</strong> — les paquets doivent être
          intégrés à l'image lors du{" "}
          <code className="bg-blue-100 px-1 rounded font-mono text-xs">docker build</code>,
          pas installés au runtime. Cet outil anticipe quels paquets doivent être présents
          dans repod avant de builder, pour toutes les distributions Debian/Ubuntu,
          RHEL/Fedora et Alpine.
        </span>
      </div>

      {/* ── Input section ──────────────────────────────────────────────────── */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100">
          <h2 className="font-medium text-gray-800 text-sm">Dockerfile</h2>
          {content && (
            <button
              onClick={() => { setContent(""); setResult(null); setError(null); setDetected(null); }}
              className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-600
                         transition-colors"
            >
              <Icon.X className="w-3.5 h-3.5"/>
              Effacer
            </button>
          )}
        </div>

        <div onDrop={handleDrop} onDragOver={(e) => e.preventDefault()} className="relative">
          <textarea
            ref={textareaRef}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={
              "Collez votre Dockerfile ici ou glissez-déposez le fichier...\n\n" +
              "Exemples détectés automatiquement :\n" +
              "  APT  : RUN apt-get install -y nginx curl python3\n" +
              "  RPM  : RUN dnf install -y nginx curl python3\n" +
              "  APK  : RUN apk add --no-cache nginx curl python3"
            }
            className="w-full h-56 px-5 py-4 font-mono text-sm text-gray-800 bg-gray-50
                       placeholder-gray-400 resize-none focus:outline-none focus:bg-white
                       transition-colors border-0"
            spellCheck={false}
          />
          {!content && (
            <div className="absolute inset-0 flex flex-col items-center justify-center
                            pointer-events-none text-gray-400">
              <Icon.Upload className="w-8 h-8 mb-2 opacity-30"/>
            </div>
          )}
        </div>

        {/* Auto-detect banner (inside card, above footer) */}
        {detected && (
          <div className="px-4 pb-3">
            <AutoDetectBanner
              detected={detected}
              onApply={() => {
                if (detected.distribution) setDistribution(detected.distribution);
              }}
            />
          </div>
        )}

        {/* Distribution + Analyze */}
        <div className="flex items-center gap-3 px-5 py-3.5 border-t border-gray-100 bg-white">
          <label className="text-xs font-medium text-gray-500 shrink-0">Distribution</label>
          <div className="relative">
            <select
              value={distribution}
              onChange={(e) => setDistribution(e.target.value)}
              className="appearance-none pl-3 pr-8 py-1.5 text-sm border border-gray-200
                         rounded-lg bg-white text-gray-700 focus:outline-none focus:ring-2
                         focus:ring-blue-500 focus:border-transparent cursor-pointer"
            >
              {DISTRIBUTION_GROUPS.map((g) => (
                <optgroup key={g.group} label={g.group}>
                  {g.items.map((d) => (
                    <option key={d.codename} value={d.codename}>{d.label}</option>
                  ))}
                </optgroup>
              ))}
            </select>
            <Icon.ChevronDown className="w-4 h-4 text-gray-400 absolute right-2 top-1/2
                                         -translate-y-1/2 pointer-events-none"/>
          </div>

          <div className="flex-1"/>

          <button
            onClick={handleAnalyze}
            disabled={!content.trim() || analyzing}
            className="flex items-center gap-2 px-4 py-1.5 bg-gray-900 text-white
                       text-sm font-medium rounded-lg hover:bg-gray-700 transition-colors
                       disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {analyzing ? (
              <>
                <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10"
                    stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                </svg>
                Analyse en cours…
              </>
            ) : (
              <>
                <Icon.Search className="w-4 h-4"/>
                Analyser
              </>
            )}
          </button>
        </div>
      </div>

      {/* ── Error ──────────────────────────────────────────────────────────── */}
      {error && (
        <div className="flex items-start gap-3 bg-red-50 border border-red-200 rounded-xl
                        px-4 py-3 text-sm text-red-800">
          <Icon.X className="w-4 h-4 mt-0.5 shrink-0 text-red-500"/>
          {error}
        </div>
      )}

      {/* ── Results ────────────────────────────────────────────────────────── */}
      {result && (
        <div className="space-y-4">

          {/* All clear */}
          {result.importable === 0 && result.unknown === 0 && result.total > 0 && (
            <div className="flex items-center gap-3 bg-green-50 border border-green-200
                            rounded-xl px-4 py-3 text-sm text-green-800">
              <Icon.Check className="w-4 h-4 shrink-0 text-green-600"/>
              <span>
                Tous les paquets ({result.total}) sont déjà disponibles dans repod.
                Votre Dockerfile est prêt à builder.
              </span>
            </div>
          )}

          {/* No packages found */}
          {result.total === 0 && (
            <div className="flex items-start gap-3 bg-orange-50 border border-orange-200
                            rounded-xl px-4 py-3 text-sm text-orange-800">
              <Icon.Info className="w-4 h-4 mt-0.5 shrink-0 text-orange-500"/>
              <span>
                Aucun paquet détecté dans ce Dockerfile.
                Vérifiez qu'il contient des instructions d'installation :
                <code className="bg-orange-100 px-1 rounded font-mono text-xs mx-1">
                  apt-get install
                </code>
                <code className="bg-orange-100 px-1 rounded font-mono text-xs mx-1">
                  dnf install
                </code>
                ou
                <code className="bg-orange-100 px-1 rounded font-mono text-xs ml-1">
                  apk add
                </code>.
              </span>
            </div>
          )}

          {/* Package table */}
          {result.total > 0 && (
            <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">

              <ResultSummary result={result}/>

              {/* Table filter bar */}
              <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100">
                <div className="flex rounded-lg border border-gray-200 overflow-hidden text-xs
                                font-medium bg-gray-50">
                  {[
                    { id: "all",        label: `Tous (${result.total})`            },
                    { id: "available",  label: `Disponibles (${result.available})`  },
                    { id: "importable", label: `Importables (${result.importable})` },
                    { id: "unknown",    label: `Inconnus (${result.unknown})`       },
                  ].map((tab) => (
                    <button
                      key={tab.id}
                      onClick={() => setFilter(tab.id)}
                      className={`px-3 py-1.5 transition-colors ${
                        filter === tab.id
                          ? "bg-gray-800 text-white"
                          : "text-gray-500 hover:bg-gray-100"
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                {importableCount > 0 && (
                  <button
                    onClick={toggleAllImportable}
                    className="ml-auto text-xs text-blue-600 hover:text-blue-800
                               font-medium transition-colors"
                  >
                    {allImportableSelected ? "Tout désélectionner" : "Tout sélectionner"}
                  </button>
                )}
              </div>

              {/* Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-100 bg-gray-50 text-xs text-gray-500
                                   uppercase tracking-wide font-medium">
                      {importableCount > 0 && <th className="pl-4 pr-2 py-2.5 w-8"/>}
                      <th className="px-4 py-2.5 text-left">Paquet</th>
                      <th className="px-4 py-2.5 text-left">Statut</th>
                      <th className="px-4 py-2.5 text-left">Détails</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredPkgs.length === 0 ? (
                      <tr>
                        <td colSpan={importableCount > 0 ? 4 : 3}
                          className="px-4 py-8 text-center text-sm text-gray-400">
                          Aucun paquet dans cette catégorie
                        </td>
                      </tr>
                    ) : (
                      filteredPkgs.map((pkg) => (
                        <PackageRow
                          key={`${pkg.pkg_manager}-${pkg.name}`}
                          pkg={pkg}
                          selected={selected.has(pkg.name)}
                          onToggle={togglePackage}
                          showCheckbox={importableCount > 0}
                        />
                      ))
                    )}
                  </tbody>
                </table>
              </div>

              {/* Import action bar */}
              {importableCount > 0 && (
                <div className="flex items-center gap-3 px-4 py-3 border-t border-gray-100
                                bg-gray-50">
                  <span className="text-xs text-gray-500">
                    {selected.size} paquet{selected.size > 1 ? "s" : ""} sélectionné{selected.size > 1 ? "s" : ""}
                  </span>
                  <div className="flex-1"/>
                  <button
                    onClick={handleImport}
                    disabled={selected.size === 0 || running}
                    className="flex items-center gap-2 px-4 py-1.5 bg-blue-600 text-white
                               text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors
                               disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {running ? (
                      <>
                        <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10"
                            stroke="currentColor" strokeWidth="4"/>
                          <path className="opacity-75" fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                        </svg>
                        Import en cours…
                      </>
                    ) : (
                      <>
                        <Icon.Download className="w-4 h-4"/>
                        Importer {selected.size > 0 ? `(${selected.size})` : "les manquants"}
                      </>
                    )}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Import log console ─────────────────────────────────────────────── */}
      {(running || importDone) && logs.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
            <h3 className="text-sm font-medium text-gray-800">Journal d'import</h3>
            {running && (
              <span className="flex items-center gap-1.5 text-xs text-blue-600">
                <svg className="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10"
                    stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                </svg>
                En cours…
              </span>
            )}
            {importDone && !running && (
              <span className="text-xs text-green-600 font-medium">Terminé</span>
            )}
          </div>
          <div ref={logsRef}
            className="bg-gray-900 px-5 py-4 h-52 overflow-y-auto space-y-0.5">
            {logs.map((line, i) => <LogLine key={i} line={line}/>)}
          </div>
        </div>
      )}

      {/* ── Usage guide ────────────────────────────────────────────────────── */}
      {!result && !analyzing && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-100">
            <h3 className="text-sm font-medium text-gray-800">Comment utiliser cet outil</h3>
          </div>
          <div className="px-5 py-4">
            <ol className="space-y-4 text-sm text-gray-600">
              <li className="flex gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 text-gray-600
                                 flex items-center justify-center text-xs font-semibold">1</span>
                <div>
                  <p className="font-medium text-gray-800">Collez votre Dockerfile</p>
                  <p className="text-gray-500 mt-0.5 text-xs">
                    Copiez-collez le contenu de votre Dockerfile ou glissez-déposez le fichier.
                    La distribution est <strong>détectée automatiquement</strong> depuis la
                    ligne <code className="font-mono bg-gray-100 px-1 rounded">FROM</code>.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 text-gray-600
                                 flex items-center justify-center text-xs font-semibold">2</span>
                <div>
                  <p className="font-medium text-gray-800">Formats supportés</p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {Object.entries(PM_META).map(([pm, m]) => (
                      <span key={pm} className={`inline-flex items-center gap-1 px-2 py-0.5
                                                  rounded text-xs font-medium border
                                                  ${m.bg} ${m.text} ${m.border}`}>
                        <span className="font-bold">{m.label}</span>
                        <span className="opacity-70">
                          {pm === "apt" ? "apt-get / apt install"
                           : pm === "rpm" ? "dnf / yum / microdnf install"
                           : "apk add"}
                        </span>
                      </span>
                    ))}
                  </div>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 text-gray-600
                                 flex items-center justify-center text-xs font-semibold">3</span>
                <div>
                  <p className="font-medium text-gray-800">Analysez et importez</p>
                  <p className="text-gray-500 mt-0.5 text-xs">
                    Cliquez sur <strong>Analyser</strong> — l'outil identifie les paquets déjà
                    dans repod (vert), ceux importables depuis l'upstream (bleu) et les inconnus
                    (orange). Sélectionnez les paquets à importer puis cliquez{" "}
                    <strong>Importer</strong>.
                  </p>
                </div>
              </li>
              <li className="flex gap-3">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gray-100 text-gray-600
                                 flex items-center justify-center text-xs font-semibold">4</span>
                <div>
                  <p className="font-medium text-gray-800">Buildez votre image</p>
                  <p className="text-gray-500 mt-0.5 text-xs">
                    Une fois les paquets importés, configurez votre Dockerfile pour pointer
                    vers repod comme source et relancez votre{" "}
                    <code className="font-mono bg-gray-100 px-1 rounded">docker build</code>.
                  </p>
                </div>
              </li>
            </ol>
          </div>
        </div>
      )}
    </div>
  );
}
