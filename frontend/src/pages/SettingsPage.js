import { useState, useEffect, useRef, useCallback } from "react";
import toast from "react-hot-toast";
import HelpTooltip from "../components/HelpTooltip";
import {
  getSettings,
  patchSettings,
  testEmail,
  runRetention,
  getNextSync,
  getApiBaseUrl,
  getGpgInfo,
  generateGpgKey,
  listGroups,
  listUsers,
  getRepoUrl,
  getRpmRepoUrl,
  getExternalApiUrl,
} from "../api";

const API_URL = getApiBaseUrl();

// ─── Sources connues (label lisible) ─────────────────────────────────────────

const SOURCE_META = {
  // ── APT (Debian/Ubuntu) ───────────────────────────────────────────────────
  "ubuntu-jammy":             { label: "Ubuntu 22.04 (Jammy) — base",        security: false, format: "deb" },
  "ubuntu-jammy-updates":     { label: "Ubuntu 22.04 (Jammy) — updates",     security: false, format: "deb" },
  "ubuntu-noble":             { label: "Ubuntu 24.04 (Noble) — base",        security: false, format: "deb" },
  "ubuntu-focal":             { label: "Ubuntu 20.04 (Focal) — base",        security: false, format: "deb" },
  "debian-bookworm":          { label: "Debian 12 (Bookworm) — base",        security: false, format: "deb" },
  "ubuntu-jammy-security":    { label: "Ubuntu 22.04 Security",              security: true,  format: "deb" },
  "ubuntu-noble-security":    { label: "Ubuntu 24.04 Security",              security: true,  format: "deb" },
  "ubuntu-focal-security":    { label: "Ubuntu 20.04 Security",              security: true,  format: "deb" },
  "debian-bookworm-security": { label: "Debian 12 Security",                 security: true,  format: "deb" },
  // ── RPM (RHEL / Fedora / openSUSE) ───────────────────────────────────────
  "almalinux8-baseos":        { label: "AlmaLinux 8 — BaseOS",               security: false, format: "rpm" },
  "almalinux8-appstream":     { label: "AlmaLinux 8 — AppStream",            security: false, format: "rpm" },
  "almalinux8-extras":        { label: "AlmaLinux 8 — Extras",               security: false, format: "rpm" },
  "almalinux9-baseos":        { label: "AlmaLinux 9 — BaseOS",               security: false, format: "rpm" },
  "almalinux9-appstream":     { label: "AlmaLinux 9 — AppStream",            security: false, format: "rpm" },
  "rocky8-baseos":            { label: "Rocky Linux 8 — BaseOS",             security: false, format: "rpm" },
  "rocky8-appstream":         { label: "Rocky Linux 8 — AppStream",          security: false, format: "rpm" },
  "rocky9-baseos":            { label: "Rocky Linux 9 — BaseOS",             security: false, format: "rpm" },
  "rocky9-appstream":         { label: "Rocky Linux 9 — AppStream",          security: false, format: "rpm" },
  "centos-stream9-baseos":    { label: "CentOS Stream 9 — BaseOS",           security: false, format: "rpm" },
  "centos-stream9-appstream": { label: "CentOS Stream 9 — AppStream",        security: false, format: "rpm" },
  "oraclelinux8-baseos":      { label: "Oracle Linux 8 — BaseOS",            security: false, format: "rpm" },
  "oraclelinux8-appstream":   { label: "Oracle Linux 8 — AppStream",         security: false, format: "rpm" },
  "oraclelinux9-baseos":      { label: "Oracle Linux 9 — BaseOS",            security: false, format: "rpm" },
  "fedora42":                 { label: "Fedora 42",                          security: false, format: "rpm" },
  "fedora42-updates":         { label: "Fedora 42 — Updates",                security: false, format: "rpm" },
  "epel8":                    { label: "EPEL 8 (extras RHEL 8)",             security: false, format: "rpm" },
  "epel9":                    { label: "EPEL 9 (extras RHEL 9)",             security: false, format: "rpm" },
  "opensuse-leap-15.6-oss":   { label: "openSUSE Leap 15.6 — OSS",          security: false, format: "rpm" },
  "opensuse-leap-15.6-updates":{ label: "openSUSE Leap 15.6 — Updates",     security: false, format: "rpm" },
  "opensuse-tumbleweed-oss":  { label: "openSUSE Tumbleweed — OSS",          security: false, format: "rpm" },
  // ── APK (Alpine Linux) ───────────────────────────────────────────────────
  "alpine3.18-main":          { label: "Alpine 3.18 — main",                 security: false, format: "apk" },
  "alpine3.18-community":     { label: "Alpine 3.18 — community",            security: false, format: "apk" },
  "alpine3.19-main":          { label: "Alpine 3.19 — main",                 security: false, format: "apk" },
  "alpine3.19-community":     { label: "Alpine 3.19 — community",            security: false, format: "apk" },
  "alpine3.20-main":          { label: "Alpine 3.20 — main",                 security: false, format: "apk" },
  "alpine3.20-community":     { label: "Alpine 3.20 — community",            security: false, format: "apk" },
  "alpine3.21-main":          { label: "Alpine 3.21 — main",                 security: false, format: "apk" },
  "alpine3.21-community":     { label: "Alpine 3.21 — community",            security: false, format: "apk" },
};

// ─── Composants utilitaires ───────────────────────────────────────────────────

function SectionCard({ title, description, tooltip, icon, children }) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-3">
        <span className="w-5 h-5 text-gray-500 shrink-0">{icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold text-gray-900">{title}</h2>
            {tooltip && <HelpTooltip text={tooltip} position="right" />}
          </div>
          {description && <p className="text-xs text-gray-500 mt-0.5">{description}</p>}
        </div>
      </div>
      <div className="px-6 py-5 space-y-5">{children}</div>
    </div>
  );
}

function Toggle({ checked, onChange, disabled = false }) {
  return (
    <button
      type="button"
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none
        ${checked ? "bg-blue-600" : "bg-gray-300"}
        ${disabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform
          ${checked ? "translate-x-6" : "translate-x-1"}`}
      />
    </button>
  );
}

function FieldRow({ label, hint, children }) {
  return (
    <div className="flex items-start justify-between gap-6">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-700">{label}</p>
        {hint && <p className="text-xs text-gray-400 mt-0.5">{hint}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

// ─── Logs SSE (sync manuelle) ─────────────────────────────────────────────────

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

// ─── Section : Bases de sécurité ─────────────────────────────────────────────

function SecuritySection({ settings, onChange }) {
  const sec = settings.security || {};
  const TTL_OPTIONS = [1, 2, 4, 6, 12, 24, 48, 72];

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
      title="Bases de sécurité"
      description="TTL des caches KEV et EPSS. Réduire le TTL améliore la fraîcheur mais augmente les appels réseau."
      tooltip="KEV (CISA) et EPSS (FIRST.org) sont mis en cache localement. Le cache est réutilisé tant qu'il n'est pas expiré. En environnement air-gap, augmentez le TTL pour éviter les tentatives de connexion inutiles."
    >
      <FieldRow
        label="TTL cache KEV (CISA)"
        hint="Durée de validité du cache Known Exploited Vulnerabilities avant re-téléchargement."
      >
        <select
          value={sec.kev_ttl_hours ?? 24}
          onChange={(e) => onChange("security", { ...sec, kev_ttl_hours: parseInt(e.target.value) })}
          className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
        >
          {TTL_OPTIONS.map((h) => (
            <option key={h} value={h}>{h}h</option>
          ))}
        </select>
      </FieldRow>

      <FieldRow
        label="TTL cache EPSS (FIRST.org)"
        hint="Durée de validité du cache des scores de probabilité d'exploitation."
      >
        <select
          value={sec.epss_ttl_hours ?? 24}
          onChange={(e) => onChange("security", { ...sec, epss_ttl_hours: parseInt(e.target.value) })}
          className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
        >
          {TTL_OPTIONS.map((h) => (
            <option key={h} value={h}>{h}h</option>
          ))}
        </select>
      </FieldRow>

      <div className="rounded-lg bg-blue-50 border border-blue-100 px-4 py-3 text-xs text-blue-700 space-y-1">
        <p><strong>Grype (CVE)</strong> — mis à jour par le cron de synchronisation automatique (section ci-dessus).</p>
        <p><strong>ClamAV</strong> — géré par le daemon <code className="font-mono bg-blue-100 px-1 rounded">freshclam</code> interne au container, indépendant de RepoD.</p>
      </div>
    </SectionCard>
  );
}


// ─── Section : Synchronisation ────────────────────────────────────────────────

function SyncSection({ settings, onChange }) {
  const sync = settings.sync || {};
  const [logs, setLogs] = useState([]);
  const [running, setRunning] = useState(false);
  const [done, setDone] = useState(false);
  const [nextRun, setNextRun] = useState(null);
  const logsRef = useRef(null);

  useEffect(() => {
    getNextSync()
      .then((d) => setNextRun(d.next_run))
      .catch(() => {});
  }, [done]);

  useEffect(() => {
    if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
  }, [logs]);

  const handleManualSync = () => {
    const token = localStorage.getItem("token");
    setLogs([]);
    setDone(false);
    setRunning(true);

    fetch(`${API_URL}/import/sync-security`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({}),
    }).then(async (resp) => {
      if (!resp.ok) {
        setLogs(["error|Erreur serveur"]);
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
    }).catch(() => { setLogs(["error|Connexion perdue"]); setRunning(false); });
  };

  const HOURS = Array.from({ length: 24 }, (_, i) => i);
  const MINUTES = [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55];

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>}
      title="Synchronisation automatique"
      description="Planifiez la mise à jour quotidienne des sources de sécurité et des bases de vulnérabilités."
      tooltip="Chaque nuit à l'heure définie, repod interroge les sources de sécurité activées (APT, RPM ou APK selon le mode configuré) pour détecter les nouvelles CVE, met à jour la base de vulnérabilités Grype, et rafraîchit les flux de threat intelligence KEV (CISA) et EPSS (FIRST.org)."
    >
      <FieldRow
        label="Activer la sync automatique"
        hint="Désactiver stoppe le cron — la sync manuelle reste disponible."
      >
        <Toggle
          checked={sync.enabled ?? true}
          onChange={(v) => onChange("sync", { ...sync, enabled: v })}
        />
      </FieldRow>

      <div className={`space-y-4 ${!(sync.enabled ?? true) ? "opacity-40 pointer-events-none" : ""}`}>
        <FieldRow
          label="Heure de déclenchement"
          hint="Heure et minute (fuseau UTC par défaut — configurable via settings.sync.timezone)"
        >
          <div className="flex items-center gap-2">
            <select
              value={sync.hour ?? 3}
              onChange={(e) => onChange("sync", { ...sync, hour: parseInt(e.target.value) })}
              className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
            >
              {HOURS.map((h) => (
                <option key={h} value={h}>{String(h).padStart(2, "0")}h</option>
              ))}
            </select>
            <span className="text-gray-400 text-sm">:</span>
            <select
              value={sync.minute ?? 0}
              onChange={(e) => onChange("sync", { ...sync, minute: parseInt(e.target.value) })}
              className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
            >
              {MINUTES.map((m) => (
                <option key={m} value={m}>{String(m).padStart(2, "0")}</option>
              ))}
            </select>
          </div>
        </FieldRow>

        {nextRun && (
          <p className="text-xs text-gray-500 bg-blue-50 border border-blue-100 rounded-lg px-3 py-2">
            <span className="inline-flex items-center justify-center w-4 h-4 shrink-0 align-middle mr-1"><svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></span> Prochain déclenchement :{" "}
            <strong>{new Date(nextRun).toLocaleString("fr-FR")}</strong>
          </p>
        )}
      </div>

      {/* Sync manuelle */}
      <div className="pt-2 border-t border-gray-100">
        <div className="flex items-center justify-between mb-3">
          <div>
            <p className="text-sm font-medium text-gray-700">Synchronisation manuelle</p>
            <p className="text-xs text-gray-400">Déclenche immédiatement la sync des sources sécurité actives.</p>
          </div>
          <button
            onClick={handleManualSync}
            disabled={running}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white text-sm font-medium
                       rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            {running ? "En cours..." : "Sync sécurité"}
          </button>
        </div>
        {logs.length > 0 && (
          <div className="border border-gray-800 rounded-lg bg-gray-900 p-3">
            <div ref={logsRef} className="max-h-40 overflow-y-auto space-y-0.5">
              {logs.map((line, i) => <LogLine key={i} line={line} />)}
            </div>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ─── Section : Sources (APT + RPM) ───────────────────────────────────────────

function SourcesSection({ settings, onChange }) {
  const sources = settings.sources || {};

  const aptStd  = Object.keys(SOURCE_META).filter((id) => SOURCE_META[id].format === "deb" && !SOURCE_META[id].security);
  const aptSec  = Object.keys(SOURCE_META).filter((id) => SOURCE_META[id].format === "deb" &&  SOURCE_META[id].security);
  const rpmIds  = Object.keys(SOURCE_META).filter((id) => SOURCE_META[id].format === "rpm");
  const apkIds  = Object.keys(SOURCE_META).filter((id) => SOURCE_META[id].format === "apk");

  const SourceRow = ({ id }) => {
    const meta = SOURCE_META[id] || { label: id, security: false };
    const enabled = sources[id] ?? true;
    return (
      <div className="flex items-center justify-between py-2.5 border-b border-gray-50 last:border-0">
        <div className="flex items-center gap-2">
          {meta.security && <span title="Source de sécurité"><svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></span>}
          <div>
            <p className="text-sm text-gray-800">{meta.label}</p>
            <p className="text-xs text-gray-400 font-mono">{id}</p>
          </div>
        </div>
        <Toggle
          checked={enabled}
          onChange={(v) => onChange("sources", { ...sources, [id]: v })}
        />
      </div>
    );
  };

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polygon points="12 2 2 7 12 12 22 7"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>}
      title="Sources de paquets"
      description="Activez ou désactivez chaque source. Les sources désactivées sont ignorées lors de la synchronisation et de la recherche d'index."
      tooltip="Repod indexe les paquets disponibles depuis les dépôts officiels APT (Ubuntu/Debian) et RPM (RHEL/Fedora/openSUSE). Les sources marquées 'Sécurité' contiennent les correctifs CVE."
    >
      {/* ── APT (Debian/Ubuntu) ── */}
      <div className="space-y-0">
        <p className="text-xs font-semibold text-blue-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3"/></svg>
          Sources APT — Debian / Ubuntu
        </p>
        <div>
          <p className="text-xs text-gray-400 uppercase tracking-wider mb-1.5 ml-0.5">Standard</p>
          {aptStd.map((id) => <SourceRow key={id} id={id} />)}
        </div>
        <div className="mt-3">
          <p className="text-xs font-semibold text-red-500 uppercase tracking-wider mb-2 flex items-center gap-1">
            <svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            Sécurité (CVE)
          </p>
          {aptSec.map((id) => <SourceRow key={id} id={id} />)}
        </div>
      </div>

      {/* ── Séparateur ── */}
      <hr className="border-gray-100" />

      {/* ── RPM (RHEL / Fedora / openSUSE) ── */}
      <div className="space-y-0">
        <p className="text-xs font-semibold text-orange-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10"/></svg>
          Sources RPM — RHEL / Fedora / openSUSE
        </p>
        {rpmIds.map((id) => <SourceRow key={id} id={id} />)}
      </div>

      {/* ── Séparateur ── */}
      <hr className="border-gray-100" />

      {/* ── APK (Alpine Linux) ── */}
      <div className="space-y-0">
        <p className="text-xs font-semibold text-emerald-600 uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 20h20L12 2z"/>
          </svg>
          Sources APK — Alpine Linux
        </p>
        <p className="text-xs text-gray-400 mb-2">Activez les versions Alpine dont vous hébergez les paquets. Les sources actives sont scannées lors de la synchronisation.</p>
        {apkIds.map((id) => <SourceRow key={id} id={id} />)}
      </div>
    </SectionCard>
  );
}

// ─── Section : Rétention ─────────────────────────────────────────────────────

function RetentionSection({ settings, onChange }) {
  const ret = settings.retention || {};
  const [running, setRunning]   = useState(false);
  const [lastRun, setLastRun]   = useState(null);   // { ran_at, audit_logs, packages, total_freed_bytes }

  const handleRunNow = async () => {
    setRunning(true);
    try {
      const res = await runRetention();
      setLastRun(res.result);
      toast.success("Nettoyage terminé !");
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Erreur lors du nettoyage");
    } finally {
      setRunning(false);
    }
  };

  const fmtBytes = (b) => {
    if (b >= 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} Mo`;
    if (b >= 1024)         return `${(b / 1024).toFixed(0)} Ko`;
    return `${b} o`;
  };

  const fmtDate = (iso) => {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("fr-FR", {
        day: "2-digit", month: "2-digit", year: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    } catch { return iso; }
  };

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>}
      title="Rétention & nettoyage"
      tooltip="Définit combien de temps les logs d'audit et les anciennes versions de paquets sont conservés. Les logs d'audit sont requis pour la conformité NIS2. Les anciens paquets sont déplacés vers /repos/archive avant suppression."
      description="Conservation automatique des logs et des anciennes versions de paquets."
    >
      <FieldRow
        label="Rétention des logs d'audit"
        hint="Les fichiers JSONL plus anciens que ce délai sont supprimés automatiquement (cron 02h00)."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={7}
            max={3650}
            value={ret.audit_days ?? 90}
            onChange={(e) =>
              onChange("retention", { ...ret, audit_days: parseInt(e.target.value) || 90 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
          />
          <span className="text-sm text-gray-500">jours</span>
        </div>
      </FieldRow>

      <FieldRow
        label="Rétention des vieux paquets"
        hint="Les versions périmées (remplacées par une plus récente) sont supprimées après ce délai."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            max={365}
            value={ret.import_cleanup_days ?? 30}
            onChange={(e) =>
              onChange("retention", { ...ret, import_cleanup_days: parseInt(e.target.value) || 30 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
          />
          <span className="text-sm text-gray-500">jours</span>
        </div>
      </FieldRow>

      {/* Déclenchement manuel */}
      <div className="pt-2 border-t border-gray-100">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-700">Nettoyage manuel</p>
            <p className="text-xs text-gray-500 mt-0.5">
              Planifié chaque nuit à 02h00. Déclenchez-le immédiatement si besoin.
            </p>
          </div>
          <button
            onClick={handleRunNow}
            disabled={running}
            className="flex items-center gap-1.5 px-4 py-2 bg-orange-600 text-white text-sm
                       font-medium rounded-lg hover:bg-orange-700 disabled:opacity-50
                       disabled:cursor-not-allowed transition-colors"
          >
            {running ? (
              <>
                <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                </svg>
                Nettoyage…
              </>
            ) : (
              <><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg> Lancer maintenant</>
            )}
          </button>
        </div>

        {/* Résultat du dernier nettoyage */}
        {lastRun && (
          <div className="mt-3 bg-green-50 border border-green-200 rounded-lg p-3 text-xs text-green-800 space-y-1">
            <p className="font-medium">Dernier nettoyage : {fmtDate(lastRun.ran_at)}</p>
            <div className="grid grid-cols-3 gap-2 mt-1">
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {lastRun.audit_logs?.deleted ?? 0}
                </p>
                <p className="text-gray-500">logs supprimés</p>
              </div>
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {lastRun.packages?.deleted ?? 0}
                </p>
                <p className="text-gray-500">paquets supprimés</p>
              </div>
              <div className="bg-white rounded p-2 text-center border border-green-100">
                <p className="text-lg font-bold text-green-700">
                  {fmtBytes(lastRun.total_freed_bytes ?? 0)}
                </p>
                <p className="text-gray-500">libérés</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

// ─── Section : Validation ─────────────────────────────────────────────────────

function ValidationSection({ settings, onChange }) {
  const val = settings.validation || {};

  return (
    <SectionCard
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
      title="Validation des paquets"
      tooltip="Pipeline de validation exécuté à chaque upload. Chaque étape peut bloquer ou laisser passer le paquet selon sa configuration. Le scan ClamAV utilise le daemon clamd (signatures chargées en mémoire — rapide). Le scan CVE utilise Grype."
      description="Contrôles appliqués à chaque paquet importé ou uploadé manuellement."
    >
      <FieldRow
        label="Vérification SHA256"
        hint="Compare le hash du fichier téléchargé avec celui de l'index upstream."
      >
        <Toggle
          checked={val.sha256_check ?? true}
          onChange={(v) => onChange("validation", { ...val, sha256_check: v })}
        />
      </FieldRow>

      <FieldRow
        label="Scan antivirus ClamAV"
        hint="Analyse chaque .deb avant de l'accepter dans le dépôt."
      >
        <Toggle
          checked={val.clamav_scan ?? true}
          onChange={(v) => onChange("validation", { ...val, clamav_scan: v })}
        />
      </FieldRow>

      <FieldRow
        label="Signature GPG obligatoire"
        hint="Si activé, tout paquet sans fichier .sig/.asc accompagnant (ou avec une signature invalide) est rejeté."
      >
        <Toggle
          checked={val.gpg_required ?? false}
          onChange={(v) => onChange("validation", { ...val, gpg_required: v })}
        />
      </FieldRow>

      <FieldRow
        label="Taille max upload manuel"
        hint="Limite la taille des fichiers .deb uploadés via l'interface."
      >
        <div className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            max={4096}
            value={val.max_upload_size_mb ?? 500}
            onChange={(e) =>
              onChange("validation", { ...val, max_upload_size_mb: parseInt(e.target.value) || 500 })
            }
            className="w-24 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                       focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
          />
          <span className="text-sm text-gray-500">Mo</span>
        </div>
      </FieldRow>
    </SectionCard>
  );
}

// ─── Section Politique CVE ───────────────────────────────────────────────────

const CVE_ACTIONS = [
  { key: "block",  label: "Bloquer",    color: "bg-red-500",    desc: "Rejet immédiat, quarantaine" },
  { key: "review", label: "Révision",   color: "bg-amber-500",  desc: "En attente RSSI" },
  { key: "warn",   label: "Avertir",    color: "bg-yellow-400", desc: "Import OK, avertissement" },
  { key: "allow",  label: "Autoriser",  color: "bg-green-500",  desc: "Transparent" },
];

function PolicySelect({ value, onChange }) {
  return (
    <div className="flex gap-1.5">
      {CVE_ACTIONS.map((a) => (
        <button
          key={a.key}
          title={a.desc}
          onClick={() => onChange(a.key)}
          className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all border-2 ${
            value === a.key
              ? `${a.color} text-white border-transparent shadow`
              : "bg-white text-gray-600 border-gray-200 hover:border-gray-400"
          }`}
        >
          {a.label}
        </button>
      ))}
    </div>
  );
}

function CvePolicySection({ settings, onChange }) {
  const pol = settings?.cve_policy || {};
  const set = (key, val) => onChange("cve_policy", { ...pol, [key]: val });

  return (
    <SectionCard
      title="Politique CVE"
      tooltip="Définit l'action automatique par niveau de sévérité CVSS. Bloquer : le paquet est rejeté en quarantaine. Révision : en attente de décision RSSI. Avertir : accepté avec alerte. Autoriser : transparant, aucune action."
      description="Comportement à l'import selon la sévérité des vulnérabilités détectées par Grype."
      icon={<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}
    >
      <div className="space-y-4">
        {/* Avertissement si aucune politique n'est réellement enregistrée :
            tant que cve_policy est vide côté serveur, le backend retombe sur
            un mode historique binaire (bloque uniquement si ≥ CRITICAL,
            AUCUN palier "révision" n'existe dans ce mode) — très différent
            de ce que les boutons ci-dessous pourraient laisser croire avant
            toute sauvegarde. */}
        {Object.keys(pol).length === 0 && (
          <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-xs text-amber-700">
            <svg className="w-3.5 h-3.5 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Aucune politique n'est encore enregistrée. Tant qu'aucun choix
            n'est fait ci-dessous puis sauvegardé, le serveur utilise un mode
            historique qui ne bloque que les CVE CRITICAL — aucune révision
            RSSI n'est déclenchée pour HIGH/MEDIUM/LOW, même si les boutons
            semblent présélectionnés.
          </div>
        )}
        {/* Grille severité → action */}
        {[
          { key: "critical",   label: "CRITICAL",   desc: "CVE de score CVSS ≥ 9" },
          { key: "high",       label: "HIGH",        desc: "CVE de score CVSS 7–9" },
          { key: "medium",     label: "MEDIUM",      desc: "CVE de score CVSS 4–7" },
          { key: "low",        label: "LOW",         desc: "CVE de score CVSS < 4" },
          { key: "negligible", label: "NEGLIGIBLE",  desc: "CVE sans impact réel" },
        ].map(({ key, label, desc }) => (
          <div key={key} className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-gray-800">
                {label}
                {pol[key] === undefined && (
                  <span className="ml-2 text-[10px] font-normal text-amber-600 align-middle">non enregistré</span>
                )}
              </p>
              <p className="text-xs text-gray-400">{desc}</p>
            </div>
            <PolicySelect
              value={pol[key]}
              onChange={(v) => set(key, v)}
            />
          </div>
        ))}

        <div className="border-t border-gray-100 pt-4 space-y-3">
          {/* SLA */}
          <FieldRow
            label="SLA HIGH (jours)"
            hint="Délai maximal de remédiation pour un HIGH en révision. Alerte à J-7."
          >
            <input
              type="number" min={1} max={365}
              value={pol.sla_high_days ?? 30}
              onChange={(e) => set("sla_high_days", parseInt(e.target.value) || 30)}
              className="w-20 px-3 py-1.5 border border-gray-300 rounded-lg text-sm text-center
                         focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300"
            />
          </FieldRow>

          {/* Enrichissement EPSS/KEV */}
          <FieldRow
            label="Enrichissement EPSS + KEV"
            hint="Ajoute le score EPSS et le statut CISA KEV à chaque CVE à l'import (nécessite internet)."
          >
            <Toggle
              checked={pol.auto_enrich !== false}
              onChange={(v) => set("auto_enrich", v)}
            />
          </FieldRow>
        </div>

        {/* Légende */}
        <div className="bg-gray-50 rounded-lg p-3">
          <p className="text-xs font-semibold text-gray-500 mb-2">Légende des actions</p>
          <div className="grid grid-cols-2 gap-1.5">
            {CVE_ACTIONS.map((a) => (
              <div key={a.key} className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full ${a.color}`}></span>
                <span className="text-xs text-gray-600"><strong>{a.label}</strong> — {a.desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

// ─── Section Politique EPSS ───────────────────────────────────────────────────

function EpssPolicySection({ settings, onChange }) {
  const pol = settings?.epss_policy || {};
  const set = (key, val) => onChange("epss_policy", { ...pol, [key]: val });

  const enabled   = pol.enabled !== false;
  const blockVal  = Math.round((pol.block_threshold  ?? 0.9) * 100);
  const reviewVal = Math.round((pol.review_threshold ?? 0.5) * 100);

  const EpssBar = ({ value, color, label }) => {
    const pct = ((value - 1) / 98) * 100;
    const trackBg = `linear-gradient(to right, #7c3aed ${pct}%, #e2e8f0 ${pct}%)`;
    return (
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-slate-700">{label}</span>
          <span className={`font-bold font-mono ${color}`}>{value}%</span>
        </div>
        <input
          type="range" min={1} max={99} step={1}
          value={value}
          disabled={!enabled}
          onChange={(e) => {
            const v = parseInt(e.target.value, 10) / 100;
            if (label.includes("Blocage")) set("block_threshold", v);
            else set("review_threshold", v);
          }}
          style={{ background: trackBg }}
          className="w-full h-2 rounded-full appearance-none cursor-pointer disabled:opacity-40
                     [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4
                     [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:rounded-full
                     [&::-webkit-slider-thumb]:bg-blue-600 [&::-webkit-slider-thumb]:border-2
                     [&::-webkit-slider-thumb]:border-white [&::-webkit-slider-thumb]:shadow-md
                     [&::-webkit-slider-thumb]:cursor-pointer
                     [&::-moz-range-thumb]:w-4 [&::-moz-range-thumb]:h-4
                     [&::-moz-range-thumb]:rounded-full [&::-moz-range-thumb]:bg-blue-600
                     [&::-moz-range-thumb]:border-2 [&::-moz-range-thumb]:border-white
                     [&::-moz-range-thumb]:shadow-md [&::-moz-range-thumb]:cursor-pointer
                     [&::-moz-range-thumb]:border-solid"
        />
      </div>
    );
  };

  return (
    <SectionCard
      title="Politique EPSS"
      tooltip="EPSS (Exploit Prediction Scoring System — FIRST.org) mesure la probabilité qu'une CVE soit activement exploitée dans les 30 prochains jours."
      description="Seuils d'exploitation pour bloquer ou suspendre une promotion, indépendamment de la sévérité CVSS."
      icon={
        <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          strokeLinecap="round" strokeLinejoin="round">
          <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
        </svg>
      }
    >
      <div className="space-y-4">
        <div className="flex items-center justify-between py-1 border-b border-slate-100 pb-3">
          <div>
            <p className="text-sm font-medium text-slate-800">Activer la politique EPSS</p>
            <p className="text-xs text-slate-500 mt-0.5">Vérifie les scores EPSS lors des promotions</p>
          </div>
          <Toggle
            checked={enabled}
            onChange={(v) => set("enabled", v)}
          />
        </div>

        <div className={`space-y-4 transition-opacity ${!enabled ? "opacity-40 pointer-events-none" : ""}`}>
          <EpssBar value={blockVal}  color="text-red-600"    label="Seuil de Blocage (EPSS ≥ N → promotion bloquée)" />
          <EpssBar value={reviewVal} color="text-orange-600" label="Seuil de Revue RSSI (EPSS ≥ N → approbation requise)" />

          <div className="bg-slate-50 rounded-lg p-3 space-y-1.5 text-[11px] text-slate-600">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-slate-300 shrink-0"/>
              <span>EPSS &lt; {reviewVal}% — promotion autorisée</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-orange-400 shrink-0"/>
              <span>EPSS {reviewVal}–{blockVal - 1}% — approbation RSSI requise</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-red-500 shrink-0"/>
              <span>EPSS ≥ {blockVal}% — promotion bloquée</span>
            </div>
            <div className="flex items-center gap-2 pt-1 border-t border-slate-200">
              <span className="w-2 h-2 rounded-full bg-blue-400 shrink-0"/>
              <span>
                Scores mis à jour depuis{" "}
                <a href="https://api.first.org" target="_blank" rel="noreferrer"
                  className="text-blue-600 underline">api.first.org</a>
                {" "}à chaque scan (cache 24h).
              </span>
            </div>
          </div>
        </div>
      </div>
    </SectionCard>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function SettingsPage() {
  const [settings, setSettings] = useState(null);
  const [original, setOriginal] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    getSettings()
      .then((data) => {
        setSettings(data);
        setOriginal(JSON.stringify(data));
      })
      .catch(() => toast.error("Impossible de charger les paramètres"))
      .finally(() => setLoading(false));
  }, []);

  const isDirty = settings && JSON.stringify(settings) !== original;

  const handleChange = (section, value) => {
    setSettings((prev) => ({ ...prev, [section]: value }));
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const updated = await patchSettings(settings);
      setSettings(updated);
      setOriginal(JSON.stringify(updated));
      toast.success("Paramètres enregistrés");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la sauvegarde");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-gray-400 text-sm">
        Chargement des paramètres...
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="text-center py-24 text-red-500 text-sm">
        Impossible de charger les paramètres. Vérifiez que vous êtes connecté en tant qu'administrateur.
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Paramètres</h1>
          <p className="text-sm text-gray-500 mt-1">
            Configuration du serveur repod (admin uniquement).
          </p>
        </div>
      </div>

      {/* Sections */}
      <SyncSection settings={settings} onChange={handleChange} />
      <SecuritySection settings={settings} onChange={handleChange} />
      <SourcesSection settings={settings} onChange={handleChange} />
      <EmailSection settings={settings} onChange={handleChange} />
      <NotificationRulesSection settings={settings} onChange={handleChange} />
      <RetentionSection settings={settings} onChange={handleChange} />
      <ValidationSection settings={settings} onChange={handleChange} />
      <CvePolicySection settings={settings} onChange={handleChange} />
      <EpssPolicySection settings={settings} onChange={handleChange} />
      <ContainersSection />
      <GpgSection />
      <CiIntegrationsSection />

      {/* Barre de sauvegarde sticky */}
      {isDirty && (
        <div className="fixed bottom-0 left-0 right-0 z-40 bg-white border-t border-gray-200 shadow-[0_-4px_12px_rgba(0,0,0,0.08)]">
          <div className="max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
              <span className="text-sm text-gray-600">Modifications non sauvegardées</span>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={() => { setSettings(JSON.parse(original)); }}
                className="text-sm text-gray-500 hover:text-gray-700 px-3 py-1.5 transition-colors">
                Annuler
              </button>
              <button onClick={handleSave} disabled={saving}
                className="px-5 py-2 bg-blue-600 text-white text-sm font-semibold rounded-lg
                           hover:bg-blue-700 disabled:opacity-50 transition-colors">
                {saving ? "Enregistrement..." : "Sauvegarder"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


// ─── Section Email SMTP ────────────────────────────────────────────────────────

function EmailSection({ settings, onChange }) {
  const cfg = settings?.email || {};
  const [testing, setTesting] = useState(false);
  const [testTo, setTestTo] = useState("");

  const set = (key, val) => onChange("email", { ...cfg, [key]: val });

  const handleTest = async () => {
    setTesting(true);
    try {
      await testEmail(testTo || null);
      toast.success("Email de test envoyé !");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Échec envoi email");
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Notifications email (SMTP)</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Alertes CVE, SLA et révisions envoyées par email en complément du webhook.
          </p>
        </div>
        <Toggle checked={!!cfg.enabled} onChange={(v) => set("enabled", v)} />
      </div>

      <div className={`p-6 space-y-4 ${!cfg.enabled ? "opacity-50 pointer-events-none" : ""}`}>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Serveur SMTP</label>
            <input type="text" value={cfg.smtp_host || ""} onChange={e => set("smtp_host", e.target.value)}
              placeholder="smtp.example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Port</label>
            <input type="number" value={cfg.smtp_port || 587} onChange={e => set("smtp_port", parseInt(e.target.value))}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Utilisateur SMTP</label>
            <input type="text" value={cfg.smtp_user || ""} onChange={e => set("smtp_user", e.target.value)}
              placeholder="repod@example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Mot de passe</label>
            <input type="password" value={cfg.smtp_password || ""} onChange={e => set("smtp_password", e.target.value)}
              placeholder="••••••••"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Adresse expéditeur</label>
          <input type="email" value={cfg.from_address || ""} onChange={e => set("from_address", e.target.value)}
            placeholder="repod@example.com"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Destinataires par defaut <span className="text-gray-400 font-normal normal-case">(separes par des virgules)</span>
          </label>
          <input type="text" value={cfg.to_addresses || ""} onChange={e => set("to_addresses", e.target.value)}
            placeholder="rssi@example.com, admin@example.com"
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
          <p className="text-xs text-gray-400 mt-1">Utilises lorsqu'aucune regle de notification specifique n'est configuree pour un evenement.</p>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" checked={cfg.use_tls !== false}
              onChange={e => set("use_tls", e.target.checked)}
              className="rounded" />
            <span className="text-sm text-gray-700">Utiliser STARTTLS (recommandé)</span>
          </label>
        </div>

        {/* Test email */}
        <div className="pt-2 border-t border-gray-100">
          <p className="text-sm font-medium text-gray-700 mb-2">Tester la configuration</p>
          <div className="flex gap-2">
            <input type="email" value={testTo} onChange={e => setTestTo(e.target.value)}
              placeholder="Destinataire test (optionnel)"
              className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300" />
            <button onClick={handleTest} disabled={testing}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors">
              {testing ? "Envoi..." : "Envoyer un test"}
            </button>
          </div>
          <p className="text-xs text-gray-400 mt-1">
            Si vide, l'email est envoyé aux destinataires configurés ci-dessus.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Section Règles de notification ──────────────────────────────────────────

const EVENT_META = {
  pending_review:   { label: "Paquet en révision RSSI",  desc: "Importé mais bloqué par une CVE — décision RSSI requise" },
  decision_taken:   { label: "Décision prise",            desc: "Un RSSI enregistre une décision CVE (acceptation, rejet…)" },
  sla_expiring:     { label: "SLA expirant",              desc: "Décisions CVE qui expirent dans les 7 prochains jours" },
  cve_assignment:   { label: "Assignation CVE",           desc: "Une décision CVE est assignée à un utilisateur ou groupe" },
};

const ROLE_OPTIONS = [
  { value: "admin",      label: "Administrateur" },
  { value: "maintainer", label: "Mainteneur" },
  { value: "uploader",   label: "Importateur" },
  { value: "auditor",    label: "Auditeur" },
  { value: "reader",     label: "Lecteur" },
];

const DYNAMIC_TYPES = ["assigned_to", "escalated_by", "decided_by"];
const DYNAMIC_LABELS = {
  assigned_to:  "Assigné à (résolu à l'envoi)",
  escalated_by: "Escaladé par (résolu à l'envoi)",
  decided_by:   "Décidé par (résolu à l'envoi)",
};

function RecipientBadge({ rec, onRemove }) {
  const labels = {
    role: `Rôle: ${rec.value}`, group: `Groupe: ${rec.value}`,
    user: `User: ${rec.value}`, email: rec.value,
    assigned_to: "Assigné à", escalated_by: "Escaladé par", decided_by: "Décidé par",
  };
  return (
    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium bg-blue-50 text-blue-700">
      {labels[rec.type] || `${rec.type}: ${rec.value || ""}`}
      <button onClick={onRemove} className="ml-0.5 hover:opacity-70 leading-none">×</button>
    </span>
  );
}

function AddRecipientForm({ onAdd, groups, users }) {
  const [type, setType]   = useState("role");
  const [value, setValue] = useState("");
  const isDynamic = DYNAMIC_TYPES.includes(type);
  const handleAdd = () => {
    if (!isDynamic && !value.trim()) return;
    onAdd({ type, value: isDynamic ? "" : value.trim() });
    setValue("");
  };
  return (
    <div className="flex items-center gap-2 mt-2 flex-wrap">
      <select value={type} onChange={e => { setType(e.target.value); setValue(""); }}
        className="text-xs border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 bg-white">
        <optgroup label="Statique">
          <option value="role">Rôle</option>
          <option value="group">Groupe</option>
          <option value="user">Utilisateur</option>
          <option value="email">Email direct</option>
        </optgroup>
        <optgroup label="Dynamique (résolu à l'envoi)">
          <option value="assigned_to">Assigné à</option>
          <option value="escalated_by">Escaladé par</option>
          <option value="decided_by">Décidé par</option>
        </optgroup>
      </select>
      {!isDynamic && type === "role" && (
        <select value={value} onChange={e => setValue(e.target.value)}
          className="text-xs border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 bg-white">
          <option value="">— Choisir un rôle —</option>
          {ROLE_OPTIONS.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
        </select>
      )}
      {!isDynamic && type === "group" && (
        <select value={value} onChange={e => setValue(e.target.value)}
          className="text-xs border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 bg-white">
          <option value="">— Choisir un groupe —</option>
          {groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select>
      )}
      {!isDynamic && type === "user" && (
        <select value={value} onChange={e => setValue(e.target.value)}
          className="text-xs border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 bg-white">
          <option value="">— Choisir un utilisateur —</option>
          {users.map(u => <option key={u.username} value={u.username}>{u.username}{u.email ? ` (${u.email})` : ""}</option>)}
        </select>
      )}
      {!isDynamic && type === "email" && (
        <input type="email" value={value} onChange={e => setValue(e.target.value)}
          placeholder="nom@exemple.com"
          className="text-xs border border-gray-300 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-100 focus:border-blue-300 w-48"
          onKeyDown={e => e.key === "Enter" && handleAdd()} />
      )}
      {isDynamic && <span className="text-xs text-gray-500 italic">{DYNAMIC_LABELS[type]}</span>}
      <button onClick={handleAdd}
        className="text-xs px-3 py-1.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium">
        Ajouter
      </button>
    </div>
  );
}

const DEFAULT_NOTIFICATION_RULES = [
  { event: "pending_review", enabled: true, recipients: [
    { type: "role", value: "admin" },
    { type: "role", value: "maintainer" },
  ]},
  { event: "decision_taken", enabled: true, recipients: [
    { type: "escalated_by" },
    { type: "assigned_to" },
  ]},
  { event: "sla_expiring", enabled: true, recipients: [
    { type: "role", value: "admin" },
    { type: "assigned_to" },
  ]},
  { event: "cve_assignment", enabled: true, recipients: [
    { type: "assigned_to" },
  ]},
];

function NotificationRulesSection({ settings, onChange }) {
  const savedRules = settings?.notification_rules || [];
  const rules = DEFAULT_NOTIFICATION_RULES.map(def => {
    const saved = savedRules.find(r => r.event === def.event);
    return saved || def;
  });
  const [expandedEvent, setExpandedEvent] = useState(null);
  const [groups, setGroups] = useState([]);
  const [users, setUsers]   = useState([]);

  useEffect(() => {
    Promise.all([
      listGroups().catch(() => ({ groups: [] })),
      listUsers().catch(() => ({ users: [] })),
    ]).then(([gRes, uRes]) => {
      setGroups(gRes.groups || []);
      setUsers(uRes.users || []);
    });
  }, []);

  const getRule = (event) =>
    rules.find(r => r.event === event) || { event, enabled: true, recipients: [] };

  const updateRules = (event, patch) => {
    const existing = rules.find(r => r.event === event);
    let updated;
    if (existing) {
      updated = rules.map(r => r.event === event ? { ...r, ...patch } : r);
    } else {
      updated = [...rules, { event, enabled: true, recipients: [], ...patch }];
    }
    onChange("notification_rules", updated);
  };

  const toggleEvent = (event, enabled) => updateRules(event, { enabled });
  const addRecipient = (event, rec) => {
    const rule = getRule(event);
    updateRules(event, { recipients: [...rule.recipients, rec] });
  };
  const removeRecipient = (event, idx) => {
    const rule = getRule(event);
    updateRules(event, { recipients: rule.recipients.filter((_, i) => i !== idx) });
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100">
        <h2 className="text-base font-semibold text-gray-900">Règles de notification par événement</h2>
        <p className="text-xs text-gray-400 mt-0.5">
          Définissez qui reçoit les alertes pour chaque type d'événement.
        </p>
      </div>
      <div className="divide-y divide-gray-100">
        {Object.entries(EVENT_META).map(([event, meta]) => {
          const rule    = getRule(event);
          const enabled = rule.enabled !== false;
          const isOpen  = expandedEvent === event;
          return (
            <div key={event} className="px-6 py-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-gray-700">{meta.label}</span>
                    <div className="flex flex-wrap gap-1">
                      {rule.recipients.map((rec, idx) => (
                        <RecipientBadge key={idx} rec={rec} onRemove={() => removeRecipient(event, idx)} />
                      ))}
                      {rule.recipients.length === 0 && enabled && (
                        <span className="text-xs text-gray-400 italic">Aucun destinataire — les emails seront envoyes aux adresses par defaut (section SMTP)</span>
                      )}
                    </div>
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">{meta.desc}</p>
                  {isOpen && <AddRecipientForm onAdd={(rec) => addRecipient(event, rec)} groups={groups} users={users} />}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <button onClick={() => setExpandedEvent(isOpen ? null : event)}
                    className="text-xs px-2.5 py-1 border border-gray-300 rounded-lg text-gray-500 hover:bg-gray-50 hover:border-blue-300 hover:text-blue-600 transition-colors">
                    {isOpen ? "Fermer" : "+ Ajouter"}
                  </button>
                  <Toggle checked={enabled} onChange={(v) => toggleEvent(event, v)} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
      <div className="px-6 py-3 bg-gray-50 border-t border-gray-100">
        <p className="text-xs text-gray-400">
          Si aucune règle n'est configurée pour un événement, les emails sont envoyés aux <strong>Destinataires</strong> configurés dans la section SMTP.
        </p>
      </div>
    </div>
  );
}

// ─── Section Intégrations CI/CD ───────────────────────────────────────────────

function CopySnippet({ code }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="bg-gray-900 text-green-300 text-xs font-mono p-4 rounded-xl overflow-x-auto leading-relaxed max-h-56 overflow-y-auto">
        {code}
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-2 right-2 px-2 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded transition-colors"
      >
        {copied ? "✓ Copié" : "Copier"}
      </button>
    </div>
  );
}

function CiIntegrationsSection() {
  const [activeTab, setActiveTab] = useState("github");

  const repodUrl    = API_URL.replace("/api/v1", "");
  const ghUpload    = `# .github/workflows/repod-upload.yml
name: Publish to repod
on:
  push:
    tags: ['v*']
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Login repod
        id: login
        run: |
          TOKEN=$(curl -sf -X POST \\
            --data-urlencode "username=\${{ secrets.REPOD_USERNAME }}" \\
            --data-urlencode "password=\${{ secrets.REPOD_PASSWORD }}" \\
            "\${{ secrets.REPOD_URL }}/api/v1/auth/token" | jq -r '.access_token')
          echo "token=$TOKEN" >> "$GITHUB_OUTPUT"
      - name: Upload .deb
        run: |
          for DEB in dist/*.deb; do
            curl -sf \\
              -H "Authorization: Bearer \${{ steps.login.outputs.token }}" \\
              -F "file=@$DEB" -F "distribution=jammy" \\
              "\${{ secrets.REPOD_URL }}/api/v1/upload"
          done`;

  const glSnippet = `# Dans votre .gitlab-ci.yml
variables:
  REPOD_DISTRIBUTION: "jammy"

.repod-auth: &repod-auth
  - |
    REPOD_TOKEN=$(curl -sf -X POST \\
      --data-urlencode "username=$REPOD_USERNAME" \\
      --data-urlencode "password=$REPOD_PASSWORD" \\
      "$REPOD_URL/api/v1/auth/token" | jq -r '.access_token')
    export REPOD_TOKEN

repod-upload:
  stage: deploy
  script:
    - *repod-auth
    - |
      for DEB in dist/*.deb; do
        curl -sf \\
          -H "Authorization: Bearer $REPOD_TOKEN" \\
          -F "file=@$DEB" -F "distribution=$REPOD_DISTRIBUTION" \\
          "$REPOD_URL/api/v1/upload"
      done
  rules:
    - if: $CI_COMMIT_TAG`;

  const shellSnippet = `#!/usr/bin/env bash
# repod-cli.sh — disponible dans examples/ci/repod-cli.sh
# Variables requises : REPOD_URL, REPOD_USERNAME, REPOD_PASSWORD

export REPOD_URL="${repodUrl}"
export REPOD_USERNAME="ci-bot"
export REPOD_PASSWORD="<mot-de-passe>"

# Login (stocke le token dans REPOD_TOKEN)
./repod-cli.sh login

# Upload d'un paquet
./repod-cli.sh upload monpaquet_1.0.0_amd64.deb jammy

# Vérifier les CVE (exit 2 si CVE critique)
./repod-cli.sh vulnerabilities jammy`;

  const webhookSnippet = `# Variable d'environnement à définir sur le backend
WEBHOOK_SECRET=<secret-partagé-avec-github>

# Endpoints disponibles :
# POST /webhooks/github   ← GitHub Security Advisory
# POST /webhooks/kev      ← CISA Known Exploited Vulnerabilities

# Configuration GitHub (Settings → Webhooks → Add webhook) :
# Payload URL : ${repodUrl}/webhooks/github
# Content-Type : application/json
# Secret : <même valeur que WEBHOOK_SECRET>
# Events : Security advisory`;

  const tabs = [
    { id: "github",  label: "GitHub Actions" },
    { id: "gitlab",  label: "GitLab CI" },
    { id: "shell",   label: "Shell / CLI" },
    { id: "webhook", label: "Webhooks entrants" },
  ];

  const snippets = {
    github:  ghUpload,
    gitlab:  glSnippet,
    shell:   shellSnippet,
    webhook: webhookSnippet,
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-3">
        <svg className="w-5 h-5 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round"
            d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
        <div>
          <h2 className="text-base font-semibold text-gray-900">Intégrations CI/CD</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Extraits prêts à l'emploi pour GitHub Actions, GitLab CI, scripts shell et webhooks entrants.
          </p>
        </div>
      </div>

      <div className="px-6 py-5 space-y-4">
        {/* Info endpoints */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
          {[
            ["POST", "/api/v1/auth/token",           "Authentification JWT"],
            ["POST", "/api/v1/upload",               "Publication d'un .deb"],
            ["GET",  "/api/v1/security/vulnerabilities", "Liste des CVE"],
            ["POST", "/webhooks/github",             "Advisory GitHub (HMAC)"],
            ["POST", "/webhooks/kev",                "CISA KEV (HMAC)"],
          ].map(([method, path, desc]) => (
            <div key={path} className="flex items-start gap-1.5 bg-gray-50 rounded-lg px-2.5 py-2">
              <span className={`shrink-0 font-mono font-bold text-xs px-1.5 py-0.5 rounded
                ${method === "GET" ? "bg-blue-100 text-blue-700" : "bg-green-100 text-green-700"}`}>
                {method}
              </span>
              <div>
                <p className="font-mono text-gray-700 text-xs leading-tight">{path}</p>
                <p className="text-gray-400 text-xs">{desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Onglets */}
        <div className="border-b border-gray-100">
          <div className="flex gap-1 overflow-x-auto pb-0">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`shrink-0 px-3 py-2 text-xs font-medium rounded-t-lg border-b-2 transition-colors ${
                  activeTab === t.id
                    ? "border-blue-500 text-blue-700 bg-blue-50"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-50"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <CopySnippet code={snippets[activeTab]} />

        <p className="text-xs text-gray-400">
          Exemples complets disponibles dans{" "}
          <span className="font-mono text-gray-600">backend/examples/ci/</span>
          {" "}(gitlab-repod.yml, github-*.yml, repod-cli.sh).
        </p>
      </div>
    </div>
  );
}

// ─── Section : Conteneurs ────────────────────────────────────────────────────

function ContainersSection() {
  const [activeTab, setActiveTab] = useState("apt");
  const REPO_URL     = getRepoUrl();
  const RPM_REPO_URL = getRpmRepoUrl();
  const API_URL      = getExternalApiUrl();

  const copy = (text) => {
    navigator.clipboard.writeText(text).then(
      () => toast.success("Copié"),
      () => toast.error("Impossible de copier")
    );
  };

  const CopyBlock = ({ code, label }) => (
    <div className="rounded-xl overflow-hidden border border-gray-200">
      {label && (
        <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
          <span className="text-xs text-gray-400 font-mono">{label}</span>
          <button onClick={() => copy(code)} className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition-colors">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
            </svg>
            Copier
          </button>
        </div>
      )}
      <pre className="bg-gray-900 text-green-400 text-xs font-mono px-5 py-4 overflow-x-auto whitespace-pre w-0 min-w-full">
        {code}
      </pre>
    </div>
  );

  const aptSnippet = `# docker-compose.yml — service utilisant le dépôt APT Repod
services:
  mon-service:
    build:
      context: .
      args:
        APT_REPO_URL: "${REPO_URL}"
        APT_DISTRO: "jammy"   # jammy | noble | focal | bookworm

# Dockerfile correspondant :
# FROM ubuntu:22.04
# ARG APT_REPO_URL
# ARG APT_DISTRO
# RUN apt-get update && apt-get install -y curl gnupg && \\
#     curl -fsSL \${APT_REPO_URL}/repos/depot.gpg | \\
#       gpg --dearmor -o /etc/apt/trusted.gpg.d/repod.gpg && \\
#     echo "deb [signed-by=/etc/apt/trusted.gpg.d/repod.gpg] \\
#       \${APT_REPO_URL}/repos \${APT_DISTRO} main" > \\
#       /etc/apt/sources.list.d/repod.list && \\
#     apt-get update && \\
#     apt-get install -y <votre-paquet>`;

  const rpmSnippet = `# docker-compose.yml — service utilisant le dépôt RPM Repod
services:
  mon-service:
    build:
      context: .
      args:
        RPM_REPO_URL: "${RPM_REPO_URL}"
        RPM_DISTRO: "almalinux9"  # almalinux8/9 | rocky8/9 | centos-stream9 | fedora

# Dockerfile correspondant :
# FROM almalinux:9
# ARG RPM_REPO_URL
# ARG RPM_DISTRO
# RUN cat > /etc/yum.repos.d/repod.repo << EOF
# [repod]
# name=Repod Private RPM Repository
# baseurl=\${RPM_REPO_URL}/\${RPM_DISTRO}/x86_64/
# enabled=1
# gpgcheck=0
# EOF
# RUN dnf clean all && dnf install -y <votre-paquet>`;

  const apkSnippet = `# docker-compose.yml — service utilisant le dépôt APK Alpine Repod
services:
  mon-service:
    build:
      context: .
      args:
        APK_REPO_URL: "${REPO_URL}"
        ALPINE_VERSION: "alpine3.21"  # alpine3.18 | alpine3.19 | alpine3.20 | alpine3.21

# Dockerfile correspondant :
# FROM alpine:3.21
# ARG APK_REPO_URL
# ARG ALPINE_VERSION
# RUN echo "\${APK_REPO_URL}/apk/\${ALPINE_VERSION}/main" >> /etc/apk/repositories \\
#  && apk update \\
#  && apk add --no-cache <votre-paquet>`;

  const multiSnippet = `# docker-compose.yml complet — variables d'environnement pour les 3 formats
version: "3.9"

x-repod-env: &repod-env
  APT_REPO_URL: "${REPO_URL}"
  RPM_REPO_URL: "${RPM_REPO_URL}"
  APK_REPO_URL: "${REPO_URL}"
  REPOD_API:    "${API_URL}"

services:
  # Conteneur Ubuntu/Debian (APT)
  app-ubuntu:
    image: ubuntu:22.04
    environment:
      <<: *repod-env
      APT_DISTRO: "jammy"
    command: |
      bash -c "
        apt-get update && apt-get install -y curl gnupg
        curl -fsSL $$APT_REPO_URL/repos/depot.gpg | \\
          gpg --dearmor -o /etc/apt/trusted.gpg.d/repod.gpg
        echo \"deb [signed-by=/etc/apt/trusted.gpg.d/repod.gpg] \\
          $$APT_REPO_URL/repos $$APT_DISTRO main\" > \\
          /etc/apt/sources.list.d/repod.list
        apt-get update
      "

  # Conteneur AlmaLinux/Rocky (RPM/DNF)
  app-almalinux:
    image: almalinux:9
    environment:
      <<: *repod-env
      RPM_DISTRO: "almalinux9"
    command: |
      bash -c "
        echo '[repod]
        name=Repod RPM
        baseurl=$$RPM_REPO_URL/$$RPM_DISTRO/x86_64/
        enabled=1
        gpgcheck=0' > /etc/yum.repos.d/repod.repo
        dnf clean all
      "

  # Conteneur Alpine Linux (APK)
  app-alpine:
    image: alpine:3.21
    environment:
      <<: *repod-env
      ALPINE_VERSION: "alpine3.21"
    command: |
      sh -c "
        echo $$APK_REPO_URL/apk/$$ALPINE_VERSION/main >> /etc/apk/repositories
        apk update
      "`;

  const tabs = [
    { id: "apt",   label: "APT (Ubuntu/Debian)" },
    { id: "rpm",   label: "RPM (RHEL/Fedora)" },
    { id: "apk",   label: "APK (Alpine)" },
    { id: "multi", label: "Multi-format" },
  ];

  const snippets = { apt: aptSnippet, rpm: rpmSnippet, apk: apkSnippet, multi: multiSnippet };

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-3">
        <svg className="w-5 h-5 text-gray-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 9h18M9 21V9"/>
        </svg>
        <div>
          <h2 className="text-base font-semibold text-gray-900">Conteneurs Docker</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Extraits docker-compose prêts à l'emploi pour connecter vos conteneurs au dépôt privé Repod.
          </p>
        </div>
      </div>

      <div className="px-6 py-5 space-y-4">
        {/* URLs actuelles */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
          {[
            { label: "APT Repo", url: REPO_URL, color: "blue" },
            { label: "RPM Repo", url: RPM_REPO_URL, color: "orange" },
            { label: "APK Repo", url: `${REPO_URL}/apk/`, color: "emerald" },
          ].map(({ label, url, color }) => (
            <div key={label} className={`flex items-start gap-1.5 bg-${color}-50 border border-${color}-100 rounded-lg px-3 py-2`}>
              <div>
                <p className={`font-semibold text-${color}-700 text-xs mb-0.5`}>{label}</p>
                <p className={`font-mono text-${color}-800 text-xs break-all`}>{url}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Onglets */}
        <div className="border-b border-gray-100">
          <div className="flex gap-1 overflow-x-auto pb-0">
            {tabs.map((t) => (
              <button key={t.id} onClick={() => setActiveTab(t.id)}
                className={`shrink-0 px-3 py-2 text-xs font-medium rounded-t-lg border-b-2 transition-colors ${
                  activeTab === t.id
                    ? "border-blue-500 text-blue-700 bg-blue-50"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-50"
                }`}>
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <CopyBlock code={snippets[activeTab]} label="docker-compose.yml / Dockerfile" />

        <p className="text-xs text-gray-400">
          Les URLs ci-dessus sont celles actuellement configurées dans votre instance Repod.
          Adaptez <code className="font-mono text-gray-600">APT_DISTRO</code>,{" "}
          <code className="font-mono text-gray-600">RPM_DISTRO</code> ou{" "}
          <code className="font-mono text-gray-600">ALPINE_VERSION</code> selon votre cible.
        </p>
      </div>
    </div>
  );
}

// ─── Section GPG ──────────────────────────────────────────────────────────────

function GpgSection() {
  const [gpg, setGpg]           = useState(null);
  const [loading, setLoading]   = useState(true);
  const [generating, setGen]    = useState(false);
  const [showPubKey, setShow]   = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getGpgInfo();
      setGpg(data);
    } catch {
      setGpg(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleGenerate = async () => {
    if (!window.confirm("Générer une nouvelle clé GPG 4096 bits ? L'ancienne clé sera conservée mais les clients devront mettre à jour leur trousseau.")) return;
    setGen(true);
    try {
      const r = await generateGpgKey();
      toast.success(r.message || "Clé GPG générée");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur génération GPG");
    } finally {
      setGen(false);
    }
  };

  const key = gpg?.keys?.[0];

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
        <div>
          <h2 className="text-base font-semibold text-gray-900">Clé GPG du dépôt</h2>
          <p className="text-xs text-gray-500 mt-0.5">Utilisée pour signer les packages et les fichiers Release</p>
        </div>
        <button onClick={handleGenerate} disabled={generating}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium border border-gray-200 rounded-lg hover:bg-gray-50 disabled:opacity-50 text-gray-600 transition-colors">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4"/>
          </svg>
          {generating ? "Génération…" : "Générer une nouvelle clé"}
        </button>
      </div>

      <div className="px-6 py-4">
        {loading ? (
          <p className="text-sm text-gray-400">Chargement…</p>
        ) : !key ? (
          <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
            <p className="text-sm font-semibold text-amber-800">Aucune clé GPG trouvée</p>
            <p className="text-xs text-amber-600 mt-0.5">Cliquez sur "Générer une nouvelle clé" pour initialiser le trousseau GPG du dépôt.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Key ID",      value: key.key_id || "—" },
                { label: "Algorithme",  value: `RSA ${key.algo || ""}` },
                { label: "UID",         value: key.uids?.[0] || "—" },
                { label: "Expire le",   value: key.expires || "Pas d'expiration" },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-50 rounded-lg px-3 py-2.5">
                  <p className="text-xs text-gray-500 mb-0.5">{label}</p>
                  <p className="text-sm font-mono text-gray-800 truncate">{value}</p>
                </div>
              ))}
            </div>

            {key.fingerprint && (
              <div className="bg-gray-50 rounded-lg px-3 py-2.5">
                <p className="text-xs text-gray-500 mb-0.5">Fingerprint</p>
                <p className="text-xs font-mono text-gray-700 break-all">{key.fingerprint}</p>
              </div>
            )}

            {gpg.public_key_armored && (
              <div>
                <button onClick={() => setShow(!showPubKey)}
                  className="text-xs text-blue-600 hover:underline font-medium">
                  {showPubKey ? "Masquer la clé publique" : "Afficher la clé publique (PEM)"}
                </button>
                {showPubKey && (
                  <div className="mt-2 relative">
                    <pre className="bg-gray-900 text-green-400 text-xs font-mono p-4 rounded-xl overflow-x-auto max-h-48 overflow-y-auto">
                      {gpg.public_key_armored}
                    </pre>
                    <button
                      onClick={() => { navigator.clipboard.writeText(gpg.public_key_armored); toast.success("Clé copiée"); }}
                      className="absolute top-2 right-2 px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded hover:bg-gray-600">
                      Copier
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
