import { useCallback, useEffect, useRef, useState } from "react";
import { useDropzone } from "react-dropzone";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { getDistributions } from "../api";

const API_URL = import.meta.env.REACT_APP_API_URL || "";
const API_V1  = `${API_URL}/api/v1`;

// ─── SVG Icons ────────────────────────────────────────────────────────────────

function IconInbox({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859m-19.5.338V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H6.911a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661z"/></svg>;
}
function IconShield({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/></svg>;
}
function IconChecksum({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33"/></svg>;
}
function IconKey({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/></svg>;
}
function IconVirus({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>;
}
function IconCVE({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M11.42 15.17L17.25 21A2.652 2.652 0 0021 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 11-3.586-3.586l6.837-5.63m5.108-.233c.55-.164 1.163-.188 1.743-.14a4.5 4.5 0 004.486-6.336l-3.276 3.277a3.004 3.004 0 01-2.25-2.25l3.276-3.276a4.5 4.5 0 00-6.336 4.486c.091 1.076-.071 2.264-.904 2.95l-.102.085m-1.745 1.437L5.909 7.5H4.5L2.25 3.75l1.5-1.5L7.5 4.5v1.409l4.26 4.26m-1.745 1.437l1.745-1.437m6.615 8.206L15.75 15.75M4.867 19.125h.008v.008h-.008v-.008z"/></svg>;
}
function IconLink({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244"/></svg>;
}
function IconPackage({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z"/></svg>;
}
function IconTag({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M9.568 3H5.25A2.25 2.25 0 003 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581c.699.699 1.78.872 2.607.33a18.095 18.095 0 005.223-5.223c.542-.827.369-1.908-.33-2.607L11.16 3.66A2.25 2.25 0 009.568 3z"/><path strokeLinecap="round" strokeLinejoin="round" d="M6 6h.008v.008H6V6z"/></svg>;
}
function IconIndex({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"/></svg>;
}
function IconServer({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}><path strokeLinecap="round" strokeLinejoin="round" d="M21.75 17.25v.75a2.25 2.25 0 01-2.25 2.25H4.5a2.25 2.25 0 01-2.25-2.25v-.75m19.5 0a2.25 2.25 0 00-2.25-2.25H4.5a2.25 2.25 0 00-2.25 2.25m19.5 0v-13.5a2.25 2.25 0 00-2.25-2.25H4.5A2.25 2.25 0 002.25 3.75v13.5"/></svg>;
}
function IconArrowRight({ className = "w-4 h-4" }) {
  return <svg className={className} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/></svg>;
}

const STEP_META = {
  reception:        { Icon: IconInbox,    label: "Réception du fichier" },
  validation:       { Icon: IconShield,   label: "Pipeline de validation" },
  sub_format:       { Icon: IconPackage,  label: "Format du paquet" },
  sub_checksum:     { Icon: IconChecksum, label: "Intégrité SHA-256" },
  sub_gpg:          { Icon: IconKey,      label: "Signature GPG" },
  sub_clamav:       { Icon: IconVirus,    label: "Antivirus ClamAV" },
  sub_cve:          { Icon: IconCVE,      label: "Analyse CVE" },
  sub_dependencies: { Icon: IconLink,     label: "Dépendances" },
  auto_deps:        { Icon: IconLink,     label: "Résolution des dépendances manquantes" },
  pool:             { Icon: IconPackage,  label: "Déplacement vers le pool" },
  manifest:         { Icon: IconTag,      label: "Génération du manifest" },
  index:            { Icon: IconIndex,    label: "Mise à jour de l'index" },
  reprepro:         { Icon: IconServer,   label: "Ajout au dépôt (reprepro)" },
  createrepo:       { Icon: IconServer,   label: "Ajout au dépôt (createrepo_c)" },
  apkindex:         { Icon: IconServer,   label: "Mise à jour APKINDEX (Alpine)" },
};

// ─── Step status icon ─────────────────────────────────────────────────────────

function StepStatusIcon({ status }) {
  if (status === "running") return <div className="w-5 h-5 rounded-full border-2 border-blue-500 border-t-transparent animate-spin flex-shrink-0" />;
  if (status === "done")    return <svg className="w-5 h-5 text-emerald-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5"/></svg>;
  if (status === "error")   return <svg className="w-5 h-5 text-red-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>;
  if (status === "warn")    return <svg className="w-5 h-5 text-amber-500 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 3.75h.008v.008H12v-.008zm9.002-7.5c0-1.036-.84-1.875-1.875-1.875H4.873C3.838 7.875 3 8.713 3 9.75L12 22.5l9-12.75z"/></svg>;
  return <div className="w-5 h-5 rounded-full border-2 border-gray-200 flex-shrink-0" />;
}

function WorkflowStep({ step }) {
  const meta = STEP_META[step.name] || {};
  const isSub = step.name?.startsWith("sub_");
  const StepSvgIcon = meta.Icon;

  const bgClass =
    step.status === "done"    ? "bg-emerald-50 border-emerald-200" :
    step.status === "running" ? "bg-blue-50 border-blue-200" :
    step.status === "error"   ? "bg-red-50 border-red-200" :
    step.status === "warn"    ? "bg-amber-50 border-amber-200" :
    "bg-gray-50 border-gray-200";

  const labelClass =
    step.status === "done"    ? "text-emerald-800" :
    step.status === "running" ? "text-blue-800" :
    step.status === "error"   ? "text-red-800" :
    step.status === "warn"    ? "text-amber-800" :
    "text-gray-400";

  const iconColor =
    step.status === "done"    ? "text-emerald-600" :
    step.status === "running" ? "text-blue-600" :
    step.status === "error"   ? "text-red-500" :
    step.status === "warn"    ? "text-amber-500" :
    "text-gray-300";

  return (
    <div className={`flex items-start gap-3 px-3 py-2.5 rounded-lg border transition-all ${bgClass} ${isSub ? "ml-7" : ""}`}>
      <StepStatusIcon status={step.status} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          {StepSvgIcon && <StepSvgIcon className={`w-3.5 h-3.5 flex-shrink-0 ${iconColor}`} />}
          <span className={`text-sm font-medium ${labelClass}`}>
            {step.label || meta.label || step.name}
          </span>
        </div>
        {step.message && <p className="text-xs text-gray-500 mt-0.5 truncate">{step.message}</p>}
        {step.detail  && <p className="text-xs text-gray-400 mt-0.5 font-mono break-all leading-relaxed">{step.detail}</p>}
      </div>
    </div>
  );
}

function ResultBanner({ result }) {
  const navigate = useNavigate();
  const isAccepted  = result.status === "accepted";
  const isPending   = result.status === "pending_review";
  const isDuplicate = result.status === "already_imported";
  const isConflict  = result.status === "conflict";
  const isMismatch  = result.status === "format_mismatch";
  // Publié dans le dépôt (accepted) ou déjà présent (already_imported) → visible dans Paquets.
  // En attente de révision RSSI → pas encore publié, visible uniquement dans Décisions CVE.
  const isPublished = isAccepted || isDuplicate;

  const bg    = isAccepted  ? "bg-emerald-50 border-emerald-200"
              : isPending   ? "bg-amber-50 border-amber-200"
              : isDuplicate ? "bg-sky-50 border-sky-200"
              : isConflict  ? "bg-orange-50 border-orange-300"
              : isMismatch  ? "bg-violet-50 border-violet-200"
              :               "bg-red-50 border-red-200";

  const title = isAccepted  ? "Paquet accepté"
              : isPending   ? "En attente de révision RSSI"
              : isDuplicate ? "Doublon — déjà importé"
              : isConflict  ? "Conflit de doublon — SHA256 différent"
              : isMismatch  ? "Format incompatible avec la distribution"
              :               "Paquet rejeté";

  const color = isAccepted  ? "text-emerald-800"
              : isPending   ? "text-amber-800"
              : isDuplicate ? "text-sky-800"
              : isConflict  ? "text-orange-800"
              : isMismatch  ? "text-violet-800"
              :               "text-red-800";

  const dot   = isAccepted  ? "bg-emerald-500"
              : isPending   ? "bg-amber-400"
              : isDuplicate ? "bg-sky-400"
              : isConflict  ? "bg-orange-500"
              : isMismatch  ? "bg-violet-500"
              :               "bg-red-500";

  return (
    <div className={`rounded-xl border p-4 mt-3 space-y-3 ${bg}`}>
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dot}`} />
          <p className={`font-semibold text-sm ${color}`}>{title}</p>
        </div>
        {result.package && (
          <span className="font-mono text-sm text-gray-600 shrink-0">{result.package} {result.version}</span>
        )}
      </div>
      <p className="text-sm text-gray-600">{result.message}</p>
      {result.sha256 && (
        <div className="bg-white/70 rounded-lg px-3 py-2 border border-white">
          <span className="text-xs font-semibold text-gray-500 mr-1.5">SHA-256</span>
          <span className="text-xs font-mono text-gray-700 break-all">{result.sha256}</span>
        </div>
      )}
      {isConflict && result.existing_sha256 && (
        <div className="space-y-1">
          <div className="bg-white/70 rounded-lg px-3 py-2 border border-white">
            <span className="text-xs font-semibold text-gray-500 mr-1.5">SHA-256 entrant</span>
            <span className="text-xs font-mono text-orange-700 break-all">{result.incoming_sha256}</span>
          </div>
          <div className="bg-white/70 rounded-lg px-3 py-2 border border-white">
            <span className="text-xs font-semibold text-gray-500 mr-1.5">SHA-256 existant</span>
            <span className="text-xs font-mono text-gray-700 break-all">{result.existing_sha256}</span>
          </div>
          <p className="text-xs text-orange-700 font-medium">Incrémentez la version ou vérifiez l'intégrité du fichier source.</p>
        </div>
      )}
      {result.distribution && (
        <p className="text-xs text-gray-500">Distribution : <strong className="font-medium">{result.distribution}</strong></p>
      )}
      {(isPublished || isPending) && (
        <button
          type="button"
          onClick={() => navigate(isPublished ? "/packages" : "/security")}
          className={`inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-2 border transition-colors
            ${isPublished
              ? "bg-white text-emerald-700 border-emerald-200 hover:bg-emerald-50"
              : "bg-white text-amber-700 border-amber-200 hover:bg-amber-50"}`}
        >
          {isPublished ? "Voir dans Paquets" : "Voir dans Décisions CVE"}
          <IconArrowRight className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function UploadForm() {
  const [distributions, setDistributions] = useState([]);
  const [distribution, setDistribution]   = useState("jammy");
  const [uploading, setUploading]         = useState(false);
  const [steps, setSteps]                 = useState([]);
  const [result, setResult]               = useState(null);
  const [fileName, setFileName]           = useState(null);
  const readerRef = useRef(null);

  // Charger la liste des distributions depuis l'API
  useEffect(() => {
    getDistributions()
      .then((data) => {
        const dists = (data.distributions || []).map((d) => ({
          codename: d.codename,
          name:     d.name || d.codename,
          format:   d.format || "deb",
        }));
        setDistributions(dists);
        // Valeur initiale : jammy si présent, sinon premier disponible
        if (dists.length > 0 && !dists.find((d) => d.codename === "jammy")) {
          setDistribution(dists[0].codename);
        }
      })
      .catch(() => {
        // Fallback statique si l'API échoue
        setDistributions([
          { codename: "jammy",    name: "Ubuntu 22.04 LTS (Jammy)", format: "deb" },
          { codename: "noble",    name: "Ubuntu 24.04 LTS (Noble)", format: "deb" },
          { codename: "focal",    name: "Ubuntu 20.04 LTS (Focal)", format: "deb" },
          { codename: "bookworm", name: "Debian 12 (Bookworm)",     format: "deb" },
        ]);
      });
  }, []);

  const debDists = distributions.filter((d) => d.format === "deb");
  const rpmDists = distributions.filter((d) => d.format === "rpm");
  const apkDists = distributions.filter((d) => d.format === "apk");
  const currentFmt = distributions.find((d) => d.codename === distribution)?.format || "deb";

  const addOrUpdateStep = (step) => setSteps((prev) => {
    const idx = prev.findIndex((s) => s.name === step.name);
    if (idx >= 0) { const next = [...prev]; next[idx] = { ...next[idx], ...step }; return next; }
    return [...prev, step];
  });

  // Retourne l'extension attendue pour une distribution donnée
  const expectedExtForDist = (codename) => {
    const c = (codename || "").toLowerCase();
    if (c.startsWith("alpine")) return ".apk";
    if (["almalinux","rocky","centos","oraclelinux","fedora","opensuse"].some(p => c.startsWith(p))) return ".rpm";
    return ".deb";
  };

  const onDrop = useCallback(async (acceptedFiles) => {
    const file = acceptedFiles[0];
    if (!file) return;
    const ext = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (![".deb", ".rpm", ".apk"].includes(ext)) {
      toast.error("Seuls les fichiers .deb, .rpm et .apk sont acceptés");
      return;
    }

    // Pré-contrôle client : format du fichier vs distribution sélectionnée
    const expectedExt = expectedExtForDist(distribution);
    if (ext !== expectedExt) {
      const fmtLabels = { ".deb": "APT / Debian·Ubuntu", ".rpm": "RPM / RHEL·Fedora", ".apk": "APK / Alpine Linux" };
      setFileName(file.name);
      setSteps([]);
      setResult({
        status: "format_mismatch",
        filename: file.name,
        message: `Le fichier '${file.name}' est un paquet ${ext.toUpperCase().slice(1)} mais la distribution '${distribution}' attend des paquets ${fmtLabels[expectedExt]} (${expectedExt.toUpperCase().slice(1)}). Sélectionnez la bonne distribution ou choisissez le bon type de fichier.`,
        expected_ext: expectedExt,
        actual_ext: ext,
      });
      toast.error(`Format incompatible : fichier ${ext.toUpperCase().slice(1)} avec une distribution ${fmtLabels[expectedExt]}`);
      return;
    }

    setUploading(true); setSteps([]); setResult(null); setFileName(file.name);

    const token = localStorage.getItem("token");
    const formData = new FormData();
    formData.append("file", file);
    formData.append("distribution", distribution);

    try {
      const resp = await fetch(`${API_V1}/upload/stream`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: "Erreur serveur" }));
        toast.error(err.detail || "Erreur lors de l'upload");
        setUploading(false);
        return;
      }

      const reader = resp.body.getReader();
      readerRef.current = reader;
      const decoder = new TextDecoder();
      let buffer = "";

      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop();
          for (const part of parts) {
            const lines = part.split("\n");
            let evType = "message", dataStr = "";
            for (const line of lines) {
              if (line.startsWith("event: ")) evType = line.slice(7).trim();
              if (line.startsWith("data: "))  dataStr = line.slice(6).trim();
            }
            if (dataStr === "done|DONE") { setUploading(false); break; }
            try {
              const data = JSON.parse(dataStr);
              if (evType === "step") {
                addOrUpdateStep(data);
              } else if (evType === "result") {
                setResult(data);
                if (data.status === "accepted")           toast.success(`${data.package} ${data.version} ajouté au dépôt`);
                else if (data.status === "pending_review")  toast(`${data.package} — en attente RSSI`, { icon: "⏳" });
                else if (data.status === "already_imported") toast(`Doublon ignoré — déjà présent dans le dépôt`, { icon: "ℹ️" });
                else if (data.status === "conflict")        toast.error("Conflit : même paquet, SHA256 différent — vérifiez la version");
                else                                        toast.error("Paquet rejeté");
              }
            } catch (_) {}
          }
        }
      } catch (streamErr) {
        toast.error(`Erreur de flux : ${streamErr.message}`);
      }
    } catch (e) {
      toast.error(`Erreur réseau : ${e.message}`);
    } finally {
      setUploading(false);
    }
  }, [distribution]);

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    accept: { "application/octet-stream": [".deb", ".rpm", ".apk"] },
    multiple: false,
    disabled: uploading,
  });

  return (
    <>
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Déposer un paquet</h1>
        <p className="text-sm text-gray-500 mt-0.5">Le paquet (.deb, .rpm ou .apk) sera validé automatiquement avant d'être ajouté au dépôt</p>
      </div>

      {/* Distribution */}
      <div className="bg-white border border-gray-200 rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between">
          <label className="block text-sm font-medium text-gray-700">Distribution cible</label>
          <span className={`text-xs font-semibold uppercase tracking-wider ${
            currentFmt === "deb" ? "text-blue-500" : currentFmt === "rpm" ? "text-orange-500" : "text-emerald-600"
          }`}>
            {currentFmt === "deb" ? "APT" : currentFmt === "rpm" ? "RPM" : "APK"}
          </span>
        </div>
        <select
          value={distribution}
          onChange={(e) => setDistribution(e.target.value)}
          disabled={uploading}
          className="w-full px-3 py-2 rounded-lg text-sm font-medium border border-gray-200 text-gray-700 bg-white cursor-pointer disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-blue-500/40 focus:border-blue-500"
        >
          {debDists.length > 0 && (
            <optgroup label="APT — Debian / Ubuntu">
              {debDists.map((d) => <option key={d.codename} value={d.codename}>{d.name}</option>)}
            </optgroup>
          )}
          {rpmDists.length > 0 && (
            <optgroup label="RPM — RHEL / Fedora / openSUSE">
              {rpmDists.map((d) => <option key={d.codename} value={d.codename}>{d.name}</option>)}
            </optgroup>
          )}
          {apkDists.length > 0 && (
            <optgroup label="APK — Alpine Linux">
              {apkDists.map((d) => <option key={d.codename} value={d.codename}>{d.name}</option>)}
            </optgroup>
          )}
        </select>
      </div>

      {/* Drop zone */}
      {steps.length === 0 && (
        <div {...getRootProps()}
          className={`border-2 border-dashed rounded-xl p-14 text-center cursor-pointer transition-all
            ${uploading ? "opacity-50 cursor-not-allowed" : ""}
            ${isDragReject ? "border-red-400 bg-red-50" : ""}
            ${isDragActive && !isDragReject ? "border-blue-500 bg-blue-50" : ""}
            ${!isDragActive && !isDragReject ? "border-gray-300 hover:border-blue-400 hover:bg-gray-50 bg-white" : ""}`}>
          <input {...getInputProps()} />
          <div className="flex flex-col items-center gap-3">
            {isDragReject ? (
              <><svg className="w-10 h-10 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12"/></svg><p className="text-sm text-red-500 font-medium">Fichier non supporté</p></>
            ) : isDragActive ? (
              <><svg className="w-10 h-10 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg><p className="text-sm text-blue-600 font-medium">Déposez le fichier ici</p></>
            ) : (
              <><svg className="w-10 h-10 text-gray-300" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
              <div>
                <p className="text-sm font-medium text-gray-700">
                  Glissez-déposez un fichier{" "}
                  <span className="text-blue-600">.deb</span>
                  {", "}
                  <span className="text-orange-600">.rpm</span>
                  {" "}ou{" "}
                  <span className="text-emerald-600">.apk</span>
                </p>
                <p className="text-xs text-gray-400 mt-1">ou cliquez pour sélectionner</p>
              </div></>
            )}
          </div>
        </div>
      )}

      {/* Workflow */}
      {steps.length > 0 && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <div className="px-4 py-3.5 border-b border-gray-100 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {uploading
                ? <div className="w-3.5 h-3.5 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
                : <div className={`w-3.5 h-3.5 rounded-full ${
                    result?.status === "accepted"         ? "bg-emerald-500" :
                    result?.status === "already_imported" ? "bg-sky-400" :
                    result?.status === "conflict"         ? "bg-orange-500" :
                    result?.status === "format_mismatch"  ? "bg-violet-500" :
                    result?.status === "rejected" || result?.status === "error" ? "bg-red-500" :
                    "bg-amber-400"
                  }`} />}
              <div>
                <p className="text-sm font-semibold text-gray-800">{uploading ? "Pipeline en cours…" : "Pipeline terminé"}</p>
                {fileName && <p className="text-xs text-gray-400 font-mono mt-0.5">{fileName}</p>}
              </div>
            </div>
            {!uploading && (
              <button onClick={() => { setSteps([]); setResult(null); setFileName(null); }}
                className="text-xs text-gray-400 hover:text-gray-600 border border-gray-200 rounded-lg px-3 py-1.5 transition-colors">
                Nouvel upload
              </button>
            )}
          </div>
          <div className="p-3 space-y-1.5">
            {steps.map((step, i) => <WorkflowStep key={step.name || i} step={step} />)}
          </div>
          {uploading && steps.some((s) => s.name === "auto_deps") && (
            <div className="mx-3 mb-3 flex items-center gap-2.5 px-3 py-2.5 bg-blue-50 border border-blue-200 rounded-lg">
              <div className="w-3.5 h-3.5 rounded-full border-2 border-blue-500 border-t-transparent animate-spin flex-shrink-0" />
              <p className="text-xs text-blue-700">
                <span className="font-semibold">Résolution des dépendances en cours</span> — ne quittez pas cette page, le traitement peut prendre un moment (synchronisation de l'index si nécessaire).
              </p>
            </div>
          )}
          {result && <div className="px-3 pb-3"><ResultBanner result={result} /></div>}
        </div>
      )}
    </div>

    {/* Pipeline de sécurité */}
    <div className="bg-white border border-gray-200 rounded-xl p-6 mt-6">
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
  </>
  );
}
