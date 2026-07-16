import { useState, useEffect, useCallback } from "react";
import toast from "react-hot-toast";
import { listEmailTemplates, getEmailTemplate, updateEmailTemplate, resetEmailTemplate, previewEmailTemplate } from "../api";

const TEMPLATE_ICONS = {
  pending_review: "M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0z",
  security_decision: "M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z",
  escalation: "M3 3v1.5M3 21v-6m0 0l2.77-.693a9 9 0 016.208.682l.108.054a9 9 0 006.086.71l3.114-.732a48.524 48.524 0 01-.005-10.499l-3.11.732a9 9 0 01-6.085-.711l-.108-.054a9 9 0 00-6.208-.682L3 4.5M3 15V4.5",
  sla_overdue: "M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z",
  patch_available: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  itsm_resolved: "M16.5 6v.75m0 3v.75m0 3v.75m0 3V18m-9-5.25h5.25M7.5 15h3M3.375 5.25c-.621 0-1.125.504-1.125 1.125v3.026a2.999 2.999 0 010 5.198v3.026c0 .621.504 1.125 1.125 1.125h17.25c.621 0 1.125-.504 1.125-1.125v-3.026a2.999 2.999 0 010-5.198V6.375c0-.621-.504-1.125-1.125-1.125H3.375z",
  itsm_error: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z",
  scheduler_job_failed: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z",
  default: "M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75",
  base: "M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z",
};

export default function TemplatesPage() {
  const [templates, setTemplates]   = useState([]);
  const [selected, setSelected]     = useState(null);
  const [editing, setEditing]       = useState(null);
  const [subject, setSubject]       = useState("");
  const [body, setBody]             = useState("");
  const [preview, setPreview]       = useState("");
  const [saving, setSaving]         = useState(false);
  const [showPreview, setShowPreview] = useState(false);

  const load = useCallback(async () => {
    try {
      const list = await listEmailTemplates();
      setTemplates(list);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { load(); }, [load]);

  const selectTemplate = async (name) => {
    try {
      const tpl = await getEmailTemplate(name);
      setSelected(tpl);
      setEditing(name);
      setSubject(tpl.subject || "");
      setBody(tpl.body || "");
      setShowPreview(false);
      setPreview("");
    } catch {
      toast.error("Impossible de charger le template");
    }
  };

  const handlePreview = async () => {
    try {
      const html = await previewEmailTemplate(editing, body);
      setPreview(html);
      setShowPreview(true);
    } catch {
      toast.error("Erreur de rendu du preview");
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateEmailTemplate(editing, body, subject);
      toast.success("Template sauvegarde");
      load();
    } catch {
      toast.error("Erreur lors de la sauvegarde");
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm("Restaurer le template par defaut ? Les modifications seront perdues.")) return;
    try {
      const tpl = await resetEmailTemplate(editing);
      setBody(tpl.body);
      setSubject(tpl.subject || "");
      toast.success("Template restaure");
      load();
    } catch {
      toast.error("Erreur lors de la restauration");
    }
  };

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-slate-900">Templates email</h1>
        <p className="text-sm text-slate-500 mt-1">
          Personnalisez les emails envoyes par RepoD. Utilisez la syntaxe Jinja2 pour les variables dynamiques.
        </p>
      </div>

      <div className="flex gap-6">
        {/* Left: template list */}
        <div className="w-72 shrink-0">
          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            {templates.filter(t => t.name !== "base").map((t) => (
              <button
                key={t.name}
                onClick={() => selectTemplate(t.name)}
                className={`w-full text-left px-4 py-3 flex items-center gap-3 border-b border-slate-100 last:border-0 transition-colors ${
                  editing === t.name ? "bg-blue-50" : "hover:bg-slate-50"
                }`}
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                  editing === t.name ? "bg-blue-100" : "bg-slate-100"
                }`}>
                  <svg className={`w-4 h-4 ${editing === t.name ? "text-blue-600" : "text-slate-400"}`}
                       fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                    <path strokeLinecap="round" strokeLinejoin="round"
                          d={TEMPLATE_ICONS[t.name] || TEMPLATE_ICONS.default} />
                  </svg>
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-slate-800 truncate">
                    {t.name.replace(/_/g, " ")}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">{t.description?.slice(0, 50)}</div>
                </div>
                {t.is_customized && (
                  <span className="ml-auto shrink-0 w-2 h-2 rounded-full bg-blue-500" title="Personnalise" />
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Right: editor + preview */}
        <div className="flex-1 min-w-0">
          {!editing ? (
            <div className="bg-white rounded-xl border border-slate-200 p-12 text-center">
              <svg className="w-12 h-12 mx-auto text-slate-300 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
              </svg>
              <p className="text-slate-500 text-sm">Selectionnez un template pour le modifier.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Header */}
              <div className="bg-white rounded-xl border border-slate-200 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h2 className="text-base font-semibold text-slate-900">
                      {editing.replace(/_/g, " ")}
                    </h2>
                    <p className="text-xs text-slate-400 mt-0.5">{selected?.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button onClick={handlePreview}
                      className="px-3 py-1.5 text-xs font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors">
                      Apercu
                    </button>
                    <button onClick={handleReset}
                      className="px-3 py-1.5 text-xs font-medium text-amber-600 bg-amber-50 hover:bg-amber-100 rounded-lg transition-colors">
                      Reinitialiser
                    </button>
                    <button onClick={handleSave} disabled={saving}
                      className="px-4 py-1.5 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg transition-colors disabled:opacity-50">
                      {saving ? "..." : "Sauvegarder"}
                    </button>
                  </div>
                </div>

                {/* Variables */}
                {selected?.variables?.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    <span className="text-[10px] text-slate-400 font-medium mr-1 self-center">Variables :</span>
                    {selected.variables.map((v) => (
                      <span key={v}
                        className="text-[11px] font-mono px-2 py-0.5 bg-slate-100 text-slate-600 rounded cursor-pointer hover:bg-blue-100 hover:text-blue-700 transition-colors"
                        onClick={() => {
                          navigator.clipboard.writeText(`{{ ${v} }}`);
                          toast.success(`{{ ${v} }} copie`);
                        }}
                        title={`Cliquer pour copier {{ ${v} }}`}
                      >
                        {"{{ "}{v}{" }}"}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Subject */}
              <div className="bg-white rounded-xl border border-slate-200 p-4">
                <label className="block text-xs font-medium text-slate-500 mb-1.5">Objet de l'email</label>
                <input
                  type="text"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="[RepoD] ..."
                />
              </div>

              {/* Body editor */}
              <div className="bg-white rounded-xl border border-slate-200 p-4">
                <label className="block text-xs font-medium text-slate-500 mb-1.5">Corps du template (HTML + Jinja2)</label>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 resize-y"
                  rows={16}
                  spellCheck={false}
                />
              </div>

              {/* Preview */}
              {showPreview && (
                <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2 bg-slate-50 border-b border-slate-200">
                    <span className="text-xs font-medium text-slate-500">Apercu (donnees fictives)</span>
                    <button onClick={() => setShowPreview(false)}
                      className="text-xs text-slate-400 hover:text-slate-600">
                      Fermer
                    </button>
                  </div>
                  <iframe
                    srcDoc={preview}
                    title="Email preview"
                    className="w-full border-0"
                    style={{ height: "500px" }}
                    sandbox=""
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
