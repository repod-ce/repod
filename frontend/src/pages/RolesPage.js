import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import { listRoles, createRole, updateRole, deleteRole, setRolePermissions } from "../api";
import toast from "react-hot-toast";

const COLOR_OPTIONS = [
  { value: "blue",   label: "Bleu",   hex: "#3b82f6" },
  { value: "green",  label: "Vert",   hex: "#22c55e" },
  { value: "red",    label: "Rouge",  hex: "#ef4444" },
  { value: "purple", label: "Violet", hex: "#a855f7" },
  { value: "yellow", label: "Jaune",  hex: "#eab308" },
  { value: "orange", label: "Orange", hex: "#f97316" },
  { value: "teal",   label: "Teal",   hex: "#14b8a6" },
  { value: "indigo", label: "Indigo", hex: "#6366f1" },
  { value: "pink",   label: "Rose",   hex: "#ec4899" },
  { value: "gray",   label: "Gris",   hex: "#6b7280" },
];

const colorHex = (color) =>
  COLOR_OPTIONS.find((c) => c.value === color)?.hex ?? "#6b7280";

function ColorDot({ color, size = 10 }) {
  return (
    <span
      className="inline-block rounded-full flex-shrink-0"
      style={{ width: size, height: size, backgroundColor: colorHex(color) }}
    />
  );
}

// ── Modal création/édition de rôle ────────────────────────────────────────────
function RoleModal({ role, permCategories, permLabels, onClose, onSaved }) {
  const isEdit = !!role;
  const [name, setName]               = useState(role?.name || "");
  const [label, setLabel]             = useState(role?.label || "");
  const [description, setDescription] = useState(role?.description || "");
  const [color, setColor]             = useState(role?.color || "gray");
  const [perms, setPerms]             = useState(new Set(role?.permissions || []));
  const [saving, setSaving]           = useState(false);

  const togglePerm = (p) => setPerms((prev) => {
    const next = new Set(prev);
    next.has(p) ? next.delete(p) : next.add(p);
    return next;
  });

  const toggleAll = (catPerms, check) => setPerms((prev) => {
    const next = new Set(prev);
    catPerms.forEach((p) => check ? next.add(p) : next.delete(p));
    return next;
  });

  const handleSave = async () => {
    if (!name.trim()) { toast.error("L'identifiant est obligatoire"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await updateRole(role.id, { label: label.trim() || name.trim(), description, color });
        await setRolePermissions(role.id, [...perms]);
        toast.success("Rôle mis à jour");
      } else {
        await createRole({ name: name.trim(), label: label.trim() || name.trim(), description, color, permissions: [...perms] });
        toast.success("Rôle créé");
      }
      onSaved();
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la sauvegarde");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col max-h-[90vh]" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100 shrink-0">
          <h2 className="text-base font-semibold text-gray-900">
            {isEdit ? `Modifier "${role.label}"` : "Nouveau rôle"}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-gray-500 mb-1.5">
                Identifiant technique <span className="text-red-500">*</span>
              </label>
              <input
                className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-50 disabled:text-gray-400"
                value={name} onChange={(e) => setName(e.target.value)}
                disabled={isEdit}
                placeholder="ex : analyste-secu"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-500 mb-1.5">Label affiché</label>
              <input
                className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={label} onChange={(e) => setLabel(e.target.value)}
                placeholder="ex : Analyste Sécurité"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Description</label>
            <textarea
              className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
              rows={2} value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="Périmètre et responsabilités de ce rôle"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-2">Couleur</label>
            <div className="flex flex-wrap gap-2.5">
              {COLOR_OPTIONS.map((c) => (
                <button key={c.value} title={c.label}
                  onClick={() => setColor(c.value)}
                  className={`w-6 h-6 rounded-full transition-all ${
                    color === c.value ? "ring-2 ring-offset-2 ring-gray-400 scale-110" : "opacity-60 hover:opacity-100"
                  }`}
                  style={{ backgroundColor: c.hex }}
                />
              ))}
            </div>
          </div>

          {/* Matrice des permissions */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="text-xs font-semibold text-gray-500">
                Permissions
              </label>
              <span className="text-xs text-gray-400 tabular-nums">
                {perms.size} sélectionnée{perms.size !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-2">
              {Object.entries(permCategories || {}).map(([cat, catPerms]) => {
                const allChecked = catPerms.every((p) => perms.has(p));
                const someChecked = catPerms.some((p) => perms.has(p));
                return (
                  <div key={cat} className="border border-gray-200 rounded-xl overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-200">
                      <p className="text-xs font-semibold text-gray-600 uppercase tracking-wider">{cat}</p>
                      <button
                        onClick={() => toggleAll(catPerms, !allChecked)}
                        className={`text-[11px] font-medium transition-colors ${
                          allChecked ? "text-blue-600 hover:text-blue-800" : "text-gray-400 hover:text-gray-600"
                        }`}>
                        {allChecked ? "Tout désélectionner" : someChecked ? "Sélectionner tout" : "Sélectionner tout"}
                      </button>
                    </div>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 px-4 py-3">
                      {catPerms.map((perm) => (
                        <label key={perm} className="flex items-center gap-2.5 py-1 cursor-pointer group">
                          <input
                            type="checkbox"
                            checked={perms.has(perm)}
                            onChange={() => togglePerm(perm)}
                            className="w-3.5 h-3.5 rounded accent-blue-600"
                          />
                          <span className="text-xs text-gray-600 group-hover:text-gray-900 transition-colors">
                            {permLabels?.[perm] || perm}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        <div className="px-6 pb-5 pt-4 flex gap-3 border-t border-gray-100 shrink-0">
          <button onClick={onClose}
            className="flex-1 py-2 text-sm text-gray-500 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-colors disabled:opacity-50">
            {saving ? "Sauvegarde…" : isEdit ? "Mettre à jour" : "Créer"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Ligne de rôle ─────────────────────────────────────────────────────────────
function RoleRow({ role, permLabels, isAdmin, onEdit, onDelete, canDelete }) {
  const [expanded, setExpanded] = useState(false);
  const perms = role.permissions || [];

  return (
    <tr className="hover:bg-gray-50/60 transition-colors group">
      {/* Nom + badge */}
      <td className="px-6 py-3">
        <div className="flex items-center gap-2.5">
          <ColorDot color={role.color} />
          <span className="font-medium text-gray-800 text-sm">{role.label}</span>
          {role.is_builtin && (
            <span className="text-[10px] font-semibold text-gray-400 bg-gray-100 border border-gray-200 px-1.5 py-0.5 rounded uppercase tracking-wider">
              système
            </span>
          )}
        </div>
      </td>
      {/* Description */}
      <td className="px-4 py-3 text-xs text-gray-500 max-w-xs">
        <p className="line-clamp-2">{role.description || <span className="text-gray-300">—</span>}</p>
      </td>
      {/* Permissions */}
      <td className="px-4 py-3">
        <span className="text-xs text-gray-500 tabular-nums">
          {perms.length} permission{perms.length !== 1 ? "s" : ""}
        </span>
      </td>
      {/* Actions */}
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-xs text-gray-500 hover:text-gray-700 transition-colors">
            {expanded ? "Masquer" : "Détails"}
          </button>
          {isAdmin && (
            <>
              <span className="text-gray-200">·</span>
              <button onClick={onEdit}
                className="text-xs text-blue-600 hover:text-blue-700 font-medium transition-colors">
                Éditer
              </button>
              {canDelete && (
                <>
                  <span className="text-gray-200">·</span>
                  <button onClick={onDelete}
                    className="text-xs text-red-400 hover:text-red-600 transition-colors">
                    Supprimer
                  </button>
                </>
              )}
            </>
          )}
        </div>
      </td>
    </tr>
  );
}

// ── Ligne étendue (permissions) ───────────────────────────────────────────────
function RolePermRow({ role, permLabels }) {
  const [expanded, setExpanded] = useState(false);
  const perms = (role.permissions || []).sort();

  // On track l'expansion depuis RoleRow — on a besoin d'une solution partagée.
  // Simplement : on exporte le state depuis RoleRow via un contexte local ou
  // on ré-implémente en un seul composant avec expandable <tr> pair.
  if (perms.length === 0) return null;
  return (
    <tr className="bg-gray-50/40">
      <td colSpan={4} className="px-6 pb-3 pt-0">
        <div className="flex flex-wrap gap-1.5">
          {perms.map((p) => (
            <span key={p} className="text-[11px] text-gray-600 bg-white border border-gray-200 px-2 py-0.5 rounded-full">
              {permLabels?.[p] || p}
            </span>
          ))}
        </div>
      </td>
    </tr>
  );
}

// ── Composant ligne complet avec expand inline ────────────────────────────────
function RoleRowExpandable({ role, permLabels, isAdmin, onEdit, onDelete, canDelete }) {
  const [expanded, setExpanded] = useState(false);
  const perms = (role.permissions || []).slice().sort();

  return (
    <>
      <tr className="hover:bg-gray-50/60 transition-colors border-b border-gray-50">
        <td className="px-6 py-3">
          <div className="flex items-center gap-2.5">
            <ColorDot color={role.color} />
            <span className="font-medium text-gray-800 text-sm">{role.label}</span>
            {role.is_builtin && (
              <span className="text-[10px] font-semibold text-gray-400 bg-gray-100 border border-gray-200 px-1.5 py-0.5 rounded uppercase tracking-wider">
                système
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-3 text-xs text-gray-500 max-w-xs">
          <p className="line-clamp-2">{role.description || <span className="text-gray-300 italic">—</span>}</p>
        </td>
        <td className="px-4 py-3">
          <span className="text-xs text-gray-500 tabular-nums">
            {perms.length} permission{perms.length !== 1 ? "s" : ""}
          </span>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {perms.length > 0 && (
              <button onClick={() => setExpanded((e) => !e)}
                className="text-xs text-gray-500 hover:text-gray-700 transition-colors">
                {expanded ? "Masquer" : "Détails"}
              </button>
            )}
            {isAdmin && (
              <>
                {perms.length > 0 && <span className="text-gray-200">·</span>}
                <button onClick={onEdit}
                  className="text-xs text-blue-600 hover:text-blue-700 font-medium transition-colors">
                  Éditer
                </button>
                {canDelete && (
                  <>
                    <span className="text-gray-200">·</span>
                    <button onClick={onDelete}
                      className="text-xs text-red-400 hover:text-red-600 transition-colors">
                      Supprimer
                    </button>
                  </>
                )}
              </>
            )}
          </div>
        </td>
      </tr>
      {expanded && perms.length > 0 && (
        <tr className="border-b border-gray-50">
          <td colSpan={4} className="px-6 pb-3 pt-1 bg-gray-50/40">
            <div className="flex flex-wrap gap-1.5">
              {perms.map((p) => (
                <span key={p} className="text-[11px] text-gray-600 bg-white border border-gray-200 px-2 py-0.5 rounded-full">
                  {permLabels?.[p] || p}
                </span>
              ))}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Page principale ───────────────────────────────────────────────────────────
export default function RolesPage() {
  const { can } = useAuth();
  const isAdmin = can("action_manage_users");

  const [roles, setRoles]             = useState([]);
  const [permCats, setPermCats]       = useState({});
  const [permLabels, setPermLabels]   = useState({});
  const [loading, setLoading]         = useState(true);
  const [showCreate, setShowCreate]   = useState(false);
  const [editingRole, setEditingRole] = useState(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listRoles();
      setRoles(data.roles || []);
      setPermCats(data.permission_categories || {});
      setPermLabels(data.permission_labels || {});
    } catch {
      toast.error("Impossible de charger les rôles");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const handleDelete = async (role) => {
    if (!window.confirm(`Supprimer le rôle "${role.label}" ?`)) return;
    try {
      await deleteRole(role.id);
      toast.success(`Rôle "${role.label}" supprimé`);
      reload();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Impossible de supprimer ce rôle");
    }
  };

  const builtin = roles.filter((r) => r.is_builtin);
  const custom  = roles.filter((r) => !r.is_builtin);

  return (
    <div className="p-6 space-y-5">
      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-semibold text-gray-900">Rôles</h1>
            <p className="text-xs text-gray-400 mt-0.5">
              Gérez les rôles système et créez des rôles personnalisés avec des permissions granulaires.
            </p>
          </div>
        </div>
        {isAdmin && (
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl transition-colors shrink-0">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4"/>
            </svg>
            Nouveau rôle
          </button>
        )}
      </div>

      {loading ? (
        <div className="bg-white border border-gray-200 rounded-xl p-10 text-center text-gray-400 text-sm">
          Chargement…
        </div>
      ) : (
        <div className="space-y-4">
          {/* Rôles système */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
            <div className="px-6 py-3 border-b border-gray-100 bg-gray-50/50">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Rôles système</p>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-6 py-2.5">Rôle</th>
                  <th className="px-4 py-2.5">Description</th>
                  <th className="px-4 py-2.5">Permissions</th>
                  <th className="px-4 py-2.5">Actions</th>
                </tr>
              </thead>
              <tbody>
                {builtin.map((role) => (
                  <RoleRowExpandable key={role.id} role={role} permLabels={permLabels}
                    isAdmin={isAdmin} onEdit={() => setEditingRole(role)}
                    onDelete={() => {}} canDelete={false} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Rôles personnalisés */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
            <div className="px-6 py-3 border-b border-gray-100 bg-gray-50/50">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider">Rôles personnalisés</p>
            </div>
            {custom.length === 0 ? (
              <div className="py-12 text-center">
                <p className="text-gray-400 text-sm">Aucun rôle personnalisé créé.</p>
                {isAdmin && (
                  <button onClick={() => setShowCreate(true)}
                    className="mt-2 text-blue-600 hover:text-blue-700 text-sm font-medium">
                    Créer un rôle personnalisé →
                  </button>
                )}
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-100">
                    <th className="px-6 py-2.5">Rôle</th>
                    <th className="px-4 py-2.5">Description</th>
                    <th className="px-4 py-2.5">Permissions</th>
                    <th className="px-4 py-2.5">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {custom.map((role) => (
                    <RoleRowExpandable key={role.id} role={role} permLabels={permLabels}
                      isAdmin={isAdmin} onEdit={() => setEditingRole(role)}
                      onDelete={() => handleDelete(role)} canDelete />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {(showCreate || editingRole) && (
        <RoleModal
          role={editingRole}
          permCategories={permCats}
          permLabels={permLabels}
          onClose={() => { setShowCreate(false); setEditingRole(null); }}
          onSaved={reload}
        />
      )}
    </div>
  );
}
