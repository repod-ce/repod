import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../context/AuthContext";
import {
  listGroups, createGroup, updateGroup, deleteGroup,
  getGroupMembers, addGroupMember, removeGroupMember, listUsers,
} from "../api";
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

// ── Dot coloré ───────────────────────────────────────────────────────────────
function ColorDot({ color, size = 10 }) {
  return (
    <span
      className="inline-block rounded-full flex-shrink-0"
      style={{ width: size, height: size, backgroundColor: colorHex(color) }}
    />
  );
}

// ── Modal création/édition ────────────────────────────────────────────────────
const ROLE_OPTIONS = [
  { value: "",           label: "Aucun (pas d'héritage)" },
  { value: "reader",     label: "Lecteur" },
  { value: "auditor",    label: "Auditeur" },
  { value: "uploader",   label: "Packager" },
  { value: "maintainer", label: "Mainteneur" },
  { value: "admin",      label: "Administrateur" },
];

function GroupModal({ group, onClose, onSaved }) {
  const [name, setName]               = useState(group?.name || "");
  const [description, setDescription] = useState(group?.description || "");
  const [color, setColor]             = useState(group?.color || "blue");
  const [defaultRole, setDefaultRole] = useState(group?.default_role || "");
  const [saving, setSaving]           = useState(false);

  const handleSave = async () => {
    if (!name.trim()) { toast.error("Le nom est obligatoire"); return; }
    setSaving(true);
    try {
      const payload = {
        name: name.trim(), description, color,
        default_role: defaultRole || null,
      };
      if (group) {
        await updateGroup(group.id, payload);
        toast.success("Groupe mis à jour");
      } else {
        await createGroup(payload);
        toast.success("Groupe créé");
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
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">
            {group ? "Modifier le groupe" : "Nouveau groupe"}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div className="px-6 py-4 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Nom <span className="text-red-500">*</span></label>
            <input
              className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              value={name} onChange={(e) => setName(e.target.value)}
              placeholder="ex : Équipe RSSI"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">Description</label>
            <textarea
              className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
              rows={2} value={description} onChange={(e) => setDescription(e.target.value)}
              placeholder="Rôle ou périmètre de ce groupe"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-2">Couleur</label>
            <div className="flex flex-wrap gap-2.5">
              {COLOR_OPTIONS.map((c) => (
                <button key={c.value} title={c.label}
                  onClick={() => setColor(c.value)}
                  className={`w-7 h-7 rounded-full transition-all ${
                    color === c.value ? "ring-2 ring-offset-2 ring-gray-400 scale-110" : "opacity-70 hover:opacity-100"
                  }`}
                  style={{ backgroundColor: c.hex }}
                />
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-500 mb-1.5">
              Role par defaut
            </label>
            <select
              value={defaultRole}
              onChange={(e) => setDefaultRole(e.target.value)}
              className="w-full border border-gray-300 rounded-xl px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            <p className="text-[11px] text-gray-400 mt-1">
              Les membres dont le role actuel est inferieur heriteront automatiquement de ce role.
            </p>
          </div>
        </div>

        <div className="px-6 pb-5 flex gap-3 border-t border-gray-100 pt-4">
          <button onClick={onClose}
            className="flex-1 py-2 text-sm text-gray-500 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button onClick={handleSave} disabled={saving}
            className="flex-1 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-xl transition-colors disabled:opacity-50">
            {saving ? "Sauvegarde…" : group ? "Mettre à jour" : "Créer"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Modal membres ─────────────────────────────────────────────────────────────
function MembersModal({ group, onClose, isAdmin }) {
  const [members, setMembers] = useState([]);
  const [users, setUsers]     = useState([]);
  const [search, setSearch]   = useState("");
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    setLoading(true);
    const [mRes, uRes] = await Promise.all([
      getGroupMembers(group.id),
      listUsers(),
    ]);
    setMembers(mRes.members || []);
    setUsers(uRes.users || []);
    setLoading(false);
  }, [group.id]);

  useEffect(() => { reload(); }, [reload]);

  const memberSet = new Set(members.map((m) => m.username));
  const available = users.filter(
    (u) => !memberSet.has(u.username) && (
      search === "" ||
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      (u.full_name || "").toLowerCase().includes(search.toLowerCase())
    )
  );

  const handleAdd = async (username) => {
    try {
      await addGroupMember(group.id, username);
      toast.success(`${username} ajouté`);
      reload();
    } catch (err) { toast.error(err.response?.data?.detail || "Erreur"); }
  };

  const handleRemove = async (username) => {
    try {
      await removeGroupMember(group.id, username);
      toast.success(`${username} retiré`);
      reload();
    } catch (err) { toast.error(err.response?.data?.detail || "Erreur"); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-xl flex flex-col max-h-[80vh]" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-gray-100 shrink-0">
          <div className="flex items-center gap-2.5">
            <ColorDot color={group.color} size={12} />
            <div>
              <h2 className="text-base font-semibold text-gray-900">{group.name}</h2>
              <p className="text-xs text-gray-400">{members.length} membre{members.length !== 1 ? "s" : ""}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-gray-400 text-sm">Chargement…</div>
        ) : (
          <div className="flex min-h-0 flex-1 divide-x divide-gray-100">
            {/* Membres actuels */}
            <div className="flex-1 overflow-y-auto px-5 py-4">
              <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-3">
                Membres ({members.length})
              </p>
              {members.length === 0 ? (
                <p className="text-gray-400 text-sm italic">Aucun membre pour l'instant.</p>
              ) : members.map((m) => (
                <div key={m.username} className="flex items-center justify-between py-2 group border-b border-gray-50 last:border-0">
                  <div>
                    <p className="text-sm font-medium text-gray-800">{m.username}</p>
                    {m.full_name && <p className="text-xs text-gray-400">{m.full_name}</p>}
                  </div>
                  {isAdmin && (
                    <button onClick={() => handleRemove(m.username)}
                      className="text-xs text-red-500 hover:text-red-700 opacity-0 group-hover:opacity-100 transition-opacity font-medium">
                      Retirer
                    </button>
                  )}
                </div>
              ))}
            </div>

            {/* Ajouter */}
            {isAdmin && (
              <div className="flex-1 overflow-y-auto px-5 py-4">
                <p className="text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-3">
                  Ajouter un utilisateur
                </p>
                <input
                  className="w-full border border-gray-300 rounded-lg px-3 py-1.5 text-xs mb-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Rechercher…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                {available.length === 0 ? (
                  <p className="text-gray-400 text-xs italic">
                    {search ? "Aucun résultat." : "Tous les utilisateurs sont déjà membres."}
                  </p>
                ) : available.map((u) => (
                  <button key={u.username} onClick={() => handleAdd(u.username)}
                    className="w-full text-left flex items-center justify-between py-2 px-2 rounded-lg hover:bg-blue-50 hover:text-blue-700 group transition-colors border-b border-gray-50 last:border-0">
                    <div>
                      <p className="text-sm text-gray-700 group-hover:text-blue-700">{u.username}</p>
                      {u.full_name && <p className="text-xs text-gray-400">{u.full_name}</p>}
                    </div>
                    <span className="text-xs text-blue-500 opacity-0 group-hover:opacity-100 font-medium">+ Ajouter</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Page principale ───────────────────────────────────────────────────────────
export default function GroupsPage() {
  const { can } = useAuth();
  const isAdmin = can("action_manage_users");

  const [groups, setGroups]             = useState([]);
  const [loading, setLoading]           = useState(true);
  const [showCreate, setShowCreate]     = useState(false);
  const [editingGroup, setEditingGroup] = useState(null);
  const [membersGroup, setMembersGroup] = useState(null);

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listGroups();
      setGroups(data.groups || []);
    } catch {
      toast.error("Impossible de charger les groupes");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const handleDelete = async (group) => {
    if (!window.confirm(`Supprimer le groupe "${group.name}" ?`)) return;
    try {
      await deleteGroup(group.id);
      toast.success(`Groupe "${group.name}" supprimé`);
      reload();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la suppression");
    }
  };

  return (
    <div className="p-6 space-y-5">
      {/* En-tête */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-50 rounded-xl flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-semibold text-gray-900">Groupes d'utilisateurs</h1>
            <p className="text-xs text-gray-400 mt-0.5">
              Organisez vos utilisateurs en groupes pour l'attribution des décisions CVE.
            </p>
          </div>
        </div>
        {isAdmin && (
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-xl transition-colors shrink-0">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4"/>
            </svg>
            Nouveau groupe
          </button>
        )}
      </div>

      {/* Tableau */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-10 text-center text-gray-400 text-sm">Chargement…</div>
        ) : groups.length === 0 ? (
          <div className="p-16 text-center">
            <div className="w-12 h-12 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <svg className="w-6 h-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/>
              </svg>
            </div>
            <p className="text-gray-500 text-sm font-medium">Aucun groupe créé</p>
            {isAdmin && (
              <button onClick={() => setShowCreate(true)}
                className="mt-2 text-blue-600 hover:text-blue-700 text-sm font-medium">
                Créer le premier groupe →
              </button>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs font-semibold text-gray-400 uppercase tracking-wider border-b border-gray-100 bg-gray-50/50">
                <th className="px-6 py-3">Groupe</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3">Membres</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Créé par</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {groups.map((group) => (
                <tr key={group.id} className="hover:bg-gray-50/60 transition-colors group">
                  {/* Nom */}
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2.5">
                      <ColorDot color={group.color} />
                      <span className="font-medium text-gray-800">{group.name}</span>
                    </div>
                  </td>
                  {/* Description */}
                  <td className="px-4 py-3 text-gray-500 text-xs max-w-xs">
                    <p className="line-clamp-2">{group.description || <span className="text-gray-300">—</span>}</p>
                  </td>
                  {/* Membres */}
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-gray-600 bg-gray-100 px-2 py-0.5 rounded-full">
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                      </svg>
                      {group.member_count ?? 0}
                    </span>
                  </td>
                  {/* Role */}
                  <td className="px-4 py-3">
                    {group.default_role ? (
                      <span className="text-xs font-medium text-violet-700 bg-violet-50 px-2 py-0.5 rounded-full">
                        {ROLE_OPTIONS.find(r => r.value === group.default_role)?.label || group.default_role}
                      </span>
                    ) : (
                      <span className="text-xs text-gray-300">—</span>
                    )}
                  </td>
                  {/* Créé par */}
                  <td className="px-4 py-3 text-xs text-gray-400">{group.created_by || "—"}</td>
                  {/* Actions */}
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button onClick={() => setMembersGroup(group)}
                        className="text-xs text-blue-600 hover:text-blue-700 font-medium transition-colors">
                        {isAdmin ? "Membres" : "Voir"}
                      </button>
                      {isAdmin && (
                        <>
                          <span className="text-gray-200">·</span>
                          <button onClick={() => setEditingGroup(group)}
                            className="text-xs text-gray-500 hover:text-gray-700 transition-colors">
                            Éditer
                          </button>
                          <span className="text-gray-200">·</span>
                          <button onClick={() => handleDelete(group)}
                            className="text-xs text-red-400 hover:text-red-600 transition-colors">
                            Supprimer
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modales */}
      {(showCreate || editingGroup) && (
        <GroupModal
          group={editingGroup}
          onClose={() => { setShowCreate(false); setEditingGroup(null); }}
          onSaved={reload}
        />
      )}
      {membersGroup && (
        <MembersModal
          group={membersGroup}
          onClose={() => setMembersGroup(null)}
          isAdmin={isAdmin}
        />
      )}
    </div>
  );
}
