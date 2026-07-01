import { useState, useEffect } from "react";
import toast from "react-hot-toast";
import {
  listUsers, createUser, updateUser, deleteUser,
  resetUserPassword, getRoles,
} from "../api";

// ─── Couleurs et métadonnées des rôles ───────────────────────────────────────

const ROLE_COLORS = {
  admin:      { bg: "bg-red-100",    text: "text-red-700",    border: "border-red-200"    },
  maintainer: { bg: "bg-purple-100", text: "text-purple-700", border: "border-purple-200" },
  uploader:   { bg: "bg-blue-100",   text: "text-blue-700",   border: "border-blue-200"   },
  auditor:    { bg: "bg-yellow-100", text: "text-yellow-700", border: "border-yellow-200" },
  reader:     { bg: "bg-gray-100",   text: "text-gray-600",   border: "border-gray-200"   },
};

function RoleBadge({ role, label }) {
  const c = ROLE_COLORS[role] || ROLE_COLORS.reader;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${c.bg} ${c.text} ${c.border}`}>
      {label || role}
    </span>
  );
}

function SourceBadge({ authSource }) {
  const isLdap = authSource === "ldap";
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border
      ${isLdap
        ? "bg-indigo-50 text-indigo-700 border-indigo-200"
        : "bg-gray-100 text-gray-600 border-gray-200"
      }`}>
      {isLdap ? (
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"/>
        </svg>
      ) : (
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
        </svg>
      )}
      {isLdap ? "Compte LDAP" : "Compte local"}
    </span>
  );
}

// ─── Modal générique ─────────────────────────────────────────────────────────

function Modal({ title, onClose, children }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-semibold text-gray-900">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="px-6 py-5">{children}</div>
      </div>
    </div>
  );
}

// ─── Formulaire de création d'utilisateur ────────────────────────────────────

function CreateUserModal({ roles, onClose, onCreated }) {
  const [form, setForm] = useState({ username: "", password: "", role: "reader", full_name: "", email: "" });
  const [saving, setSaving] = useState(false);
  const [showPwd, setShowPwd] = useState(false);

  const set = (k, v) => setForm((p) => ({ ...p, [k]: v }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.username || !form.password) {
      toast.error("Nom d'utilisateur et mot de passe requis");
      return;
    }
    if (form.password.length < 8) {
      toast.error("Mot de passe : 8 caractères minimum");
      return;
    }
    setSaving(true);
    try {
      await createUser(form);
      toast.success(`Utilisateur "${form.username}" créé`);
      onCreated();
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la création");
    } finally {
      setSaving(false);
    }
  };

  const selectedRole = roles[form.role];

  return (
    <Modal title="Créer un utilisateur" onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Username */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Nom d'utilisateur *</label>
          <input
            type="text" value={form.username} onChange={(e) => set("username", e.target.value)}
            placeholder="ex: j.dupont"
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            autoFocus
          />
        </div>

        {/* Mot de passe */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Mot de passe * <span className="text-gray-400 font-normal">(8 caractères min.)</span></label>
          <div className="relative">
            <input
              type={showPwd ? "text" : "password"} value={form.password}
              onChange={(e) => set("password", e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10"
            />
            <button type="button" onClick={() => setShowPwd(!showPwd)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
              {showPwd ? (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              ) : (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              )}
            </button>
          </div>
        </div>

        {/* Rôle */}
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Rôle</label>
          <select
            value={form.role} onChange={(e) => set("role", e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            {Object.entries(roles).map(([key, r]) => (
              <option key={key} value={key}>{r.label}</option>
            ))}
          </select>
          {selectedRole && (
            <p className="text-xs text-gray-500 mt-1.5 bg-gray-50 rounded-lg px-3 py-2">
              {selectedRole.description}
            </p>
          )}
        </div>

        {/* Nom complet */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Nom complet</label>
            <input type="text" value={form.full_name} onChange={(e) => set("full_name", e.target.value)}
              placeholder="Jean Dupont"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input type="email" value={form.email} onChange={(e) => set("email", e.target.value)}
              placeholder="j.dupont@..."
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button type="button" onClick={onClose}
            className="px-4 py-2 text-sm text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button type="submit" disabled={saving}
            className="px-5 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors">
            {saving ? "Création..." : "Créer l'utilisateur"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ─── Modal d'édition ─────────────────────────────────────────────────────────

function EditUserModal({ user, roles, onClose, onUpdated }) {
  const [form, setForm] = useState({
    role: user.role, full_name: user.full_name || "", email: user.email || "", active: user.active,
  });
  const [saving, setSaving] = useState(false);
  const set = (k, v) => setForm((p) => ({ ...p, [k]: v }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await updateUser(user.username, form);
      toast.success(`Utilisateur "${user.username}" mis à jour`);
      onUpdated();
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur lors de la mise à jour");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={`Modifier — ${user.username}`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Rôle</label>
          <select value={form.role} onChange={(e) => set("role", e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
            {Object.entries(roles).map(([key, r]) => (
              <option key={key} value={key}>{r.label}</option>
            ))}
          </select>
          {roles[form.role] && (
            <p className="text-xs text-gray-500 mt-1.5 bg-gray-50 rounded-lg px-3 py-2">
              {roles[form.role].description}
            </p>
          )}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Nom complet</label>
            <input type="text" value={form.full_name} onChange={(e) => set("full_name", e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input type="email" value={form.email} onChange={(e) => set("email", e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
        </div>
        <div className="flex items-center justify-between py-2">
          <div>
            <p className="text-sm font-medium text-gray-700">Compte actif</p>
            <p className="text-xs text-gray-400">Désactiver empêche la connexion sans supprimer le compte.</p>
          </div>
          <button type="button" onClick={() => set("active", !form.active)}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${form.active ? "bg-blue-600" : "bg-gray-300"}`}>
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${form.active ? "translate-x-6" : "translate-x-1"}`} />
          </button>
        </div>
        <div className="flex justify-end gap-3 pt-2">
          <button type="button" onClick={onClose}
            className="px-4 py-2 text-sm text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button type="submit" disabled={saving}
            className="px-5 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors">
            {saving ? "Enregistrement..." : "Enregistrer"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ─── Modal reset mot de passe ─────────────────────────────────────────────────

function ResetPasswordModal({ user, onClose }) {
  const [pwd, setPwd] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [showPwd, setShowPwd] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (pwd.length < 8) { toast.error("8 caractères minimum"); return; }
    if (pwd !== confirm) { toast.error("Les mots de passe ne correspondent pas"); return; }
    setSaving(true);
    try {
      await resetUserPassword(user.username, pwd);
      toast.success(`Mot de passe de "${user.username}" réinitialisé`);
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Erreur");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={`Réinitialiser le mot de passe — ${user.username}`} onClose={onClose}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Nouveau mot de passe</label>
          <div className="relative">
            <input type={showPwd ? "text" : "password"} value={pwd}
              onChange={(e) => setPwd(e.target.value)} autoFocus
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10"
            />
            <button type="button" onClick={() => setShowPwd(!showPwd)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400">
              {showPwd ? (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
              ) : (
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              )}
            </button>
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Confirmer</label>
          <input type={showPwd ? "text" : "password"} value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className={`w-full px-3 py-2 border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 ${confirm && pwd !== confirm ? "border-red-400" : "border-gray-300"}`}
          />
        </div>
        <div className="flex justify-end gap-3 pt-2">
          <button type="button" onClick={onClose}
            className="px-4 py-2 text-sm text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors">
            Annuler
          </button>
          <button type="submit" disabled={saving}
            className="px-5 py-2 bg-orange-600 text-white text-sm font-medium rounded-lg hover:bg-orange-700 disabled:opacity-50 transition-colors">
            {saving ? "..." : "Réinitialiser"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ─── Page principale ──────────────────────────────────────────────────────────

export default function UsersPage() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState({});
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(null); // "create" | {type:"edit"|"reset"|"delete", user}

  const load = async () => {
    setLoading(true);
    try {
      const [usersData, rolesData] = await Promise.all([listUsers(), getRoles()]);
      setUsers(usersData.users || []);
      setRoles(rolesData.roles || {});
    } catch {
      toast.error("Impossible de charger les utilisateurs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (user) => {
    if (!window.confirm(`Supprimer définitivement l'utilisateur "${user.username}" ?`)) return;
    try {
      await deleteUser(user.username);
      toast.success(`Utilisateur "${user.username}" supprimé`);
      load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Impossible de supprimer");
    }
  };

  const fmt = (iso) => iso ? new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" }) : "—";

  const roleOrder = { admin: 0, maintainer: 1, uploader: 2, auditor: 3, reader: 4 };
  const sortedUsers = [...users].sort((a, b) => (roleOrder[a.role] ?? 9) - (roleOrder[b.role] ?? 9));

  return (
    <div className="space-y-6 p-6">
      {/* En-tête */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Utilisateurs</h1>
          <p className="text-sm text-gray-500 mt-1">
            Gestion des comptes et des droits d'accès au dépôt.
          </p>
        </div>
        <button
          onClick={() => setModal("create")}
          className="flex items-center gap-2 px-4 py-2.5 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Créer un utilisateur
        </button>
      </div>

      {/* Légende des rôles */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3">Rôles disponibles</p>
        <div className="grid grid-cols-1 gap-2">
          {Object.entries(roles).map(([key, r]) => (
            <div key={key} className="flex items-start gap-3">
              <RoleBadge role={key} label={r.label} />
              <p className="text-xs text-gray-500 leading-relaxed">{r.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Tableau des utilisateurs */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="px-5 py-3.5 border-b border-gray-200 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-800">
            {users.length} utilisateur{users.length > 1 ? "s" : ""}
          </h2>
          <button onClick={load} className="text-xs text-gray-400 hover:text-gray-600 transition-colors">
            Actualiser
          </button>
        </div>

        {loading ? (
          <div className="py-16 text-center text-gray-400 text-sm">Chargement...</div>
        ) : users.length === 0 ? (
          <div className="py-16 text-center text-gray-400 text-sm">Aucun utilisateur</div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Utilisateur</th>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Rôle</th>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Origine</th>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Statut</th>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Dernière connexion</th>
                <th className="px-5 py-2.5 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Créé le</th>
                <th className="px-5 py-2.5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sortedUsers.map((u) => (
                <tr key={u.username} className={`hover:bg-gray-50 ${!u.active ? "opacity-50" : ""}`}>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold
                        ${ROLE_COLORS[u.role]?.bg || "bg-gray-100"} ${ROLE_COLORS[u.role]?.text || "text-gray-600"}`}>
                        {(u.full_name || u.username).charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">{u.username}</p>
                        {u.full_name && <p className="text-xs text-gray-400">{u.full_name}</p>}
                        {u.email
                          ? <p className="text-xs text-gray-400">{u.email}</p>
                          : <p className="text-xs text-amber-500 flex items-center gap-1">
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
                              </svg>
                              Pas d'email — ne recevra pas les notifications
                            </p>
                        }
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <RoleBadge role={u.role} label={roles[u.role]?.label || u.role} />
                  </td>
                  <td className="px-5 py-3.5">
                    <SourceBadge authSource={u.auth_source} />
                  </td>
                  <td className="px-5 py-3.5">
                    <span className={`inline-flex items-center gap-1 text-xs font-medium ${u.active ? "text-green-600" : "text-gray-400"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${u.active ? "bg-green-500" : "bg-gray-400"}`} />
                      {u.active ? "Actif" : "Inactif"}
                    </span>
                  </td>
                  <td className="px-5 py-3.5 text-xs text-gray-500">{fmt(u.last_login)}</td>
                  <td className="px-5 py-3.5 text-xs text-gray-500">{fmt(u.created_at)}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-1 justify-end">
                      <button title="Modifier"
                        onClick={() => setModal({ type: "edit", user: u })}
                        className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button
                        title={u.auth_source === "ldap" ? "Mot de passe géré par l'annuaire LDAP" : "Réinitialiser le mot de passe"}
                        onClick={() => u.auth_source !== "ldap" && setModal({ type: "reset", user: u })}
                        disabled={u.auth_source === "ldap"}
                        className={`p-1.5 rounded-lg transition-colors ${u.auth_source === "ldap" ? "text-gray-200 cursor-not-allowed" : "text-gray-400 hover:text-orange-600 hover:bg-orange-50"}`}>
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                      </button>
                      <button title="Supprimer"
                        onClick={() => handleDelete(u)}
                        className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Modals */}
      {modal === "create" && (
        <CreateUserModal roles={roles} onClose={() => setModal(null)} onCreated={load} />
      )}
      {modal?.type === "edit" && (
        <EditUserModal user={modal.user} roles={roles} onClose={() => setModal(null)} onUpdated={load} />
      )}
      {modal?.type === "reset" && (
        <ResetPasswordModal user={modal.user} onClose={() => setModal(null)} />
      )}
    </div>
  );
}
