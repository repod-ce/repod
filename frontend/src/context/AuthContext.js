import { createContext, useContext, useState, useEffect, useMemo, useCallback } from "react";
import { setApiToken, clearApiToken, refreshToken } from "../api";

const AuthContext = createContext(null);

// ─── Métadonnées des rôles (source unique de vérité) ─────────────────────────
// Utilisé dans : sidebar pill, UsersPage badge, in-page guards, tooltips

export const ROLE_META = {
  admin: {
    label:       "Administrateur",
    short:       "Admin",
    bg:          "bg-red-100",
    text:        "text-red-700",
    border:      "border-red-200",
    dot:         "bg-red-500",
    description: "Accès complet — gestion des utilisateurs, paramètres système, toutes les fonctionnalités.",
  },
  maintainer: {
    label:       "Mainteneur",
    short:       "Mainteneur",
    bg:          "bg-purple-100",
    text:        "text-purple-700",
    border:      "border-purple-200",
    dot:         "bg-purple-500",
    description: "Gestion du dépôt — import, sécurité, distributions.",
  },
  uploader: {
    label:       "Packager",
    short:       "Packager",
    bg:          "bg-blue-100",
    text:        "text-blue-700",
    border:      "border-blue-200",
    dot:         "bg-blue-500",
    description: "Dépôt de paquets — upload de paquets.",
  },
  auditor: {
    label:       "Auditeur",
    short:       "Auditeur",
    bg:          "bg-amber-100",
    text:        "text-amber-700",
    border:      "border-amber-200",
    dot:         "bg-amber-500",
    description: "Lecture seule sur sécurité, audit et téléchargements.",
  },
  reader: {
    label:       "Lecteur",
    short:       "Lecteur",
    bg:          "bg-slate-100",
    text:        "text-slate-600",
    border:      "border-slate-200",
    dot:         "bg-slate-400",
    description: "Consultation des paquets disponibles uniquement.",
  },
};

// Hiérarchie pour comparaisons éventuelles
export const ROLE_RANK = { admin: 5, maintainer: 4, uploader: 3, auditor: 2, reader: 1 };

// ─── Matrice des permissions par fonctionnalité ───────────────────────────────
// Clés = feature token utilisé dans le code (pas les URLs)
export const PERMISSIONS = {
  // Navigation
  nav_upload:        ["admin", "maintainer", "uploader"],
  nav_import:        ["admin", "maintainer"],
  nav_security:      ["admin", "maintainer", "auditor"],
  nav_audit:         ["admin", "maintainer", "auditor"],
  nav_downloads:     ["admin", "maintainer", "auditor"],
  nav_health:        ["admin", "maintainer"],
  nav_users:         ["admin"],
  nav_settings:      ["admin"],

  // Actions dans les pages (au-delà de la lecture)
  action_quarantine: ["admin", "maintainer"],
  action_upload:     ["admin", "maintainer", "uploader"],
  action_import:     ["admin", "maintainer"],
  action_delete_pkg: ["admin", "maintainer"],
  action_scan:       ["admin", "maintainer"],        // scan CVE manuel
  action_manage_users:   ["admin"],
  action_manage_groups:  ["admin"],
  action_manage_roles:   ["admin"],
  action_settings:       ["admin"],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseJwt(token) {
  try {
    return JSON.parse(atob(token.split(".")[1]));
  } catch {
    return null;
  }
}

function isTokenValid(token) {
  if (!token) return false;
  const payload = parseJwt(token);
  if (!payload?.exp) return false;
  return payload.exp * 1000 > Date.now() + 10_000;
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export function AuthProvider({ children }) {
  const [sessionWarning, setSessionWarning] = useState(false);
  const [token, setToken] = useState(() => {
    const stored = localStorage.getItem("token");
    return isTokenValid(stored) ? stored : null;
  });

  useEffect(() => {
    const stored = localStorage.getItem("token");
    if (stored && !isTokenValid(stored)) {
      localStorage.removeItem("token");
    }
    const valid = isTokenValid(stored) ? stored : null;
    if (valid) setApiToken(valid);
    else clearApiToken();
  }, []);

  const user = useMemo(() => {
    if (!token) return null;
    const payload = parseJwt(token);
    return payload
      ? { username: payload.sub, role: payload.role, fullName: payload.full_name }
      : null;
  }, [token]);

  // ── can(feature) — vérifie si l'utilisateur a la permission ──────────────
  // Usage : can("action_quarantine")  ou  can(["admin","maintainer"])
  const can = useCallback((featureOrRoles) => {
    if (!user) return false;
    const allowed = Array.isArray(featureOrRoles)
      ? featureOrRoles
      : (PERMISSIONS[featureOrRoles] ?? []);
    return allowed.includes(user.role);
  }, [user]);

  // Raccourcis lisibles pour les conditions fréquentes
  const isAdmin      = user?.role === "admin";
  const isMaintainer = ["admin", "maintainer"].includes(user?.role);
  const isAuditor    = user?.role === "auditor";
  const isReadOnly   = user?.role === "auditor" || user?.role === "reader";

  const signIn = (newToken) => {
    localStorage.setItem("token", newToken);
    setApiToken(newToken);
    setToken(newToken);
  };

  const signOut = () => {
    localStorage.removeItem("token");
    clearApiToken();
    setToken(null);
  };

  useEffect(() => {
    if (!token) return;
    let lastActivity = Date.now();
    const REFRESH_INTERVAL = 45 * 60 * 1000;
    const INACTIVITY_LIMIT = 120 * 60 * 1000;
    const WARNING_BEFORE   =   5 * 60 * 1000;

    const trackActivity = () => {
      lastActivity = Date.now();
      setSessionWarning(false);
    };
    window.addEventListener("mousemove", trackActivity);
    window.addEventListener("keydown", trackActivity);
    window.addEventListener("click", trackActivity);

    const interval = setInterval(async () => {
      const idle = Date.now() - lastActivity;
      if (idle > INACTIVITY_LIMIT) {
        setSessionWarning(false);
        signOut();
        window.location.href = "/login";
        return;
      }
      if (idle > INACTIVITY_LIMIT - WARNING_BEFORE) {
        setSessionWarning(true);
      }
      try {
        const data = await refreshToken();
        if (data?.access_token) {
          signIn(data.access_token);
        }
      } catch (err) {
        if (err?.response?.status === 401) {
          signOut();
          window.location.href = "/login";
        }
      }
    }, REFRESH_INTERVAL);

    return () => {
      clearInterval(interval);
      window.removeEventListener("mousemove", trackActivity);
      window.removeEventListener("keydown", trackActivity);
      window.removeEventListener("click", trackActivity);
    };
  }, [!!token]);

  return (
    <AuthContext.Provider value={{
      token, user, signIn, signOut,
      can, isAdmin, isMaintainer, isAuditor, isReadOnly,
      sessionWarning,
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
