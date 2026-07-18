import { useState, useEffect, useRef, useCallback } from "react";
import { Outlet, NavLink, useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth, ROLE_META, PERMISSIONS } from "../context/AuthContext";
import { listPendingPromotions } from "../api";
import { getMe, mfaSetup, mfaConfirm, mfaDisable } from "../api";
import toast from "react-hot-toast";

// ─── Icônes SVG — viewBox 0 0 24 24, stroke-width 1.7, style outline ─────────
const Icon = {
  Dashboard: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1"/>
      <rect x="14" y="3" width="7" height="7" rx="1"/>
      <rect x="3" y="14" width="7" height="7" rx="1"/>
      <rect x="14" y="14" width="7" height="7" rx="1"/>
    </svg>
  ),
  Package: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
      <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
      <line x1="12" y1="22.08" x2="12" y2="12"/>
    </svg>
  ),
  Upload: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="17 8 12 3 7 8"/>
      <line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
  Import: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 17l4 4 4-4"/>
      <path d="M12 12v9"/>
      <path d="M20.88 18.09A5 5 0 0018 9h-1.26A8 8 0 103 16.29"/>
    </svg>
  ),
  Distribution: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3"/>
      <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    </svg>
  ),
  Sources: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 010 20 15.3 15.3 0 010-20z"/>
    </svg>
  ),
  // CVE / Décisions : bouclier avec croix de virus — clair pour sécurité artefacts
  CveDecision: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
  ),
  Terminal: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/>
      <line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  ),
  Audit: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2"/>
      <rect x="9" y="3" width="6" height="4" rx="1"/>
      <line x1="9" y1="12" x2="15" y2="12"/>
      <line x1="9" y1="16" x2="13" y2="16"/>
    </svg>
  ),
  Users: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 00-3-3.87"/>
      <path d="M16 3.13a4 4 0 010 7.75"/>
    </svg>
  ),
  Settings: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
    </svg>
  ),
  Logout: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
      <polyline points="16 17 21 12 16 7"/>
      <line x1="21" y1="12" x2="9" y2="12"/>
    </svg>
  ),
  Bell: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 01-3.46 0"/>
    </svg>
  ),
  Download: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
      <polyline points="7 10 12 15 17 10"/>
      <line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  // Supervision : signal cardiogramme
  Health: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  ),
  HelpCircle: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/>
      <line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  ExternalLink: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6"/>
      <polyline points="15 3 21 3 21 9"/>
      <line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  ),
  BookOpen: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 3h6a4 4 0 014 4v14a3 3 0 00-3-3H2z"/>
      <path d="M22 3h-6a4 4 0 00-4 4v14a3 3 0 013-3h7z"/>
    </svg>
  ),
  Zap: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
    </svg>
  ),
  FileText: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
      <polyline points="10 9 9 9 8 9"/>
    </svg>
  ),
  MessageCircle: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/>
    </svg>
  ),
  // Promotions : flèche montante avec validation
  Promotion: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="17 1 21 5 17 9"/>
      <path d="M3 11V9a4 4 0 014-4h14"/>
      <polyline points="7 23 3 19 7 15"/>
      <path d="M21 13v2a4 4 0 01-4 4H3"/>
    </svg>
  ),
  // Collapse sidebar
  ChevronLeft: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 18 9 12 15 6"/>
    </svg>
  ),
  ChevronRight: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  ),
  ChevronBreadcrumb: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  ),
  // Configuration client : clé + terminal
  ClientSetup: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <polyline points="4 17 10 11 4 5"/>
      <line x1="12" y1="19" x2="20" y2="19"/>
    </svg>
  ),
  // Logs : lignes de texte avec indicateur
  Logs: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="8" y1="13" x2="16" y2="13"/>
      <line x1="8" y1="17" x2="13" y2="17"/>
    </svg>
  ),
  // Shield : rôles / permissions
  Shield: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  // Group : alias de Users pour groupes
  Group: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 00-3-3.87"/>
      <path d="M16 3.13a4 4 0 010 7.75"/>
    </svg>
  ),
  Email: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="4" width="20" height="16" rx="2"/>
      <path d="M22 4l-10 8L2 4"/>
    </svg>
  ),
  // Dockerfile : logo Docker simplifié (cube)
  Dockerfile: () => (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>
      <polyline points="3.27 6.96 12 12.01 20.73 6.96"/>
      <line x1="12" y1="22.08" x2="12" y2="12"/>
    </svg>
  ),
};

// ─── Liens d'aide ──────────────────────────────────────────────────────────────
const DOC_BASE = "https://docs.getrepod.com";
const APP_VERSION = process.env.REACT_APP_VERSION || "1.0.0";

const HELP_LINKS = [
  {
    section: "Documentation",
    items: [
      { label: "Démarrage rapide",        href: `${DOC_BASE}/getting-started/`,          icon: "Zap"         },
      { label: "Guide d'administration",  href: `${DOC_BASE}/fr/ADMINISTRATION/`,        icon: "BookOpen"    },
      { label: "Référence API",           href: `${DOC_BASE}/fr/API_REFERENCE/`,         icon: "FileText"    },
      { label: "Rotation des clés GPG",   href: `${DOC_BASE}/how-to/rotate-gpg-keys/`,  icon: "ExternalLink"},
    ],
  },
  {
    section: "Ressources",
    items: [
      { label: "Changelog",              href: `${DOC_BASE}/changelog/`,              icon: "FileText"    },
      { label: "Contacter le support",   href: "mailto:contact@getrepod.com",         icon: "MessageCircle"},
    ],
  },
];

function HelpMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className={`relative w-8 h-8 rounded-lg flex items-center justify-center transition-colors ${
          open ? "bg-slate-100 text-slate-700" : "text-slate-400 hover:bg-slate-100 hover:text-slate-600"
        }`}
        aria-label="Aide"
        title="Aide"
      >
        <span className="w-4 h-4"><Icon.HelpCircle /></span>
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-72 bg-white rounded-xl shadow-xl border border-slate-200 z-50 overflow-hidden">
          <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
            <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Centre d'aide</p>
            <p className="text-[11px] text-slate-400 mt-0.5">Repod — Community Edition</p>
          </div>
          {HELP_LINKS.map((section, si) => (
            <div key={si}>
              {si > 0 && <div className="h-px bg-slate-100 mx-4" />}
              <div className="py-1.5">
                <p className="px-4 py-1 text-[10px] font-bold tracking-widest uppercase text-slate-400">
                  {section.section}
                </p>
                {section.items.map((item, ii) => {
                  const ItemIcon = Icon[item.icon];
                  return (
                    <a key={ii} href={item.href} target="_blank" rel="noopener noreferrer"
                      onClick={() => setOpen(false)}
                      className="flex items-center gap-3 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 hover:text-slate-900 transition-colors">
                      <span className="w-3.5 h-3.5 text-slate-400 shrink-0">{ItemIcon && <ItemIcon />}</span>
                      <span className="flex-1">{item.label}</span>
                      <span className="w-3 h-3 text-slate-300 shrink-0"><Icon.ExternalLink /></span>
                    </a>
                  );
                })}
              </div>
            </div>
          ))}
          <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-100 flex items-center justify-between gap-2">
            <p className="text-[10px] text-slate-400">
              Repod Community — <span className="font-mono">v{APP_VERSION}</span>
            </p>
            <a href="https://getrepod.com/#pricing" target="_blank" rel="noopener noreferrer"
              className="text-[10px] font-bold text-blue-600 hover:text-blue-700">
              Passer à l'Enterprise →
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Métadonnées des pages (topbar + breadcrumb) ──────────────────────────────
const PAGE_TITLES = {
  "/":              { label: "Tableau de bord",    icon: "Dashboard"    },
  "/packages":      { label: "Paquets",             icon: "Package"      },
  "/upload":        { label: "Déposer un paquet",   icon: "Upload"       },
  "/import":        { label: "Importer",            icon: "Import"       },
  "/sources":       { label: "Sources",             icon: "Sources"      },
  "/distributions": { label: "Distributions",       icon: "Distribution" },
  "/security":      { label: "Décisions CVE",       icon: "CveDecision"  },
  "/promotions":    { label: "Promotions",          icon: "Promotion"    },
  "/audit":         { label: "Journal d'audit",     icon: "Audit"        },
  "/setup":         { label: "Configuration client",icon: "ClientSetup"  },
  "/users":         { label: "Utilisateurs",        icon: "Users"        },
  "/settings":      { label: "Paramètres",          icon: "Settings"     },
  "/templates":     { label: "Templates email",     icon: "Email"        },
  "/downloads":     { label: "Téléchargements",     icon: "Download"     },
  "/supervision":   { label: "Supervision",         icon: "Health"       },
  "/logs":          { label: "Logs système",        icon: "Logs"         },
  "/dockerfile":    { label: "Analyseur Dockerfile", icon: "Dockerfile"   },
  "/groups":        { label: "Groupes",             icon: "Users"        },
  "/roles":         { label: "Rôles",               icon: "Shield"       },
};

// Section d'appartenance de chaque page (pour le breadcrumb)
const PAGE_SECTION = {
  "/packages":      "Dépôt",
  "/upload":        "Dépôt",
  "/import":        "Dépôt",
  "/sources":       "Dépôt",
  "/distributions": "Dépôt",
  "/security":      "Sécurité",
  "/promotions":    "Sécurité",
  "/audit":         "Sécurité",
  "/setup":         "Clients",
  "/dockerfile":    "Dépôt",
  "/downloads":     "Administration",
  "/supervision":   "Administration",
  "/users":         "Administration",
  "/settings":      "Administration",
  "/logs":          "Administration",
  "/groups":        "Administration",
  "/roles":         "Administration",
};

// ─── Séparateur de section ─────────────────────────────────────────────────────
// Se masque si tous les enfants n'ont pas les permissions, ou si sidebar réduite.
function NavSection({ label, perms = [], collapsed = false }) {
  const { can } = useAuth();
  const visible = perms.length === 0 || perms.some(p => !p || can(p));
  if (!visible) return null;

  // En mode réduit : simple trait de séparation
  if (collapsed) {
    return <div className="mx-3 my-2 h-px bg-navy-700/70" />;
  }

  return (
    <p className="px-3 pt-4 pb-1 text-[9.5px] font-bold tracking-[0.12em] uppercase text-navy-400 select-none">
      {label}
    </p>
  );
}


// ─── Groupe de navigation (dropdown cliquable avec chevron) ───────────────────
function NavGroup({ label, paths = [], children, collapsed = false }) {
  const location = useLocation();
  const isActive = paths.some(p => location.pathname === p || location.pathname.startsWith(p + "/"));
  const [open, setOpen] = useState(true);

  useEffect(() => {
    if (isActive) setOpen(true);
  }, [isActive]);

  if (collapsed) {
    return (
      <>
        <div className="mx-3 my-2 h-px bg-navy-700/70" />
        {children}
      </>
    );
  }

  return (
    <div>
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center w-full gap-1.5 px-3 pt-3.5 pb-1 text-[9.5px] font-bold tracking-[0.12em] uppercase text-navy-400 hover:text-slate-300 transition-colors select-none"
      >
        <span className="flex-1 text-left">{label}</span>
        <svg
          className={`w-3 h-3 shrink-0 transition-transform duration-200 ${open ? "rotate-0" : "-rotate-90"}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="space-y-px">{children}</div>}
    </div>
  );
}

// ─── Item de navigation ───────────────────────────────────────────────────────
// perm    : clé PERMISSIONS — si absent, visible par tous
// collapsed : booléen pour le mode sidebar réduite
function NavItem({ to, end, icon, label, badge, perm, collapsed = false }) {
  const { can } = useAuth();
  if (perm && !can(perm)) return null;

  return (
    // group/navitem pour cibler le tooltip uniquement sur cet item
    <div className="relative group/navitem">
      <NavLink
        to={to}
        end={end}
        className={({ isActive }) =>
          `relative flex items-center rounded-lg text-sm font-medium transition-all duration-150 ${
            collapsed ? "px-0 py-2.5 justify-center w-full" : "gap-3 px-3 py-2.5"
          } ${
            isActive
              ? "bg-violet-600/[0.15] text-violet-300"
              : "text-slate-400 hover:bg-violet-600/[0.10] hover:text-violet-300"
          }`
        }
      >
        {({ isActive }) => (
          <>
            {/* Icône */}
            <span className={`w-4 h-4 shrink-0 transition-colors ${
              isActive ? "text-violet-400" : "text-slate-500 group-hover/navitem:text-violet-400"
            }`}>
              {icon}
            </span>
            {/* Label + compteur — masqués en mode collapsed */}
            {!collapsed && (
              <>
                <span className="flex-1 leading-none">{label}</span>
                {badge > 0 && (
                  <span className="ml-auto text-[10px] font-semibold tabular-nums text-navy-400 bg-navy-800 border border-navy-700 px-1.5 py-0.5 rounded">
                    {badge > 99 ? "99+" : badge}
                  </span>
                )}
              </>
            )}
            {/* Compteur compact en mode collapsed */}
            {collapsed && badge > 0 && (
              <span className="absolute -top-0.5 right-0.5 text-[9px] font-bold tabular-nums text-navy-300 bg-navy-800 border border-navy-700 px-1 rounded leading-tight">
                {badge > 99 ? "99+" : badge}
              </span>
            )}
          </>
        )}
      </NavLink>

      {/* Tooltip — visible uniquement en mode collapsed au hover */}
      {collapsed && (
        <div
          className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2.5 z-50
                     opacity-0 group-hover/navitem:opacity-100 transition-opacity duration-150"
          aria-hidden="true"
        >
          {/* Flèche */}
          <div className="absolute right-full top-1/2 -translate-y-1/2 w-0 h-0
                          border-t-[5px] border-b-[5px] border-r-[5px]
                          border-t-transparent border-b-transparent border-r-navy-700" />
          {/* Contenu */}
          <div className="bg-navy-800 border border-navy-700 text-slate-200 text-xs font-medium
                          px-2.5 py-1.5 rounded-lg shadow-xl whitespace-nowrap flex items-center gap-2">
            {label}
            {badge > 0 && (
              <span className="text-navy-300 text-[10px] font-semibold tabular-nums bg-navy-900 border border-navy-700 px-1.5 py-0.5 rounded">
                {badge > 99 ? "99+" : badge}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Pill de rôle ──────────────────────────────────────────────────────────────
function RolePill({ role }) {
  const meta = ROLE_META[role] ?? ROLE_META.reader;
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${meta.bg} ${meta.text} ${meta.border}`}>
      {meta.short}
    </span>
  );
}

// ─── Modal "Mon compte" ───────────────────────────────────────────────────────
function MonCompteModal({ onClose }) {
  const [me, setMe]               = useState(null);
  const [loading, setLoading]     = useState(true);
  const [mfaStep, setMfaStep]     = useState("idle");
  const [setupData, setSetupData] = useState(null);
  const [totpInput, setTotpInput] = useState("");
  const [disablePwd, setDisablePwd] = useState("");
  const [busy, setBusy]           = useState(false);

  const loadMe = useCallback(async () => {
    setLoading(true);
    try { setMe(await getMe()); }
    catch { toast.error("Impossible de charger les infos du compte"); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { loadMe(); }, [loadMe]);

  const handleSetup = async () => {
    setBusy(true);
    try {
      const data = await mfaSetup();
      setSetupData(data);
      setTotpInput("");
      setMfaStep("qr");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Erreur lors de l'initialisation MFA");
    } finally { setBusy(false); }
  };

  const handleConfirm = async (e) => {
    e.preventDefault();
    if (totpInput.length !== 6) return;
    setBusy(true);
    try {
      await mfaConfirm(totpInput);
      toast.success("Double authentification activée");
      setMfaStep("idle");
      setSetupData(null);
      loadMe();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Code invalide");
    } finally { setBusy(false); }
  };

  const handleDisable = async (e) => {
    e.preventDefault();
    if (!disablePwd) return;
    setBusy(true);
    try {
      await mfaDisable(disablePwd);
      toast.success("Double authentification désactivée");
      setMfaStep("idle");
      setDisablePwd("");
      loadMe();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Mot de passe incorrect");
    } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h2 className="text-base font-bold text-gray-900">Mon compte</h2>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-gray-100 text-gray-400 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div className="px-6 py-5 space-y-5">
          {loading ? (
            <div className="flex justify-center py-8">
              <svg className="animate-spin w-6 h-6 text-blue-500" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
              </svg>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center shrink-0">
                  <span className="text-xl font-bold text-blue-700 uppercase">
                    {(me?.username || "?")[0]}
                  </span>
                </div>
                <div>
                  <p className="font-semibold text-gray-900">{me?.username}</p>
                  <p className="text-xs text-gray-500">{me?.role} · {me?.email || "Aucun email"}</p>
                  {me?.full_name && <p className="text-xs text-gray-400">{me.full_name}</p>}
                </div>
              </div>

              <div className="border border-gray-200 rounded-xl overflow-hidden">
                <div className="px-4 py-3 bg-gray-50 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round"
                        d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    <span className="text-sm font-semibold text-gray-800">Double authentification (MFA)</span>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${
                    me?.mfa_enabled ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"
                  }`}>
                    {me?.mfa_enabled ? "Activé" : "Désactivé"}
                  </span>
                </div>

                <div className="px-4 py-4 space-y-4">
                  {mfaStep === "idle" && (
                    <>
                      <p className="text-xs text-gray-500">
                        {me?.mfa_enabled
                          ? "Un code TOTP est demandé à chaque connexion. Compatible Google Authenticator, Authy, Bitwarden…"
                          : "Ajoutez une deuxième couche de sécurité. Un code de votre application mobile sera demandé à chaque connexion."}
                      </p>
                      {me?.mfa_enabled ? (
                        <button onClick={() => { setMfaStep("disable"); setDisablePwd(""); }}
                          className="w-full px-4 py-2 border border-red-200 text-red-600 rounded-lg text-sm font-medium hover:bg-red-50 transition-colors">
                          Désactiver le MFA
                        </button>
                      ) : (
                        <button onClick={handleSetup} disabled={busy}
                          className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                          {busy ? "Initialisation…" : "Activer le MFA"}
                        </button>
                      )}
                    </>
                  )}

                  {mfaStep === "qr" && setupData && (
                    <div className="space-y-4">
                      <p className="text-xs text-gray-600">
                        Scannez ce QR code avec <strong>Google Authenticator</strong>, <strong>Authy</strong> ou <strong>Bitwarden</strong>.
                      </p>
                      <div className="flex justify-center">
                        <img src={`data:image/png;base64,${setupData.qr_code_base64}`} alt="QR Code MFA"
                          className="w-40 h-40 rounded-xl border border-gray-200" />
                      </div>
                      <details className="text-xs text-gray-400">
                        <summary className="cursor-pointer hover:text-gray-600">Entrer le code manuellement</summary>
                        <p className="mt-1 font-mono break-all bg-gray-50 rounded p-2">{setupData.secret}</p>
                      </details>
                      <button onClick={() => { setMfaStep("confirm"); setTotpInput(""); }}
                        className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
                        J'ai scanné le QR code →
                      </button>
                      <button onClick={() => setMfaStep("idle")} className="w-full text-xs text-gray-400 hover:text-gray-600">Annuler</button>
                    </div>
                  )}

                  {mfaStep === "confirm" && (
                    <form onSubmit={handleConfirm} className="space-y-3">
                      <p className="text-xs text-gray-600">Saisissez le code affiché dans votre application pour confirmer l'activation.</p>
                      <input type="text" inputMode="numeric" maxLength={6} value={totpInput}
                        onChange={(e) => setTotpInput(e.target.value.replace(/\D/g, ""))}
                        placeholder="000000" autoFocus
                        className="w-full border border-gray-300 rounded-lg px-4 py-3 text-center text-xl font-mono tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-500" />
                      <button type="submit" disabled={busy || totpInput.length !== 6}
                        className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        {busy ? "Activation…" : "Confirmer et activer"}
                      </button>
                      <button type="button" onClick={() => setMfaStep("qr")} className="w-full text-xs text-gray-400 hover:text-gray-600">
                        Retour au QR code
                      </button>
                    </form>
                  )}

                  {mfaStep === "disable" && (
                    <form onSubmit={handleDisable} className="space-y-3">
                      <p className="text-xs text-gray-600">Entrez votre mot de passe pour confirmer la désactivation du MFA.</p>
                      <input type="password" value={disablePwd} onChange={(e) => setDisablePwd(e.target.value)}
                        placeholder="Mot de passe actuel" autoFocus
                        className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-400" />
                      <button type="submit" disabled={busy || !disablePwd}
                        className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
                        {busy ? "Désactivation…" : "Confirmer la désactivation"}
                      </button>
                      <button type="button" onClick={() => setMfaStep("idle")} className="w-full text-xs text-gray-400 hover:text-gray-600">Annuler</button>
                    </form>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Layout principal ─────────────────────────────────────────────────────────
export default function DashboardLayout() {
  const { signOut, user, sessionWarning } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [showMonCompte, setShowMonCompte] = useState(false);
  const [pendingCount, setPendingCount]   = useState(0);

  // État collapse sidebar — persisté en localStorage
  const [collapsed, setCollapsed] = useState(() =>
    localStorage.getItem("repod_sidebar_collapsed") === "true"
  );

  // Horloge topbar — mise à jour chaque minute
  const [clock, setClock] = useState(() =>
    new Date().toLocaleString("fr-FR", {
      day: "2-digit", month: "2-digit", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    })
  );
  useEffect(() => {
    const id = setInterval(() => {
      setClock(new Date().toLocaleString("fr-FR", {
        day: "2-digit", month: "2-digit", year: "numeric",
        hour: "2-digit", minute: "2-digit",
      }));
    }, 60_000);
    return () => clearInterval(id);
  }, []);

  const toggleCollapsed = () => {
    setCollapsed(v => {
      const next = !v;
      localStorage.setItem("repod_sidebar_collapsed", String(next));
      return next;
    });
  };

  const handleLogout = () => { signOut(); navigate("/login"); };

  // Badge "Promotions en attente" — polling toutes les 30s (admin/maintainer uniquement)
  useEffect(() => {
    const isPrivileged = user?.role && ["admin", "maintainer"].includes(user.role);
    if (!isPrivileged) return;
    const fetch = () =>
      listPendingPromotions("pending", 1, 1)
        .then((d) => setPendingCount(d.total || 0))
        .catch(() => {});
    fetch();
    const id = setInterval(fetch, 30_000);
    return () => clearInterval(id);
  }, [user]);

  // Métadonnées de la page courante
  const currentPage  = PAGE_TITLES[location.pathname] || { label: "repod", icon: "Dashboard" };
  const currentSection = PAGE_SECTION[location.pathname] || null;
  const CurrentPageIcon = Icon[currentPage.icon];

  const userInitial = (user?.username || user?.sub || "A")[0].toUpperCase();

  return (
    <div className="flex h-screen bg-slate-100 font-sans overflow-hidden">

      {/* ════════════════════════════════════════════════════════════ SIDEBAR ══ */}
      <aside
        className={`${collapsed ? "w-14" : "w-56"} bg-navy-900 flex flex-col shrink-0 shadow-2xl z-20
                    transition-[width] duration-200 ease-in-out overflow-hidden`}
      >
        {/* Logo / Brand */}
        <div className={`flex items-center border-b border-navy-800 shrink-0 h-12 ${
          collapsed ? "justify-center px-0" : "gap-3 px-4"
        }`}>
          <img src="/logo.png" alt="Repod" className="w-10 h-10 object-contain shrink-0" />
          {!collapsed && (
            <p className="text-white font-black text-base tracking-widest">RepoD</p>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-2 py-2 overflow-y-auto overflow-x-hidden space-y-px">

          <NavItem to="/" end icon={<Icon.Dashboard />} label="Tableau de bord" collapsed={collapsed} />

          {/* ── Groupe Dépôt ── */}
          <NavGroup label="Dépôt" paths={["/packages","/upload","/import","/sources","/dockerfile","/distributions"]} collapsed={collapsed}>
            <NavItem to="/packages"      icon={<Icon.Package />}     label="Paquets"           collapsed={collapsed} />
            <NavItem to="/upload"        icon={<Icon.Upload />}       label="Déposer"           perm="nav_upload"   collapsed={collapsed} />
            <NavItem to="/import"        icon={<Icon.Import />}       label="Importer"          perm="nav_import"   collapsed={collapsed} />
            <NavItem to="/sources"       icon={<Icon.Sources />}      label="Sources"           perm="nav_import"   collapsed={collapsed} />
            <NavItem to="/dockerfile"    icon={<Icon.Dockerfile />}   label="Analyseur Dockerfile"  perm="nav_import"   collapsed={collapsed} />
            <NavItem to="/distributions" icon={<Icon.Distribution />} label="Distributions"                         collapsed={collapsed} />
          </NavGroup>

          {/* ── Groupe Sécurité ── */}
          <NavGroup label="Sécurité" paths={["/security","/promotions","/audit"]} collapsed={collapsed}>
            <NavItem to="/security"   icon={<Icon.CveDecision />} label="Décisions CVE"   perm="nav_security" collapsed={collapsed} />
            <NavItem to="/promotions" icon={<Icon.Promotion />}   label="Promotions"      perm="nav_security" badge={pendingCount || 0} collapsed={collapsed} />
            <NavItem to="/audit"      icon={<Icon.Audit />}       label="Journal d'audit" perm="nav_audit"    collapsed={collapsed} />
          </NavGroup>

          {/* ── Groupe Clients ── */}
          <NavGroup label="Clients" paths={["/setup"]} collapsed={collapsed}>
            <NavItem to="/setup"     icon={<Icon.ClientSetup />} label="Configuration"    collapsed={collapsed} />
          </NavGroup>

          {/* ── Groupe Administration ── */}
          <NavGroup label="Administration" paths={["/downloads","/supervision","/logs","/users","/groups","/roles","/settings","/templates"]} collapsed={collapsed}>
            <NavItem to="/downloads"   icon={<Icon.Download />} label="Téléchargements"   perm="nav_downloads" collapsed={collapsed} />
            <NavItem to="/supervision" icon={<Icon.Health />}   label="Supervision"       perm="nav_health"    collapsed={collapsed} />
            <NavItem to="/logs"        icon={<Icon.Logs />}     label="Logs système"      perm="nav_settings"  collapsed={collapsed} />
            <NavItem to="/users"       icon={<Icon.Users />}    label="Utilisateurs"      perm="nav_users"     collapsed={collapsed} />
            <NavItem to="/groups"      icon={<Icon.Group />}    label="Groupes"           perm="nav_users"     collapsed={collapsed} />
            <NavItem to="/roles"       icon={<Icon.Shield />}   label="Rôles"             perm="nav_users"     collapsed={collapsed} />
            <NavItem to="/settings"    icon={<Icon.Settings />} label="Paramètres"        perm="nav_settings"  collapsed={collapsed} />
            <NavItem to="/templates"   icon={<Icon.Email />}    label="Templates email"   perm="nav_settings"  collapsed={collapsed} />
          </NavGroup>
        </nav>

        {/* ── Bouton collapse (avant le footer) ── */}
        <div className="px-2 pb-1">
          <button
            onClick={toggleCollapsed}
            title={collapsed ? "Agrandir le menu" : "Réduire le menu"}
            className={`flex items-center w-full rounded-lg text-[11px] font-medium
                        text-navy-400 hover:bg-navy-800/70 hover:text-slate-400
                        transition-colors duration-150 ${
                          collapsed ? "justify-center px-0 py-2" : "gap-2 px-3 py-2"
                        }`}
          >
            <span className="w-3.5 h-3.5 shrink-0">
              {collapsed ? <Icon.ChevronRight /> : <Icon.ChevronLeft />}
            </span>
            {!collapsed && <span>Réduire</span>}
          </button>
        </div>

        {/* ── Footer utilisateur ── */}
        <div className="px-2 py-2 border-t border-navy-800 space-y-0.5">
          {/* Bouton "Mon compte" */}
          <button
            onClick={() => setShowMonCompte(true)}
            title={collapsed ? `${user?.username || "Mon compte"} — paramètres` : "Mon compte"}
            className={`flex items-center w-full rounded-lg hover:bg-navy-800/60 transition-colors group
                        ${collapsed ? "justify-center px-0 py-2" : "gap-2.5 px-3 py-2"}`}
          >
            {/* Avatar */}
            <div className="w-7 h-7 rounded-full bg-navy-700 border border-navy-600 flex items-center justify-center shrink-0 group-hover:border-blue-500/50 transition-colors">
              <span className="text-xs font-bold text-slate-300">{userInitial}</span>
            </div>
            {/* Infos (masquées en mode collapsed) */}
            {!collapsed && (
              <>
                <div className="min-w-0 flex-1 text-left">
                  <p className="text-slate-200 text-xs font-semibold truncate">{user?.username || user?.sub || "admin"}</p>
                  <p className="text-[10px] text-navy-500 truncate">{user?.email || ""}</p>
                </div>
                <svg className="w-3.5 h-3.5 text-navy-500 group-hover:text-slate-400 transition-colors shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
              </>
            )}
          </button>

          {showMonCompte && <MonCompteModal onClose={() => setShowMonCompte(false)} />}

          {/* Déconnexion */}
          <button
            onClick={handleLogout}
            title={collapsed ? "Déconnexion" : undefined}
            className={`flex items-center w-full rounded-lg text-xs font-medium
                        text-slate-500 hover:bg-red-900/30 hover:text-red-400 transition-colors
                        ${collapsed ? "justify-center px-0 py-2" : "gap-2.5 px-3 py-2"}`}
          >
            <span className="w-4 h-4 shrink-0"><Icon.Logout /></span>
            {!collapsed && <span>Déconnexion</span>}
          </button>
        </div>
      </aside>

      {/* ════════════════════════════════════════════════════════════ MAIN ════ */}
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">

        {/* ── Topbar ── */}
        <header className="h-12 bg-white border-b border-slate-200 flex items-center justify-between px-5 shrink-0 z-10 shadow-sm">

          {/* Gauche : breadcrumb */}
          <div className="flex items-center gap-1.5 text-sm min-w-0">
            {currentSection ? (
              // Pages avec section : Section › Page
              <>
                <span className="w-3.5 h-3.5 text-slate-400 shrink-0">
                  {CurrentPageIcon && <CurrentPageIcon />}
                </span>
                <span className="text-slate-400 text-xs font-medium">{currentSection}</span>
                <span className="text-slate-300 shrink-0">
                  <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
                    <polyline points="9 18 15 12 9 6"/>
                  </svg>
                </span>
                <span className="font-semibold text-slate-700 truncate">{currentPage.label}</span>
              </>
            ) : (
              // Dashboard ou page isolée
              <>
                <span className="w-3.5 h-3.5 text-slate-400 shrink-0">
                  {CurrentPageIcon && <CurrentPageIcon />}
                </span>
                <span className="font-semibold text-slate-700">{currentPage.label}</span>
              </>
            )}
          </div>

          {/* Centre : bannière Enterprise */}
          <a
            href="https://getrepod.com/#pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden lg:flex items-center gap-1.5 text-xs font-medium text-purple-700 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded-full px-3 py-1 transition-colors"
          >
            <span className="text-[10px] font-bold tracking-widest uppercase text-purple-700 bg-purple-100 px-1.5 py-0.5 rounded-full">
              Enterprise
            </span>
            <span>Conformité Patch, inventaire de parc, SSO/LDAP et plus — Découvrir Repod Enterprise</span>
          </a>

          {/* Droite : date/heure + outils */}
          <div className="flex items-center gap-3 shrink-0">
            <span className="text-xs text-slate-400 font-mono hidden sm:block">{clock}</span>

            {/* Cloche */}
            <button className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors" title="Notifications">
              <span className="w-4 h-4"><Icon.Bell /></span>
            </button>

            <HelpMenu />

            <div className="w-px h-5 bg-slate-200" />

            {/* Indicateur connexion — texte seul, sans pastille */}
            <span className="hidden md:block text-xs text-slate-400 font-medium">Connecté</span>
          </div>
        </header>

        {/* ── Contenu de la page ── */}
        <main className="flex-1 overflow-y-auto flex flex-col bg-slate-50">
          {sessionWarning && (
            <div className="bg-amber-50 border-b border-amber-200 px-4 py-2 text-center text-sm text-amber-800 font-medium">
              Votre session expire dans 5 minutes. Bougez la souris ou cliquez pour rester connect&eacute;.
            </div>
          )}
          <Outlet />
        </main>
      </div>
    </div>
  );
}
