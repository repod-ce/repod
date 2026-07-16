import React from "react";
import { useEdition } from "../hooks/useEdition";

/**
 * Enveloppe une section/page réservée à l'édition Enterprise.
 *
 * En Community : affiche le contenu grisé (non interactif) avec un bandeau
 * "Fonctionnalité Enterprise" + CTA vers repod.getautoflow.dev/#pricing, pour que l'utilisateur
 * sache que la fonctionnalité existe sans pouvoir l'utiliser.
 *
 * En Enterprise : affiche children normalement.
 *
 * Props :
 *   feature : nom lisible de la fonctionnalité (ex. "Inventaire & scan SSH")
 *   children: contenu de la page/section (rendu grisé en Community)
 */
export default function EnterpriseLock({ feature, children }) {
  const { isEnterprise, loading } = useEdition();

  if (loading || isEnterprise) {
    return children;
  }

  return (
    <div className="relative">
      <div className="pointer-events-none select-none opacity-40 blur-[1px]">
        {children}
      </div>
      <div className="absolute inset-0 flex items-center justify-center bg-white/60 backdrop-blur-sm">
        <div className="max-w-sm text-center bg-white border border-slate-200 shadow-xl rounded-2xl px-6 py-5">
          <span className="inline-block text-[10px] font-bold tracking-widest uppercase text-purple-700 bg-purple-100 px-2 py-1 rounded-full mb-2">
            Enterprise
          </span>
          <p className="text-sm font-semibold text-slate-800 mb-1">
            {feature} fait partie de l'édition Enterprise
          </p>
          <p className="text-xs text-slate-500 mb-4">
            Disponible avec une licence Enterprise : passez en mode multi-utilisateurs,
            conformité avancée et gestion de parc.
          </p>
          <a
            href="https://repod.getautoflow.dev/#pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center text-xs font-bold text-white bg-purple-600 hover:bg-purple-700 rounded-lg px-4 py-2 transition-colors"
          >
            Découvrir Repod Enterprise
          </a>
        </div>
      </div>
    </div>
  );
}
