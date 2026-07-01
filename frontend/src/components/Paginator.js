/**
 * Paginator — Boutons Précédent / Suivant réutilisables.
 *
 * Props :
 *   page          {number}   page courante (1-indexé)
 *   pages         {number}   nombre total de pages
 *   total         {number}   nombre total d'éléments
 *   perPage       {number}   éléments par page
 *   onPageChange  {function} appelée avec le nouveau numéro de page
 *   loading       {boolean}  désactive les boutons pendant le chargement
 *
 * Renvoie null si pages <= 1.
 */
export default function Paginator({ page, pages, total, perPage, onPageChange, loading = false }) {
  if (!pages || pages <= 1) return null;

  const start = Math.min((page - 1) * perPage + 1, total);
  const end   = Math.min(page * perPage, total);

  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 bg-gray-50/60">
      <span className="text-xs text-gray-500">
        {start}–{end} sur <span className="font-medium text-gray-700">{total}</span> résultat{total !== 1 ? "s" : ""}
      </span>

      <div className="flex items-center gap-1.5">
        <button
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1 || loading}
          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-gray-200
                     text-xs font-medium text-gray-600 bg-white
                     hover:bg-gray-50 hover:border-gray-300
                     disabled:opacity-40 disabled:cursor-not-allowed
                     transition-colors"
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24"
               stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Préc.
        </button>

        <span className="text-xs text-gray-500 font-medium px-2 tabular-nums">
          {page} / {pages}
        </span>

        <button
          onClick={() => onPageChange(page + 1)}
          disabled={page >= pages || loading}
          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-gray-200
                     text-xs font-medium text-gray-600 bg-white
                     hover:bg-gray-50 hover:border-gray-300
                     disabled:opacity-40 disabled:cursor-not-allowed
                     transition-colors"
        >
          Suiv.
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24"
               stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
        </button>
      </div>
    </div>
  );
}
