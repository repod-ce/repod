import { useState, useRef, useEffect } from "react";

/**
 * HelpTooltip — icône info circulaire avec bulle contextuelle au survol.
 *
 * Usage :
 *   <HelpTooltip text="La clé GPG signe tous vos paquets." />
 *   <HelpTooltip text="..." position="right" />
 */
export default function HelpTooltip({ text, position = "top", className = "" }) {
  const [visible, setVisible] = useState(false);
  const ref = useRef(null);

  // Fermer si clic extérieur
  useEffect(() => {
    if (!visible) return;
    const handler = (e) => { if (ref.current && !ref.current.contains(e.target)) setVisible(false); };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [visible]);

  const posClass = {
    top:    "bottom-full left-1/2 -translate-x-1/2 mb-2",
    bottom: "top-full  left-1/2 -translate-x-1/2 mt-2",
    left:   "right-full top-1/2 -translate-y-1/2  mr-2",
    right:  "left-full  top-1/2 -translate-y-1/2  ml-2",
  }[position] || "bottom-full left-1/2 -translate-x-1/2 mb-2";

  const arrowClass = {
    top:    "top-full  left-1/2 -translate-x-1/2 border-t-slate-800",
    bottom: "bottom-full left-1/2 -translate-x-1/2 border-b-slate-800",
    left:   "left-full  top-1/2 -translate-y-1/2 border-l-slate-800",
    right:  "right-full top-1/2 -translate-y-1/2 border-r-slate-800",
  }[position] || "top-full left-1/2 -translate-x-1/2 border-t-slate-800";

  return (
    <span ref={ref} className={`relative inline-flex items-center ${className}`}>
      <button
        type="button"
        onMouseEnter={() => setVisible(true)}
        onMouseLeave={() => setVisible(false)}
        onClick={() => setVisible(v => !v)}
        className="w-4 h-4 text-slate-400 hover:text-slate-600 transition-colors cursor-help"
        aria-label="Aide contextuelle"
      >
        {/* Icône info-circle */}
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
             strokeLinecap="round" strokeLinejoin="round" className="w-full h-full">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8"  x2="12.01" y2="8" />
        </svg>
      </button>

      {visible && (
        <span className={`absolute ${posClass} z-50 w-64 pointer-events-none`}>
          {/* Bulle */}
          <span className="block bg-slate-800 text-white text-xs leading-relaxed rounded-lg px-3 py-2 shadow-xl">
            {text}
          </span>
          {/* Flèche */}
          <span className={`absolute ${arrowClass} w-0 h-0 border-4 border-transparent`} />
        </span>
      )}
    </span>
  );
}
