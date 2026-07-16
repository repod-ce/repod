import { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { resetPasswordWithToken } from "../api";

export default function ResetPasswordPage() {
  const [searchParams]          = useSearchParams();
  const navigate                = useNavigate();
  const token                   = searchParams.get("token") || "";

  const [password, setPassword]   = useState("");
  const [confirm, setConfirm]     = useState("");
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState("");
  const [success, setSuccess]     = useState(false);

  // Token manquant dans l'URL
  useEffect(() => {
    if (!token) setError("Lien invalide. Refaites une demande depuis la page de connexion.");
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (password.length < 8) {
      setError("Le mot de passe doit contenir au moins 8 caractères.");
      return;
    }
    if (password !== confirm) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }

    setLoading(true);
    try {
      await resetPasswordWithToken(token, password);
      setSuccess(true);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      setError(detail || "Lien invalide ou expiré. Refaites une demande.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-sm">

        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-blue-600 rounded-xl mb-4">
            <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-gray-900">Nouveau mot de passe</h1>
          <p className="text-sm text-gray-500 mt-1">APT Repo Manager</p>
        </div>

        {success ? (
          <div className="text-center space-y-4">
            <div className="inline-flex items-center justify-center w-12 h-12 bg-green-100 rounded-full">
              <svg className="w-6 h-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7"/>
              </svg>
            </div>
            <p className="text-sm font-medium text-gray-800">Mot de passe modifié !</p>
            <p className="text-xs text-gray-500">Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.</p>
            <button
              onClick={() => navigate("/login")}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white text-sm
                         font-medium py-2 rounded-lg transition-colors mt-2"
            >
              Se connecter
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Nouveau mot de passe
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(""); }}
                placeholder="8 caractères minimum"
                autoFocus
                autoComplete="new-password"
                className={`w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2
                  focus:ring-blue-500 ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Confirmer le mot de passe
              </label>
              <input
                type="password"
                value={confirm}
                onChange={(e) => { setConfirm(e.target.value); setError(""); }}
                placeholder="••••••••"
                autoComplete="new-password"
                className={`w-full border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2
                  focus:ring-blue-500 ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
              />
            </div>

            {/* Indicateur de force */}
            {password.length > 0 && (
              <PasswordStrength password={password} />
            )}

            {/* Erreur inline */}
            {error && (
              <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2.5">
                <svg className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-9v4a1 1 0 102 0V9a1 1 0 10-2 0zm0-4a1 1 0 112 0 1 1 0 01-2 0z" clipRule="evenodd"/>
                </svg>
                <p className="text-sm text-red-700">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !token}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                         disabled:cursor-not-allowed text-white font-medium py-2
                         rounded-lg transition-colors text-sm"
            >
              {loading ? "Enregistrement…" : "Enregistrer le mot de passe"}
            </button>

            <button
              type="button"
              onClick={() => navigate("/login")}
              className="w-full text-sm text-gray-500 hover:text-gray-700 hover:underline"
            >
              Retour à la connexion
            </button>
          </form>
        )}
      </div>
    </div>
  );
}


// ── Indicateur de force du mot de passe ───────────────────────────────────────
function PasswordStrength({ password }) {
  const checks = [
    { label: "8 caractères min.", ok: password.length >= 8 },
    { label: "Majuscule",         ok: /[A-Z]/.test(password) },
    { label: "Chiffre",           ok: /[0-9]/.test(password) },
    { label: "Caractère spécial", ok: /[^A-Za-z0-9]/.test(password) },
  ];
  const score = checks.filter((c) => c.ok).length;
  const colors = ["bg-red-400", "bg-orange-400", "bg-yellow-400", "bg-green-400", "bg-green-500"];

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {[0, 1, 2, 3].map((i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors ${
              i < score ? colors[score] : "bg-gray-200"
            }`}
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-x-3 gap-y-1">
        {checks.map((c) => (
          <span key={c.label} className={`text-xs flex items-center gap-1 ${c.ok ? "text-green-600" : "text-gray-400"}`}>
            {c.ok ? (
              <svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            ) : (
              <svg className="w-3 h-3 inline" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/></svg>
            )} {c.label}
          </span>
        ))}
      </div>
    </div>
  );
}
