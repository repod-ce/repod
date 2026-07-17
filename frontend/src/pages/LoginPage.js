import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import toast from "react-hot-toast";
import { login, mfaAuthenticate, requestPasswordReset, getSetupStatus, runSetup, getSetupPreflight } from "../api";
import { useAuth } from "../context/AuthContext";

export default function LoginPage() {
  const [username, setUsername]         = useState("");
  const [password, setPassword]         = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState("");
  const [showForgot, setShowForgot]     = useState(false);

  const [mfaToken, setMfaToken] = useState(null);
  const [totpCode, setTotpCode] = useState("");

  const [needsSetup, setNeedsSetup] = useState(null);

  useEffect(() => {
    let cancelled = false;
    let retries = 0;
    const check = () => {
      getSetupStatus()
        .then((data) => { if (!cancelled) setNeedsSetup(!!data.needs_setup); })
        .catch(() => {
          if (!cancelled && retries < 10) {
            retries++;
            setTimeout(check, 3000);
          } else if (!cancelled) {
            setNeedsSetup(false);
          }
        });
    };
    check();
    return () => { cancelled = true; };
  }, []);

  const { signIn } = useAuth();
  const navigate   = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!username || !password) { setError("Veuillez remplir tous les champs."); return; }
    setLoading(true);
    try {
      const { data } = await login(username, password);
      if (data.mfa_required && data.mfa_token) {
        setMfaToken(data.mfa_token);
        setTotpCode("");
      } else {
        signIn(data.access_token);
        navigate("/");
      }
    } catch (err) {
      const status = err?.response?.status;
      if (status === 401)                                     setError("Identifiant ou mot de passe incorrect.");
      else if (status === 429)                                setError("Trop de tentatives. Réessayez dans quelques minutes.");
      else if (!err?.response || status === 502 || status === 503) setError("Le serveur démarre. Patientez quelques secondes.");
      else                                                    setError(`Erreur serveur (${status}).`);
    } finally { setLoading(false); }
  };

  const handleMfaSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (!totpCode || totpCode.length !== 6) { setError("Saisissez le code à 6 chiffres."); return; }
    setLoading(true);
    try {
      const data = await mfaAuthenticate(mfaToken, totpCode);
      signIn(data.access_token);
      navigate("/");
    } catch (err) {
      const status = err?.response?.status;
      setError(status === 401 ? "Code invalide ou expiré." : "Erreur lors de la vérification.");
    } finally { setLoading(false); }
  };

  // ── Chargement ───────────────────────────────────────────────────────────────
  if (needsSetup === null) {
    return (
      <div className="h-screen flex items-center justify-center bg-gray-50">
        <svg className="animate-spin w-7 h-7 text-blue-500" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
        </svg>
      </div>
    );
  }

  // ── Wizard de première installation ─────────────────────────────────────────
  if (needsSetup) {
    return (
      <div className="h-screen flex items-center justify-center bg-gray-50 p-4 overflow-hidden">
        <SetupWizard
          onDone={(accessToken) => { signIn(accessToken); navigate("/"); }}
        />
      </div>
    );
  }

  // ── TOTP ─────────────────────────────────────────────────────────────────────
  if (mfaToken) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-white">
        <div className="w-full max-w-sm">
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="text-center mb-5">
              <img src="/logo.png" alt="Repod" className="w-10 h-10 mx-auto mb-2" />
              <h2 className="text-lg font-bold text-gray-900">Vérification en deux étapes</h2>
              <p className="text-sm text-gray-500 mt-1">
                Ouvrez votre application d'authentification et saisissez le code à 6 chiffres.
              </p>
            </div>
            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Code TOTP</label>
                <input
                  type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
                  value={totpCode}
                  onChange={(e) => { setTotpCode(e.target.value.replace(/\D/g, "")); setError(""); }}
                  className={`w-full border rounded-lg px-4 py-3 text-center text-xl font-mono tracking-widest
                    focus:outline-none focus:ring-2 focus:ring-blue-500
                    ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                  placeholder="000000" autoFocus autoComplete="one-time-code"
                />
              </div>
              {error && <ErrorBanner msg={error} />}
              <button type="submit" disabled={loading || totpCode.length !== 6}
                className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                           disabled:cursor-not-allowed text-white font-medium py-2.5 rounded-lg
                           transition-colors text-sm">
                {loading ? <Spinner label="Vérification…" /> : "Vérifier le code"}
              </button>
              <button type="button"
                onClick={() => { setMfaToken(null); setError(""); setTotpCode(""); }}
                className="w-full text-sm text-gray-500 hover:text-gray-700 py-1">
                ← Retour à la connexion
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  // ── Formulaire de connexion ───────────────────────────────────────────────────
  return (
    <div className="min-h-screen flex flex-col items-center bg-white px-4 pt-12 pb-6">
      <div className="w-full max-w-md">

        <div className="text-center mb-6">
          <img src="/logo.png" alt="Repod" className="w-20 h-20 mx-auto mb-4" />
          <h1 className="text-xl font-bold text-gray-900">Se connecter à RepoD</h1>
          <p className="text-sm text-gray-500 mt-1">Accédez à votre espace de dépôt privé</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-semibold text-gray-700 mb-1.5">
              Nom d'utilisateur
            </label>
            <input type="text" value={username}
              onChange={(e) => { setUsername(e.target.value); setError(""); }}
              className={`w-full border-2 rounded-lg px-3.5 py-2 text-sm focus:outline-none focus:ring-2
                focus:ring-blue-500 focus:border-blue-500
                ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
              autoFocus autoComplete="username" />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-sm font-semibold text-gray-700">Mot de passe</label>
              <button type="button"
                onClick={() => { setShowForgot(!showForgot); setError(""); }}
                className="text-xs text-blue-600 hover:text-blue-700">
                Mot de passe oublié ?
              </button>
            </div>
            <div className="relative">
              <input type={showPassword ? "text" : "password"} value={password}
                onChange={(e) => { setPassword(e.target.value); setError(""); }}
                className={`w-full border-2 rounded-lg px-3.5 py-2 pr-10 text-sm focus:outline-none focus:ring-2
                  focus:ring-blue-500 focus:border-blue-500
                  ${error ? "border-red-400 bg-red-50" : "border-gray-300"}`}
                autoComplete="current-password" />
              <button type="button" tabIndex={-1}
                onClick={() => setShowPassword((v) => !v)}
                className="absolute inset-y-0 right-0 flex items-center px-2.5 text-gray-400 hover:text-gray-600 transition-colors"
                aria-label={showPassword ? "Masquer le mot de passe" : "Afficher le mot de passe"}>
                {showPassword ? <IconEyeOff /> : <IconEye />}
              </button>
            </div>
          </div>

          {error && <ErrorBanner msg={error} />}

          <button type="submit" disabled={loading}
            className="w-full bg-blue-600 hover:bg-blue-700 active:bg-blue-800 disabled:opacity-50
                       disabled:cursor-not-allowed text-white font-semibold py-2 rounded-lg
                       transition-colors text-sm mt-1">
            {loading ? <Spinner label="Connexion..." /> : "Connexion"}
          </button>
        </form>

        {showForgot && (
          <div className="mt-3">
            <ForgotPasswordPanel onClose={() => setShowForgot(false)} />
          </div>
        )}
      </div>
    </div>
  );
}


// ── Shared helpers ─────────────────────────────────────────────────────────────

function Spinner({ label }) {
  return (
    <span className="flex items-center justify-center gap-2">
      <svg className="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
      </svg>
      {label}
    </span>
  );
}

function ErrorBanner({ msg }) {
  return (
    <div className="flex items-start gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-2.5">
      <svg className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm-1-9v4a1 1 0 102 0V9a1 1 0 10-2 0zm0-4a1 1 0 112 0 1 1 0 01-2 0z" clipRule="evenodd"/>
      </svg>
      <p className="text-sm text-red-700">{msg}</p>
    </div>
  );
}

function IconEye() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
    </svg>
  );
}

function IconEyeOff() {
  return (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"/>
    </svg>
  );
}


// ── Preflight labels & icons ───────────────────────────────────────────────────

const PREFLIGHT_LABELS = {
  database:   "Base de données",
  disk_space: "Espace disque",
  clamav:     "Antivirus (ClamAV)",
  grype:      "Scanner CVE (Grype)",
  secrets:    "Secrets applicatifs",
  tls:        "Certificat TLS",
};

const PREFLIGHT_ICONS = {
  database: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 7c0-1.657 3.582-3 8-3s8 1.343 8 3M4 7v5c0 1.657 3.582 3 8 3s8-1.343 8-3V7M4 12v5c0 1.657 3.582 3 8 3s8-1.343 8-3v-5"/>
    </svg>
  ),
  disk_space: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/>
    </svg>
  ),
  clamav: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
    </svg>
  ),
  grype: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/>
    </svg>
  ),
  secrets: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"/>
    </svg>
  ),
  tls: (
    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"/>
    </svg>
  ),
};


// ── Diagnostic pré-installation ───────────────────────────────────────────────

function PreflightChecks() {
  const [checks, setChecks] = useState(null);
  const [errMsg, setErrMsg] = useState("");

  useEffect(() => {
    getSetupPreflight()
      .then((data) => setChecks(data.checks))
      .catch(() => setErrMsg("Impossible de contacter le serveur."));
  }, []);

  if (errMsg) {
    return (
      <div className="flex items-center gap-2 bg-yellow-50 border border-yellow-200 rounded-lg px-3 py-2 text-xs text-yellow-700">
        <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
        </svg>
        <span>{errMsg}</span>
      </div>
    );
  }

  if (!checks) {
    return (
      <div className="flex items-center gap-2 text-gray-400 text-xs py-3">
        <svg className="animate-spin w-3.5 h-3.5" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
        </svg>
        Diagnostic en cours…
      </div>
    );
  }

  return (
    <div className="space-y-1">
      {Object.entries(checks).map(([key, check]) => (
        <div key={key} className="flex items-center gap-2 py-1.5">
          <div className={`flex-shrink-0 w-4 h-4 rounded flex items-center justify-center
            ${check.ok ? "bg-green-100 text-green-600" : "bg-red-100 text-red-500"}`}>
            {check.ok ? (
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
              </svg>
            ) : (
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
              </svg>
            )}
          </div>
          <div className={`flex-shrink-0 ${check.ok ? "text-gray-400" : "text-red-400"}`}>
            {PREFLIGHT_ICONS[key] || null}
          </div>
          <span className={`text-xs font-medium flex-1 min-w-0 ${check.ok ? "text-gray-700" : "text-red-700"}`}>
            {PREFLIGHT_LABELS[key] || key}
          </span>
        </div>
      ))}
    </div>
  );
}


// ── Assistant de première installation ────────────────────────────────────────

function SetupWizard({ onDone }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [email,    setEmail]    = useState("");
  const [appUrl,   setAppUrl]   = useState(window.location.origin);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    if (username.trim().length < 3) { setError("Nom d'utilisateur : 3 caractères minimum."); return; }
    if (password.length < 8)        { setError("Mot de passe : 8 caractères minimum."); return; }
    if (password !== confirm)        { setError("Les mots de passe ne correspondent pas."); return; }
    setLoading(true);
    try {
      const data = await runSetup({
        admin_username: username.trim(),
        admin_password: password,
        admin_email:    email.trim(),
        app_url:        appUrl.trim(),
      });
      onDone(data.access_token);
    } catch (err) {
      const status = err?.response?.status;
      setError(status === 409
        ? "Déjà configuré. Rechargez la page."
        : err?.response?.data?.detail || "Impossible de finaliser la configuration.");
    } finally { setLoading(false); }
  };

  return (
    <div className="bg-white rounded-2xl border border-gray-200 shadow-sm w-full max-w-3xl overflow-hidden">
      <div className="flex min-h-0">

        {/* ── Panneau gauche ─── */}
        <div className="w-64 flex-shrink-0 bg-gray-50 border-r border-gray-200 flex flex-col p-6">
          {/* Logo */}
          <div className="flex items-center gap-3 mb-6">
            <img src="/logo.png" alt="RepoD" className="w-9 h-9 flex-shrink-0" />
            <div>
              <p className="text-sm font-bold text-gray-900 leading-none">RepoD</p>
              <p className="text-[10px] text-gray-400 mt-0.5 uppercase tracking-wide">Community Edition</p>
            </div>
          </div>

          {/* Diagnostic */}
          <div className="flex-1 min-h-0">
            <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-widest mb-3">
              Diagnostic système
            </p>
            <PreflightChecks />
          </div>

          {/* Mention bas */}
          <p className="text-[10px] text-gray-300 mt-4 leading-relaxed">
            Vérifiez que tous les services sont actifs avant de continuer.
          </p>
        </div>

        {/* ── Panneau droit ─── */}
        <div className="flex-1 min-w-0 flex flex-col p-7">
          <div className="mb-5">
            <h1 className="text-lg font-bold text-gray-900">Configuration initiale</h1>
            <p className="text-xs text-gray-400 mt-0.5">Créez votre compte administrateur pour démarrer.</p>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-4 flex-1">

            {/* Compte admin */}
            <fieldset>
              <legend className="flex items-center gap-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2.5">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                </svg>
                Compte administrateur
              </legend>

              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Nom d'utilisateur</label>
                  <input type="text" value={username}
                    onChange={(e) => { setUsername(e.target.value); setError(""); }}
                    className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm
                               focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    autoFocus autoComplete="username" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Mot de passe</label>
                    <input type="password" value={password}
                      onChange={(e) => { setPassword(e.target.value); setError(""); }}
                      className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm
                                 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="8 car. min." autoComplete="new-password" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Confirmer</label>
                    <input type="password" value={confirm}
                      onChange={(e) => { setConfirm(e.target.value); setError(""); }}
                      className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm
                                 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="Répétez" autoComplete="new-password" />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    E-mail <span className="text-gray-300 font-normal">(optionnel)</span>
                  </label>
                  <input type="email" value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm
                               focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="admin@example.com" autoComplete="email" />
                </div>
              </div>
            </fieldset>

            <div className="border-t border-gray-100" />

            {/* Configuration */}
            <fieldset>
              <legend className="flex items-center gap-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2.5">
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                </svg>
                Configuration
              </legend>

              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">URL publique</label>
                <input type="url" value={appUrl}
                  onChange={(e) => setAppUrl(e.target.value)}
                  className="w-full border border-gray-200 rounded-xl px-3 py-2 text-sm
                             focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="https://repod.example.com" />
                <p className="text-[10px] text-gray-400 mt-1">Utilisée pour les notifications. Modifiable dans les paramètres.</p>
              </div>
            </fieldset>

            {error && <ErrorBanner msg={error} />}

            <button type="submit" disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-40
                         text-white font-semibold py-2.5 rounded-xl transition-colors text-sm mt-auto">
              {loading ? <Spinner label="Installation en cours…" /> : "Finaliser l'installation"}
            </button>
          </form>
        </div>

      </div>
    </div>
  );
}


// ── Reset mot de passe ────────────────────────────────────────────────────────
function ForgotPasswordPanel({ onClose }) {
  const [username, setUsername] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [sent,     setSent]     = useState(false);

  const handleRequest = async (e) => {
    e.preventDefault();
    if (!username.trim()) return;
    setLoading(true);
    try {
      await requestPasswordReset(username.trim());
      setSent(true);
    } catch {
      toast.error("Impossible de contacter le serveur.");
    } finally { setLoading(false); }
  };

  return (
    <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-5">
      {sent ? (
        <div className="text-center space-y-3">
          <div className="inline-flex items-center justify-center w-10 h-10 bg-green-100 rounded-full">
            <svg className="w-5 h-5 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
            </svg>
          </div>
          <p className="text-sm font-semibold text-gray-800">Demande envoyée</p>
          <p className="text-xs text-gray-500">
            Si ce compte dispose d'un email, un lien valable <strong>30 minutes</strong> a été envoyé.
          </p>
          <button onClick={onClose} className="text-sm text-blue-500 hover:underline">
            Retour à la connexion
          </button>
        </div>
      ) : (
        <>
          <h3 className="text-sm font-semibold text-gray-800 mb-1">Réinitialiser le mot de passe</h3>
          <p className="text-xs text-gray-400 mb-4">
            Entrez votre nom d'utilisateur. Un lien sera envoyé si un email est associé.
          </p>
          <form onSubmit={handleRequest} className="space-y-3">
            <input type="text" value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Nom d'utilisateur" autoFocus
              className="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm
                         focus:outline-none focus:ring-2 focus:ring-blue-500" />
            <div className="flex gap-2">
              <button type="submit" disabled={loading || !username.trim()}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-40
                           text-white text-sm font-medium py-2 rounded-xl transition-colors">
                {loading ? "Envoi…" : "Envoyer le lien"}
              </button>
              <button type="button" onClick={onClose}
                className="px-3 py-2 border border-gray-200 rounded-xl text-sm
                           text-gray-500 hover:bg-gray-50 transition-colors">
                Annuler
              </button>
            </div>
          </form>

          <details className="mt-4">
            <summary className="text-xs text-gray-300 cursor-pointer hover:text-gray-500 select-none">
              Pas d'email ? (accès CLI)
            </summary>
            <div className="mt-2 bg-gray-50 rounded-lg p-3 font-mono text-xs text-gray-500 leading-relaxed">
              <p className="text-gray-400 mb-1"># Depuis le serveur :</p>
              <p className="break-all">
                docker exec backend-api python3 -c<br/>
                "from auth.users import change_password;<br/>
                change_password('admin', 'NouveauMDP')"
              </p>
            </div>
          </details>
        </>
      )}
    </div>
  );
}
