import axios from "axios";

// URL relative par défaut → toutes les requêtes passent par nginx (/api/)
// qui proxifie vers le backend. Fonctionne sur n'importe quel hôte sans
// configuration. Pour développement direct (sans nginx) : REACT_APP_API_URL=http://localhost:8000
const API_URL = import.meta.env.REACT_APP_API_URL || "";
const API_V1  = `${API_URL}/api/v1`;

// Toutes les requêtes métier passent par /api/v1/
// (P2-1 — API versioning).  Les endpoints infra (/health, /metrics) restent
// à la racine et sont appelés via API_URL directement.
const api = axios.create({ baseURL: API_V1 });

// Token en mémoire — synchronisé par AuthContext via setApiToken/clearApiToken.
let _apiToken = localStorage.getItem("token") || null;
export const setApiToken   = (t) => { _apiToken = t; };
export const clearApiToken = ()  => { _apiToken = null; };

// Injecte le token JWT sur chaque requête
api.interceptors.request.use((config) => {
  const token = _apiToken || localStorage.getItem("token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirige vers /login en cas de 401 uniquement si l'utilisateur était authentifié.
// Si pas de token (ex: mauvais identifiants sur la page de login), on laisse le
// composant gérer l'erreur lui-même — sinon la page recharge avant l'affichage
// du message d'erreur.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && localStorage.getItem("token")) {
      localStorage.removeItem("token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export const login = (username, password) =>
  api.post("/auth/token", { username, password });

export const getMe = () =>
  api.get("/auth/me").then((r) => r.data);

export const refreshToken = () =>
  api.post("/auth/refresh").then((r) => r.data);

// ─── MFA TOTP ─────────────────────────────────────────────────────────────────
export const mfaSetup = () =>
  api.post("/auth/mfa/setup").then((r) => r.data);

export const mfaConfirm = (totp_code) =>
  api.post("/auth/mfa/confirm", { totp_code }).then((r) => r.data);

export const mfaAuthenticate = (mfa_token, totp_code) =>
  api.post("/auth/mfa/authenticate", { mfa_token, totp_code }).then((r) => r.data);

export const mfaDisable = (password) =>
  api.post("/auth/mfa/disable", { password }).then((r) => r.data);

export const requestPasswordReset = (username) =>
  api.post("/auth/forgot-password", { username }).then((r) => r.data);

// ─── Assistant de première installation ────────────────────────────────────
export const getSetupStatus = () =>
  api.get("/setup/status").then((r) => r.data);

export const runSetup = (payload) =>
  api.post("/setup/", payload).then((r) => r.data);

export const getSetupPreflight = () =>
  api.get("/setup/preflight").then((r) => r.data);

export const resetPasswordWithToken = (token, newPassword) =>
  api.post("/auth/reset-password", { token, new_password: newPassword }).then((r) => r.data);

export const listPackages = () =>
  api.get("/packages/").then((r) => r.data);

// Artifacts — liste enrichie avec métadonnées (paginée)
export const listArtifacts = (page = 1, perPage = 50, search = "", distribution = "") => {
  const qs = new URLSearchParams({ page, per_page: perPage });
  if (search)       qs.set("search", search);
  if (distribution && distribution !== "all") qs.set("distribution", distribution);
  return api.get(`/artifacts/?${qs}`).then((r) => r.data);
};

export const getArtifact = (name) =>
  api.get(`/artifacts/${name}`).then((r) => r.data);

export const resolveDependencies = (name) =>
  api.get(`/artifacts/${name}/dependencies`).then((r) => r.data);

export const installArtifact = (name, target = "localhost") =>
  api.post(`/artifacts/${name}/install`, { target }).then((r) => r.data);

export const deleteArtifact = (name, version = null) => {
  const url = version ? `/artifacts/${name}/${version}` : `/artifacts/${name}`;
  return api.delete(url).then((r) => r.data);
};

// getAuditLogs défini plus bas avec filtres complets

export const syncIndex = () =>
  api.post("/artifacts/admin/sync-index").then((r) => r.data);

export const installPackage = (name) =>
  api.post("/packages/install/", { name }).then((r) => r.data);

export const uploadPackage = (file, distribution = "jammy") => {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("distribution", distribution);
  return api.post("/upload/", formData).then((r) => r.data);
};

// ─── Import depuis internet ───────────────────────────────────────────────────

export const searchImportPackages = (q, limit = 60, source_id = null, format = null, distro = null) => {
  const params = new URLSearchParams({ q, limit });
  if (source_id) params.append("source_id", source_id);
  if (format)    params.append("format", format);
  if (distro)    params.append("distro", distro);
  return api.get(`/import/search?${params}`).then((r) => r.data);
};

export const resolveImportDeps = (packageName) =>
  api.get(`/import/resolve/${encodeURIComponent(packageName)}`).then((r) => r.data);

export const getImportSyncStatus = () =>
  api.get("/import/sync-status").then((r) => r.data);

export const getImportGroups = () =>
  api.get("/import/groups").then((r) => r.data);

export const deleteImportGroup = (name) =>
  api.delete(`/import/groups/${encodeURIComponent(name)}`).then((r) => r.data);

export const analyzeDockerfile = (content, distribution = null) =>
  api.post("/import/analyze-dockerfile", { content, distribution }).then((r) => r.data);

// ─── Mirroir planifié sécurisé ────────────────────────────────────────────────

export const getMirrorSources = () =>
  api.get("/import/mirror/sources").then((r) => r.data);

export const updateMirrorSources = (sources) =>
  api.post("/import/mirror/sources", { sources }).then((r) => r.data);

export const getMirrorSchedule = () =>
  api.get("/import/mirror/schedule").then((r) => r.data);

export const updateMirrorSchedule = (patch) =>
  api.post("/import/mirror/schedule", patch).then((r) => r.data);

export const startMirrorJob = (sourceId, limit = null) => {
  const params = limit ? `?limit=${encodeURIComponent(limit)}` : "";
  return api.post(`/import/mirror/start/${encodeURIComponent(sourceId)}${params}`).then((r) => r.data);
};

export const getMirrorJobs = () =>
  api.get("/import/mirror/jobs").then((r) => r.data);

export const getMirrorJob = (jobId) =>
  api.get(`/import/mirror/jobs/${encodeURIComponent(jobId)}`).then((r) => r.data);

export const cancelMirrorJob = (jobId) =>
  api.post(`/import/mirror/jobs/${encodeURIComponent(jobId)}/cancel`).then((r) => r.data);

// ─── Sécurité / ClamAV ───────────────────────────────────────────────────────

export const getClamavStatus = () =>
  api.get("/security/clamav/status").then((r) => r.data);

export const getApiBaseUrl = () => API_V1;
export const getBaseUrl    = () => API_URL;

// ─── Sécurité / CVE ──────────────────────────────────────────────────────────

export const getPackagesPosture = (distribution = null) => {
  const params = distribution ? `?distribution=${encodeURIComponent(distribution)}` : "";
  return api.get(`/security/packages-posture${params}`).then((r) => r.data);
};

export const getVulnerabilities = (filters = {}) => {
  const params = new URLSearchParams();
  if (filters.severity) params.append("severity", filters.severity);
  if (filters.fix_state) params.append("fix_state", filters.fix_state);
  if (filters.distribution) params.append("distribution", filters.distribution);
  const qs = params.toString();
  return api.get(`/security/vulnerabilities${qs ? "?" + qs : ""}`).then((r) => r.data);
};

export const getPackageCve = (name, version, arch = "amd64") =>
  api.get(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/cve?arch=${arch}`)
    .then((r) => r.data);

export const quarantinePackage = (name, version, arch = "amd64") =>
  api.post(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/quarantine?arch=${arch}`)
    .then((r) => r.data);

export const getReviewQueue = (page = 1, perPage = 20) =>
  api.get(`/security/review-queue?page=${page}&per_page=${perPage}`).then((r) => r.data);

export const submitDecision = (name, version, payload) =>
  api.post(
    `/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decide`,
    payload
  ).then((r) => r.data);

export const checkSla = () =>
  api.post("/security/check-sla").then((r) => r.data);

export const getSecurityDecisions = () =>
  api.get("/security/decisions").then((r) => r.data);

export const resolveDecision = (name, version, arch = "amd64", note = "") =>
  api.post(
    `/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decision/resolve`,
    { arch, note }
  ).then((r) => r.data);

export const startBulkImport = (items) =>
  api.post("/import/bulk", { items }).then((r) => r.data);

export const getBulkImportStatus = (bulkId) =>
  api.get(`/import/bulk/${encodeURIComponent(bulkId)}`).then((r) => r.data);

export const getSecurityReport = () =>
  api.get("/security/report").then((r) => r.data);

// ─── Dashboard ───────────────────────────────────────────────────────────────

export const getDashboardStats = () =>
  api.get("/dashboard/stats").then((r) => r.data);

// ─── Distributions ───────────────────────────────────────────────────────────

export const getDistributions = () =>
  api.get("/distributions/").then((r) => r.data);

export const getDistribPackages = (codename) =>
  api.get(`/distributions/${codename}/packages`).then((r) => r.data);

export const promotePackage = (pkg, fromDist, toDist) =>
  api.post("/distributions/promote", { package: pkg, from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const migrateDistrib = (fromDist, toDist) =>
  api.post("/distributions/migrate", { from_dist: fromDist, to_dist: toDist }).then((r) => r.data);

export const initDistributions = () =>
  api.post("/distributions/init").then((r) => r.data);

// ─── Paramètres ──────────────────────────────────────────────────────────────

// ─── Gestion des utilisateurs ─────────────────────────────────────────────────

export const getRoles = () =>
  api.get("/auth/roles").then((r) => r.data);

export const listUsers = () =>
  api.get("/auth/users").then((r) => r.data);

export const createUser = (payload) =>
  api.post("/auth/users", payload).then((r) => r.data);

export const updateUser = (username, payload) =>
  api.patch(`/auth/users/${encodeURIComponent(username)}`, payload).then((r) => r.data);

export const deleteUser = (username) =>
  api.delete(`/auth/users/${encodeURIComponent(username)}`).then((r) => r.data);

export const resetUserPassword = (username, newPassword) =>
  api.post(`/auth/users/${encodeURIComponent(username)}/reset-password`, { new_password: newPassword }).then((r) => r.data);

export const changeOwnPassword = (currentPassword, newPassword) =>
  api.post("/auth/change-password", { current_password: currentPassword, new_password: newPassword }).then((r) => r.data);

// ─── Paramètres ──────────────────────────────────────────────────────────────

export const getSettings = () =>
  api.get("/settings/").then((r) => r.data);

export const patchSettings = (partial) =>
  api.patch("/settings/", partial).then((r) => r.data);

// ─── Dashboard enrichi (Sprint 5.4) ──────────────────────────────────────────
export const getEnrichedDashboard = (params = {}) => {
  const qs = new URLSearchParams();
  if (params.trend_windows) qs.set("trend_windows", params.trend_windows);
  if (params.top_limit)     qs.set("top_limit",     params.top_limit);
  if (params.sla_max_age_days != null) qs.set("sla_max_age_days", params.sla_max_age_days);
  return api.get(`/dashboard/stats/enriched?${qs}`).then((r) => r.data);
};

// ─── Workflow d'approbation RSSI (Sprint 6.3) ────────────────────────────────
export const listPendingPromotions = (status = "pending", page = 1, perPage = 50) =>
  api.get(`/artifacts/admin/pending-promotions?status=${status}&page=${page}&per_page=${perPage}`).then((r) => r.data);

export const approvePendingPromotion = (name, pendingId, justification) =>
  api.post(`/artifacts/${encodeURIComponent(name)}/promote/${encodeURIComponent(pendingId)}/approve`,
           { justification, reason: "" }).then((r) => r.data);

export const rejectPendingPromotion = (name, pendingId, reason) =>
  api.post(`/artifacts/${encodeURIComponent(name)}/promote/${encodeURIComponent(pendingId)}/reject`,
           { justification: "", reason }).then((r) => r.data);

export const promoteArtifact = (name, fromDist, toDist, { version = null, force = false, justification = "" } = {}) =>
  api.post(`/artifacts/${encodeURIComponent(name)}/promote`,
           { from_dist: fromDist, to_dist: toDist, version, force, justification })
     .then((r) => r.data);

export const getNextSync = () =>
  api.get("/settings/next-sync").then((r) => r.data);

export const getSyncSchedule = () =>
  api.get("/import/sync-schedule").then((r) => r.data);

// ─── Audit ────────────────────────────────────────────────────────────────────
export const getAuditLogs = (params = {}) => {
  const qs = new URLSearchParams();
  qs.set("page",     params.page     || 1);
  qs.set("per_page", params.per_page || 100);
  if (params.package) qs.set("package", params.package);
  if (params.action)  qs.set("action",  params.action);
  if (params.result)  qs.set("result",  params.result);
  if (params.q)       qs.set("q",       params.q);
  if (params.sort)    qs.set("sort",    params.sort);
  return api.get(`/artifacts/audit/logs?${qs}`).then((r) => r.data);
};

// ─── GPG ──────────────────────────────────────────────────────────────────────
export const getGpgInfo = () =>
  api.get("/settings/gpg").then((r) => r.data);

export const generateGpgKey = () =>
  api.post("/settings/gpg/generate").then((r) => r.data);

export const testEmail = (toOverride = null) =>
  api.post("/settings/test-email", { to_override: toOverride }).then((r) => r.data);

export const runRetention = () =>
  api.post("/settings/run-retention").then((r) => r.data);

// ─── Health ───────────────────────────────────────────────────────────────────
// /health est un endpoint infra NON versionné (pas de /api/v1/) — appel direct
export const getHealth = () =>
  axios.get(`${API_URL}/health`).then((r) => r.data);

export const updateClamavDb = () =>
  api.post("/security/clamav/update").then((r) => r.data);

// ─── Bases de sécurité (Grype, KEV, EPSS) ───────────────────────────────────
export const getGrypeStatus   = () => api.get("/security/grype/status").then((r) => r.data);
export const getFeedsStatus   = () => api.get("/security/feeds/status").then((r) => r.data);
export const getGrypeUpdateUrl  = () => `${API_V1}/security/grype/update`;
export const getFeedsRefreshUrl = () => `${API_V1}/security/feeds/refresh`;
export const getClamavUpdateUrl = () => `${API_V1}/security/clamav/update`;

// ─── Statistiques de téléchargements ─────────────────────────────────────────
export const getDownloadStats = (days = 30) =>
  api.get(`/downloads/stats?days=${days}`).then((r) => r.data);

// ─── Dashboard history ────────────────────────────────────────────────────────
export const getDashboardHistory = (days = 30) =>
  api.get(`/dashboard/history?days=${days}`).then((r) => r.data);

// ─── Package decision ─────────────────────────────────────────────────────────
export const getPackageDecision = (name, version, arch = "amd64") =>
  api.get(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/decision?arch=${arch}`)
    .then((r) => r.data);

export const rescanPackage = (name, version, arch = "amd64") =>
  api.post(`/security/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}/rescan?arch=${arch}`)
    .then((r) => r.data);



// ─── Logs streaming ──────────────────────────────────────────────────────────
export const getLogs = (p = {}) =>
  api.get("/logs", { params: p }).then((r) => r.data);



// ─── Décisions CVE — fonctions étendues ───────────────────────────────────────

export const getMyDecisions = () =>
  api.get("/security/decisions/mine").then((r) => r.data);

export const getUnassignedDecisions = () =>
  api.get("/security/decisions/unassigned").then((r) => r.data);

export const assignDecision = (decisionId, assignedTo, assignedToType) =>
  api.patch(`/security/decisions/${decisionId}/assign`, {
    assigned_to: assignedTo || null,
    assigned_to_type: assignedTo ? assignedToType : null,
  }).then((r) => r.data);

export const updateDecision = (decisionId, payload) =>
  api.put(`/security/decisions/${decisionId}`, payload).then((r) => r.data);

export const deleteDecisionById = (decisionId) =>
  api.delete(`/security/decisions/${decisionId}`).then((r) => r.data);

// ─── Groupes ──────────────────────────────────────────────────────────────────

export const listGroups = () =>
  api.get("/groups").then((r) => r.data);

export const getMyGroups = () =>
  api.get("/groups/me").then((r) => r.data);

export const createGroup = (payload) =>
  api.post("/groups", payload).then((r) => r.data);

export const updateGroup = (id, payload) =>
  api.put(`/groups/${encodeURIComponent(id)}`, payload).then((r) => r.data);

export const deleteGroup = (id) =>
  api.delete(`/groups/${encodeURIComponent(id)}`).then((r) => r.data);

export const getGroupMembers = (id) =>
  api.get(`/groups/${encodeURIComponent(id)}/members`).then((r) => r.data);

export const addGroupMember = (id, username) =>
  api.post(`/groups/${encodeURIComponent(id)}/members`, { username }).then((r) => r.data);

export const removeGroupMember = (id, username) =>
  api.delete(`/groups/${encodeURIComponent(id)}/members/${encodeURIComponent(username)}`).then((r) => r.data);

// ─── Rôles personnalisables ───────────────────────────────────────────────────

export const listRoles = () =>
  api.get("/roles").then((r) => r.data);

export const createRole = (payload) =>
  api.post("/roles", payload).then((r) => r.data);

export const updateRole = (id, payload) =>
  api.put(`/roles/${encodeURIComponent(id)}`, payload).then((r) => r.data);

export const deleteRole = (id) =>
  api.delete(`/roles/${encodeURIComponent(id)}`).then((r) => r.data);

export const getRolePermissions = (id) =>
  api.get(`/roles/${encodeURIComponent(id)}/permissions`).then((r) => r.data);

export const setRolePermissions = (id, permissions) =>
  api.put(`/roles/${encodeURIComponent(id)}/permissions`, { permissions }).then((r) => r.data);

// ── Email Templates ─────────────────────────────────────────────────────────
export const listEmailTemplates = () =>
  api.get("/templates").then((r) => r.data.templates);

export const getEmailTemplate = (name) =>
  api.get(`/templates/${name}`).then((r) => r.data.template);

export const updateEmailTemplate = (name, body, subject) =>
  api.put(`/templates/${name}`, { body, subject }).then((r) => r.data.template);

export const resetEmailTemplate = (name) =>
  api.post(`/templates/${name}/reset`).then((r) => r.data.template);

export const previewEmailTemplate = (name, body) =>
  api.post(`/templates/${name}/preview`, { body }).then((r) => r.data.html);
