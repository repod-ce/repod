## v1.0.0 — 2026-06-14

Initial public release of Repod Community Edition.

### ✨ Fonctionnalités
- Gestion de dépôts APT, RPM et APK avec interface web React + Tailwind
- API REST FastAPI, authentification JWT, RBAC à 5 rôles
- Scan antivirus ClamAV et scan CVE Grype à l'upload, avec politique configurable (Politique CVE : sévérité → action, SLA, enrichissement EPSS/KEV)
- Export SBOM (CycloneDX + SPDX), journal d'audit immuable, statistiques de téléchargement
- Import de paquets depuis des sources amont (APT/RPM/APK) et tableau de bord de santé

### 🐛 Corrections
- fix: colonnes de taille de paquets en BIGINT pour éviter les erreurs `NumericValueOutOfRange` lors de la synchronisation des index APT/APK (paquets volumineux)
- fix: restauration de la section "Politique CVE" dans Paramètres, nécessaire au workflow de décision CVE

### 🎨 Interface
- chore: remplacement des émojis par des icônes professionnelles (react-icons) sur la page Sources et les notifications de synchronisation

### 🐳 Images Docker
- `ghcr.io/getautoflow/repod-ce/backend:1.0.0`
- `ghcr.io/getautoflow/repod-ce/frontend:1.0.0`
- `ghcr.io/getautoflow/repod-ce/apt-repo:1.0.0`
- `ghcr.io/getautoflow/repod-ce/rpm-nginx:1.0.0`
