## v1.0.1 — 2026-07-17

### 🔧 Changements
- Removed the redundant standalone RPM-only stack (`docker-compose.rpm.yml`) — the default `docker-compose.yaml` (`REPO_FORMAT=all`) already serves `.deb`/`.rpm`/`.apk` centrally; the standalone stack offered no functionality the default deployment didn't already provide
- Fixed GPG key generation to immediately sign the repository — generating a new key now re-initializes all distributions right away, instead of requiring a manual visit to the Distributions page or a separate "Init dists" click before packages are actually signed
- Cleaned up the `apt-repo` Docker image — removed unused `reprepro`/`gnupg` packages and a legacy init script; it's now a minimal static file server, matching `rpm-nginx`
- Reworked `.env.example`/`backend.env.example` — no more duplicated or silently-ignored variables between the two files, and documented the real `env_file`/`environment:` precedence rules
- Added "Post-deployment setup" and "Uninstall & Reinstall" sections to the README, plus a system clock / NTP prerequisite (a stale clock breaks TLS validation against upstream mirrors during sync)

### 🐳 Images Docker
- `ghcr.io/repod-ce/backend:1.0.1`
- `ghcr.io/repod-ce/frontend:1.0.1`
- `ghcr.io/repod-ce/apt-repo:1.0.1`
- `ghcr.io/repod-ce/rpm-nginx:1.0.1`

## v1.0.0 — 2026-07-16

Initial release:

### ✨ Nouvelles fonctionnalités
- feat: initial public release — Repod Community Edition v1.0.0

### 🐳 Images Docker
- `ghcr.io/repod-ce/backend:1.0.0`
- `ghcr.io/repod-ce/frontend:1.0.0`
- `ghcr.io/repod-ce/apt-repo:1.0.0`
- `ghcr.io/repod-ce/rpm-nginx:1.0.0`
