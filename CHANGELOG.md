## v1.1.0 — 2026-07-17

Changes since `v1.0.1`:

### ✨ Nouvelles fonctionnalités
- feat(upload,packages): add wait banner during dep resolution + freshness-based index sync (1c08b32)
- feat(upload): show per-dependency scan detail + auto-sync on index miss (1c8da52)
- feat(upload): resolve dependency chains transitively, not just first level (5ed2a99)
- feat(upload): auto-import missing dependencies on manual deposit (41507b8)
- feat: initial public release — Repod Community Edition v1.0.1 (456f402)

### 🐛 Corrections
- fix(ci): close CI red gate — bandit findings, CVE bump, stale SLA test (8592f5c)
- fix(pool): package delete silently orphaned pool files in REPO_FORMAT=all (93d754b)
- fix(import): RPM/APK CVE review bypass + add post-import navigation (dddf67a)
- fix(artifacts): delete endpoints never removed the PostgreSQL row (1025106)
- fix(security): correct CVE review-workflow display bugs (0b5efc6)


### 🐳 Images Docker
- `ghcr.io/repod-ce/backend:1.1.0`
- `ghcr.io/repod-ce/frontend:1.1.0`
- `ghcr.io/repod-ce/apt-repo:1.1.0`
- `ghcr.io/repod-ce/rpm-nginx:1.1.0`
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
