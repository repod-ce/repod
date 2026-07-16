<p align="center">
  <img src="logo.png" alt="Repod" width="90" />
</p>

<h1 align="center">Repod — Community Edition</h1>

<p align="center">
  <strong>Private APT / RPM / APK repository manager with built-in security scanning</strong>
</p>

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-7c3aed?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-61DAFB?style=flat-square&logo=react&logoColor=black" alt="React">
  <img src="https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white" alt="Tailwind CSS">
  <img src="https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/nginx-009639?style=flat-square&logo=nginx&logoColor=white" alt="nginx">
</p>

<p align="center">
  <a href="https://github.com/repod-ce/repod/pkgs/container/backend"><img src="https://img.shields.io/badge/ghcr.io-backend-0d1117?style=flat-square&logo=github&logoColor=white" alt="backend image"></a>
  <a href="https://github.com/repod-ce/repod/pkgs/container/frontend"><img src="https://img.shields.io/badge/ghcr.io-frontend-0d1117?style=flat-square&logo=github&logoColor=white" alt="frontend image"></a>
  <a href="https://github.com/repod-ce/repod/pkgs/container/apt-repo"><img src="https://img.shields.io/badge/ghcr.io-apt--repo-0d1117?style=flat-square&logo=github&logoColor=white" alt="apt-repo image"></a>
  <a href="https://github.com/repod-ce/repod/pkgs/container/rpm-nginx"><img src="https://img.shields.io/badge/ghcr.io-rpm--nginx-0d1117?style=flat-square&logo=github&logoColor=white" alt="rpm-nginx image"></a>
</p>

<p align="center">
  <a href="https://docs.getrepod.com/">Documentation</a> &middot;
  <a href="https://getrepod.com">Website</a> &middot;
  <a href="https://getrepod.com/#pricing">Enterprise</a> &middot;
  <a href="https://getrepod.com/#demo">Request a demo</a>
</p>

---

> **FR** | Gestionnaire de depot APT/RPM/APK prive avec interface web, controle d'acces par roles et securite integree.
> **EN** | Private APT/RPM/APK repository manager with web UI, role-based access control, and built-in security scanning.

---

## Key Features / Fonctionnalites principales

| EN | FR |
|----|----|
| Host DEB, RPM and APK packages in a single instance | Hebergez des paquets DEB, RPM et APK dans une seule instance |
| ClamAV antivirus scan on every upload (blocking) | Scan antivirus ClamAV a chaque upload (bloquant) |
| Grype CVE scan with configurable policy (block/review/warn/allow) | Scan CVE Grype avec politique configurable (block/review/warn/allow) |
| GPG auto-signing (Release, repomd.xml, APKINDEX) | Signature GPG automatique (Release, repomd.xml, APKINDEX) |
| 5 RBAC roles (admin, maintainer, uploader, auditor, reader) | 5 roles RBAC (admin, maintainer, uploader, auditor, reader) |
| Append-only audit trail (JSONL) | Journal d'audit immuable (JSONL) |
| Package import from upstream APT/RPM/APK mirrors | Import de paquets depuis sources APT/RPM/APK amont |
| FastAPI REST API with JWT auth | API REST FastAPI avec auth JWT |
| React + Tailwind web dashboard | Dashboard web React + Tailwind |
| Download statistics | Statistiques de telechargement |
| Health monitoring dashboard | Dashboard de surveillance |
| CVE review/promotion workflow (pending_review queue) | Workflow de revue/promotion CVE (file pending_review) |
| Custom roles & groups admin | Administration des roles personnalises et groupes |
| Email notification templates | Modeles d'e-mails de notification |
| Prometheus `/metrics` endpoint | Point de terminaison Prometheus `/metrics` |
| Self-hosted, air-gap ready | Auto-heberge, compatible air-gap |

---

## Architecture

```
                         +-------------------+
                         |   Frontend (React) |
                         |   nginx :3003      |
                         +--------+----------+
                                  | /api/*
                                  v
                         +-------------------+
                         | Backend (FastAPI)  |
                         | :8000             |
                         +--------+----------+
                                  |
              +-------------+----+----+-------------+
              |             |         |              |
        +-----+-----+ +----+----+ +--+---------------+
        | ClamAV    | | Grype   | | PostgreSQL :5432  |
        | Antivirus | | CVE DB  | | (users, manifests,|
        +-----------+ +---------+ |  package index…)  |
                                  +--+-----------------+
                                  |
                    +-------------+-------------+
                    |                           |
              +-----+-----+               +-----+-----+
              | apt-repo   |               | rpm-repo  |
              | nginx :80  |               | nginx :8080 |
              | .deb (reprepro) +          | .rpm        |
              | .apk (under /apk/)         | (createrepo_c) |
              +-----------+               +-----------+
```

5 Docker services (default `docker-compose.yaml`, `REPO_FORMAT=all` — APT +
RPM + APK simultaneously): `db` (PostgreSQL, container `repod-db`) ·
`backend` (FastAPI, container `backend-api`, :8000) · `frontend`
(nginx/React, container `frontend-ui`, :3003 by default) · `apt-repo`
(nginx + reprepro, container `depot-apt`, :80 — also serves Alpine `.apk`
under `/apk/`) · `rpm-repo` (nginx + createrepo_c, container `depot-rpm`,
:8080 by default, `.rpm` only).

> A separate, standalone stack (`docker-compose.rpm.yml`, its own
> PostgreSQL instance, network and container names) exists for running RPM
> mode side-by-side with a main APT-only deployment — see
> [REPO_FORMAT modes](#repo_format-modes-apt--rpm--apk--all) below.

---

## REPO_FORMAT modes (apt / rpm / apk / all)

The backend is format-agnostic and reads `REPO_FORMAT` once at startup
(`services/format_router.py`) to decide which validator/distribution
backend to load:

| `REPO_FORMAT` | Packages served | Repo tool |
|---|---|---|
| `apt` (default if unset) | `.deb` only | reprepro |
| `rpm` | `.rpm` only | createrepo_c |
| `apk` | Alpine `.apk` only | `apk index` |
| `all` | `.deb` + `.rpm` + `.apk` together | all three |

The **default `docker-compose.yaml` ships with `REPO_FORMAT: all`**
hardcoded (not exposed as an overridable env var in `backend.env.example`)
— every fresh `docker compose up -d` runs APT, RPM, and APK simultaneously
out of the box. `docker-compose.rpm.yml` is a separate, self-contained
stack (own PostgreSQL instance, network, ports, container names) for
running RPM-only mode side by side with a main APT/`all`-mode deployment —
it's run standalone (`docker compose -f docker-compose.rpm.yml up -d`),
never merged into the main stack via `-f`.

---

## Prerequisites / Prerequis

> **EN**
> - **Docker Engine** and the **Docker Compose plugin** (`docker compose`, v2 — not the legacy standalone `docker-compose` v1 binary). The optional `docker-compose.ha.yml` and `docker-compose.tls.yml` overlays use Compose Specification merge-control tags (`!reset`, `!override`) that require **Compose v2.24+**; the base `docker-compose.yaml` works with any reasonably recent v2 release.
>   Install: [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) (Docker Desktop on macOS/Windows already bundles Compose v2; on Linux, the `docker-compose-plugin` package does).
> - **Linux x86_64 host**, Docker Compose is expected to run on Linux (the target for `apt`/`dnf`/`apk` clients). `git` to clone the repository.
> - No Python/Node/build toolchain needed for the default `docker compose pull && docker compose up -d` path — images are pre-built (`ghcr.io/repod-ce/*`). A build toolchain is only needed if compiling from source (`docker-compose.build.yml`, see below).
>
> **FR**
> - **Docker Engine** et le **plugin Docker Compose** (`docker compose`, v2 — pas l'ancien binaire autonome `docker-compose` v1). Les overlays optionnels `docker-compose.ha.yml` et `docker-compose.tls.yml` utilisent des tags de fusion de la Compose Specification (`!reset`, `!override`) qui nécessitent **Compose v2.24+** ; le `docker-compose.yaml` de base fonctionne avec n'importe quelle version v2 raisonnablement récente.
>   Installation : [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) (Docker Desktop sur macOS/Windows inclut déjà Compose v2 ; sur Linux, c'est le paquet `docker-compose-plugin`).
> - **Hôte Linux x86_64** — Docker Compose est prévu pour tourner sous Linux (la cible des clients `apt`/`dnf`/`apk`). `git` pour cloner le dépôt.
> - Aucune chaîne d'outils Python/Node/compilation nécessaire pour le chemin par défaut `docker compose pull && docker compose up -d` — les images sont pré-construites (`ghcr.io/repod-ce/*`). Une chaîne de compilation n'est requise que pour compiler depuis les sources (`docker-compose.build.yml`, voir plus bas).

### Recommended disk sizing / Dimensionnement disque recommande

> **EN** — Everything under `./repos/` (bind-mounted into the containers) and the `postgres_data` Docker volume should live on a disk with enough headroom for your package catalog — package storage (`pool/`) is by far the dominant, workload-dependent factor; everything else below is comparatively fixed overhead.

| Component / Composant | Path | Typical size | Notes |
|---|---|---|---|
| Docker images (all 5 services) | Docker's own storage | ~2–3 GB | One-time, grows slowly across upgrades |
| ClamAV signature DB | `./repos/clamav-db/` | ~300–500 MB | Fixed, updated in place |
| Grype vulnerability DB (NVD feed) | `./repos/grype-db/` | ~1–2 GB | Fixed, updated in place |
| PostgreSQL (users, manifests index, package-index search) | `postgres_data` volume | Few hundred MB → low GB | Grows slowly with package/user/audit-history count, not with package *file* size |
| Audit logs (JSONL, one file/day) | `./repos/audit/` | A few MB/day at moderate usage | Subject to `retention_daily` cleanup — see `settings.json["retention"]` |
| **Package pool (`.deb`/`.rpm`/`.apk`)** | `./repos/pool/`, `./repos/rpm/`, `./repos/apk/` | **Highly variable — the dominant factor** | Every uploaded/imported/mirrored version is retained (no automatic pruning beyond `snapshots.py`'s configurable version-count limit); size = Σ(package size × retained versions) |

> **EN — starting points, not hard limits:**
> - **Evaluation / small internal repo** (a few hundred packages, few versions each): **20 GB** total is comfortable.
> - **Small-to-medium production** (thousands of packages, multiple distributions, several retained versions each): start at **50–100 GB** and monitor `pool/` growth.
> - **Large/long-lived production** (internet mirroring enabled, many distributions, long version retention): plan **200 GB+** and treat `./repos/` as its own volume/partition so it can be resized independently of the OS disk.
>
> **FR — points de depart, pas des limites strictes :**
> - **Evaluation / petit depot interne** (quelques centaines de paquets, peu de versions chacun) : **20 Go** au total est confortable.
> - **Production petite/moyenne** (milliers de paquets, plusieurs distributions, plusieurs versions conservees chacune) : partez sur **50 a 100 Go** et surveillez la croissance de `pool/`.
> - **Production large/durable** (mirroring internet active, nombreuses distributions, retention longue) : prevoyez **200 Go+** et traitez `./repos/` comme son propre volume/partition, redimensionnable independamment du disque OS.

---

## Quick Start / Demarrage rapide

> **EN** — No build required. Images are published on GitHub Container Registry (`ghcr.io/repod-ce/*`).
> **FR** — Aucune compilation requise. Les images sont publiees sur GitHub Container Registry (`ghcr.io/repod-ce/*`).

```bash
# 1. Clone the repository / Cloner le depot
git clone https://github.com/repod-ce/repod.git && cd repod

# 2. Configure environment / Configurer l'environnement
cp backend.env.example backend.env
# Edit backend.env : JWT_SECRET_KEY (REQUIRED / OBLIGATOIRE en prod)

# 3. Pull published images and start / Tirer les images publiees et demarrer
docker compose pull
docker compose up -d
```

> **Pin a specific version / Fixer une version specifique :**
> ```bash
> REPOD_VERSION=1.0.0 docker compose pull
> REPOD_VERSION=1.0.0 docker compose up -d
> ```
>
> Available tags / Tags disponibles : [`latest`](https://github.com/repod-ce/repod/releases/latest) · `1.0.0` · `1.0` — see all at [ghcr.io/repod-ce](https://github.com/orgs/repod-ce/packages)

---

### Published images / Images publiees

| Image | Pull command |
|-------|-------------|
| Backend (FastAPI) | `docker pull ghcr.io/repod-ce/backend:latest` |
| Frontend (React/nginx) | `docker pull ghcr.io/repod-ce/frontend:latest` |
| APT repo (nginx + reprepro) | `docker pull ghcr.io/repod-ce/apt-repo:latest` |
| RPM repo (nginx) | `docker pull ghcr.io/repod-ce/rpm-nginx:latest` |

> **Registry namespace note / Remarque namespace registry** — the standalone
> `docker-compose.rpm.yml` stack currently pulls from a different namespace
> (`ghcr.io/getautoflow/repod-ce/*`) than the main `docker-compose.yaml`
> above (`ghcr.io/repod-ce/*`). If you use `docker-compose.rpm.yml`, check
> which namespace actually has published images for your target version
> before relying on the default — this inconsistency predates this fix and
> hasn't been reconciled yet.

> **Build from source / Compiler depuis les sources :**
> ```bash
> docker compose -f docker-compose.yaml -f docker-compose.build.yml up -d --build
> ```

> **Development / Developpement :**
> ```bash
> docker compose -f docker-compose.yaml -f docker-compose.build.yml -f docker-compose.dev.yml up --build
> ```

---

## TLS Deployment / Deploiement TLS

### Self-signed certificate / Certificat auto-signe

```bash
bash scripts/gen-selfsigned-certs.sh
docker compose -f docker-compose.yaml -f docker-compose.tls.yml up -d
```

### Let's Encrypt (public domain required / domaine public requis)

```bash
export REPOD_DOMAIN=repod.example.com
export CERTBOT_EMAIL=admin@example.com

docker compose -f docker-compose.yaml -f docker-compose.tls.yml \
               -f docker-compose.letsencrypt.yml up -d
docker compose -f docker-compose.yaml -f docker-compose.tls.yml \
               -f docker-compose.letsencrypt.yml run --rm certbot certonly
```

---

## Environment variables / Variables d'environnement

Two files, copied to their real (gitignored) counterpart before first use:
`backend.env.example` → `backend.env` (backend secrets/config) and
`.env.example` → `.env` (docker-compose-level variables). Full reference —
every variable in both files, not just a curated subset.

### `backend.env`

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string — required |
| `JWT_SECRET_KEY` | Token signing secret — **required in production** |
| `JWT_EXPIRE_MINUTES` | Token lifetime in minutes (default `60`) |
| `SETTINGS_ENCRYPTION_KEY` | Encrypts secrets in `settings.json` (SMTP/LDAP password, OIDC `client_secret`); falls back to `JWT_SECRET_KEY` if unset (not recommended) |
| `REPOD_LICENSE_VENDOR_KEY` | Signs/verifies Enterprise license keys — **required in production** (startup fails immediately if unset or default; only warns in dev) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | Pre-provision the first admin, skipping the setup wizard — see [Security Warning](#security-warning--avertissement-securite) below |
| `SETUP_TOKEN` | Optional — protects `POST /api/v1/setup` during the window between container start and first-admin creation (requires header `X-Setup-Token`) |
| `CORS_ORIGINS` | Comma-separated allowed origins |
| `AUTH_RATELIMIT_PER_MINUTE` | Login rate limit, requests/minute per IP (default `10`) |
| `SSH_HOST` / `SSH_USER` | Optional — **not** the Enterprise fleet-inventory feature. Powers the "Télécharger depuis Internet" button on the Packages page: the backend SSHes into the **Docker host machine** (not a remote fleet client) and runs `download-package-dep.sh` there via `apt`. Leave both empty to disable the button (returns an explicit error, no other impact). |
| `SSH_KEY_PATH` | Ed25519 private key path inside the backend container for the connection above (default `/home/appuser/.ssh/id_ed25519`) |
| `SSH_PORT` | SSH port for the same connection (default `22`) |
| `WEBHOOK_SECRET` | HMAC secret for `/webhooks/github` and `/webhooks/kev` — **must match** `WEBHOOK_SECRET` in `.env` |
| `METRICS_TOKEN` | Optional Bearer token protecting `GET /metrics` (Prometheus) — unset means unauthenticated |

`POOL_DIR`, `MANIFEST_DIR`, `STAGING_INCOMING`, `STAGING_QUARANTINE`,
`AUDIT_DIR`, `INDEX_PATH`, `ADD_DEB_SCRIPT`, `IMPORTS_DIR`,
`CLAMAV_DB_DIR`, `SETTINGS_PATH` are also set in `backend.env.example`, but
are internal paths tied to the Docker volumes declared in
`docker-compose.yaml` — don't change these unless you're also changing
those volume mounts.

### `.env`

| Variable | Purpose |
|---|---|
| `REACT_APP_API_URL` | Leave empty unless building the frontend from source (`docker-compose.build.yml`) — non-empty bakes an absolute URL into the JS bundle and breaks cross-host access |
| `REACT_APP_REPO_URL` | Same "build from source only" caveat — public URL of the repo (apt-repo), used to construct client install instructions in the UI |
| `REPOD_VERSION` | Image tag to pull (`latest`, `v1.2.3`…) |
| `BIND_HOST` | `0.0.0.0` (default, ports reachable externally) or `127.0.0.1` (reverse-proxy setups — ports host-only) |
| `FRONTEND_PORT` | Host port for the frontend (default `3003`) |
| `BACKEND_PORT` | Host port for the backend API (default `8000`) |
| `APT_PORT` | Host port for the APT repo (default `80`) |
| `APT_TLS_PORT` | APT repo port when `docker-compose.tls.yml` is active (default `8085`) — port 80 is reclaimed by the TLS reverse proxy in that mode |
| `WEBHOOK_SECRET` | Must be identical to `WEBHOOK_SECRET` in `backend.env` |

> `REPO_FORMAT` is **not** an overridable env var in either file — it's
> hardcoded per compose file (`all` in `docker-compose.yaml`, `rpm` in
> `docker-compose.rpm.yml`). See [REPO_FORMAT modes](#repo_format-modes-apt--rpm--apk--all)
> above.

---

## Security Warning / Avertissement securite

> **EN** -- No default credentials are shipped. On first start, open the web
> UI: if no admin account exists, the first-run setup wizard
> (`/api/v1/setup`) appears and lets you create the first administrator
> account (username + password).
>
> **FR** -- Aucun identifiant par defaut n'est fourni. Au premier demarrage,
> ouvrez l'interface web : si aucun compte admin n'existe, l'assistant de
> premiere installation (`/api/v1/setup`) s'affiche et vous permet de creer
> le premier compte administrateur (nom d'utilisateur + mot de passe).

For automated deployments, pre-provision an admin via `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` in `backend.env` (see `backend.env.example`).

```bash
# Generate a bcrypt hash / Generer un hash bcrypt
docker run --rm python:3.10-slim python3 -c \
  "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('YourPass1!'))"
```

---

## Documentation

| | EN | FR |
|---|---|---|
| Full guide | [docs.getrepod.com](https://docs.getrepod.com/) | [docs.getrepod.com/fr](https://docs.getrepod.com/fr/) |
| Architecture | [Architecture](https://docs.getrepod.com/explanation/architecture/) | [Architecture](https://docs.getrepod.com/fr/explanation/architecture/) |
| Getting started | [Getting started](https://docs.getrepod.com/getting-started/) | [Demarrage rapide](https://docs.getrepod.com/fr/getting-started/) |
| Roles & permissions | [Roles](https://docs.getrepod.com/reference/roles/) | [Roles](https://docs.getrepod.com/fr/reference/roles/) |
| Security pipeline | [Security pipeline](https://docs.getrepod.com/explanation/security-pipeline/) | [Pipeline de securite](https://docs.getrepod.com/fr/explanation/security-pipeline/) |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting a pull request. By contributing you agree to the [Contributor License Agreement](./CLA.md).

Les contributions sont les bienvenues. Veuillez lire [CONTRIBUTING.md](./CONTRIBUTING.md) avant de soumettre une pull request.

---

## License / Licence

The Repod source code (backend and frontend) is licensed under the
**GNU Affero General Public License v3.0 (AGPL-3.0-only)** -- see [LICENSE](./LICENSE).
A commercial license without the AGPL obligations is available -- see
[LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md).

Le code source de Repod (backend et frontend) est distribue sous la
**GNU Affero General Public License v3.0 (AGPL-3.0-only)** -- voir [LICENSE](./LICENSE).
Une licence commerciale sans les obligations de l'AGPL est disponible --
voir [LICENSE-COMMERCIAL.md](./LICENSE-COMMERCIAL.md).

### Third-party components / Composants tiers

| Component | License | Usage |
|-----------|---------|-------|
| [reprepro](https://salsa.debian.org/brlink/reprepro) | GPL v2 | APT repo management (subprocess) |
| [ClamAV](https://www.clamav.net/) | GPL v2 | Antivirus scanning (Unix socket) |
| [Grype](https://github.com/anchore/grype) | Apache 2.0 | CVE vulnerability scanning |
| [FastAPI](https://fastapi.tiangolo.com/) | MIT | Backend web framework |
| [React](https://react.dev/) | MIT | Frontend UI library |
| [Tailwind CSS](https://tailwindcss.com/) | MIT | Frontend CSS framework |
| [PostgreSQL](https://www.postgresql.org/) | PostgreSQL License | Relational database |
| [nginx](https://nginx.org/) | BSD-2-Clause | Reverse proxy & static file serving |

reprepro and ClamAV are invoked as **independent processes** (subprocess
exec and Unix socket respectively) and are **not statically or dynamically
linked** against Repod's code.

See [NOTICES](./NOTICES) for complete third-party attributions and [LICENSES/](./LICENSES/) for full license texts.
