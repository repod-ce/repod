<p align="center">
  <img src="logo.png" alt="Repod" width="90" />
</p>

<h1 align="center">Repod — Community Edition</h1>

<p align="center">
  <strong>Private APT/RPM/APK repository manager with built-in security scanning</strong>
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
(plain nginx static file server, container `depot-apt`, :80 — also serves
Alpine `.apk` under `/apk/`) · `rpm-repo` (plain nginx static file server,
container `depot-rpm`, :8080 by default, `.rpm` only). `reprepro` and
`createrepo_c` themselves run inside the `backend` container, directly
against the shared `/repos` volume — `apt-repo`/`rpm-repo` only serve the
resulting files, they don't run any repo tooling.

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
out of the box, all centrally managed (one database, one dashboard, one
RBAC/audit trail).

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

### System clock / Horloge systeme

> **EN** — The host's system clock must be correct and NTP-synchronized
> **before** first deploying, and stay that way. If it's behind, every
> HTTPS request to an upstream mirror (Sources page sync, internet
> import/mirroring) fails TLS certificate validation with `CERTIFICATE_
> VERIFY_FAILED ... certificate is not yet valid` — Python/OpenSSL compares
> the local clock against the certificate's validity window, and a clock
> that's behind makes any recently-rotated certificate (mirrors typically
> rotate every ~90 days via Let's Encrypt) look "not yet valid" even though
> the certificate itself is fine. Common on a VM restored from an old
> snapshot/clone, or one that was suspended for a while. Not specific to
> any one upstream (Alpine, AlmaLinux, Ubuntu security mirrors all hit
> this identically) and not a Repod bug — verify and fix before deploying:
> ```bash
> timedatectl status   # check "NTP synchronized: yes"
> # try this first — on some minimal Debian images/templates,
> # systemd-timesyncd is present but masked, so `set-ntp true` silently
> # has no effect until it's unmasked:
> sudo systemctl unmask systemd-timesyncd
> sudo timedatectl set-ntp true
> timedatectl status   # re-check
> # only if that's not enough (service still won't sync — check
> # `systemctl status systemd-timesyncd` for why) — install chrony instead:
> sudo apt install -y chrony && sudo systemctl enable --now chrony   # Debian/Ubuntu
> sudo dnf install -y chrony && sudo systemctl enable --now chronyd  # RHEL/AlmaLinux/Rocky
> ```
>
> **FR** — L'horloge système de l'hôte doit être correcte et synchronisée
> NTP **avant** le premier déploiement, et le rester. Si elle retarde,
> chaque requête HTTPS vers un mirroir amont (synchro de la page Sources,
> import/mirroring internet) échoue la validation du certificat TLS avec
> `CERTIFICATE_VERIFY_FAILED ... certificate is not yet valid` —
> Python/OpenSSL compare l'horloge locale à la période de validité du
> certificat, et une horloge en retard fait paraître "pas encore valide"
> n'importe quel certificat récemment renouvelé (les mirroirs tournent
> généralement leur certificat Let's Encrypt tous les ~90 jours), même s'il
> est parfaitement valide. Fréquent sur une VM restaurée depuis un ancien
> snapshot/clone, ou qui est restée suspendue un moment. Ce n'est propre à
> aucun mirroir en particulier (Alpine, AlmaLinux, mirroirs sécurité Ubuntu
> sont tous affectés identiquement) et ce n'est pas un bug de Repod —
> vérifiez et corrigez avant de déployer (mêmes commandes qu'en anglais
> ci-dessus).

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
cp .env.example .env
cp backend.env.example backend.env
# Edit .env : POSTGRES_PASSWORD, JWT_SECRET_KEY, CORS_ORIGINS (REQUIRED / OBLIGATOIRE en prod
# — with the default docker-compose.yaml, backend.env's own copies of these three
# are silently ignored, see the "Environment variables" section below)
# Edit backend.env : SETTINGS_ENCRYPTION_KEY, REPOD_LICENSE_VENDOR_KEY, WEBHOOK_SECRET (REQUIRED / OBLIGATOIRE en prod)

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
| APT repo (nginx) | `docker pull ghcr.io/repod-ce/apt-repo:latest` |
| RPM repo (nginx) | `docker pull ghcr.io/repod-ce/rpm-nginx:latest` |

> **Build from source / Compiler depuis les sources :**
> ```bash
> docker compose -f docker-compose.yaml -f docker-compose.build.yml up -d --build
> ```

> **Development / Developpement :**
> ```bash
> docker compose -f docker-compose.yaml -f docker-compose.build.yml -f docker-compose.dev.yml up --build
> ```

---

## Post-deployment setup / Configuration post-deploiement

> **EN** — `docker compose up -d` brings up a running stack, but it isn't
> fully configured yet: no admin account, no GPG signing key, no security
> databases loaded. Do these four steps in order right after first deploy.
>
> **FR** — `docker compose up -d` démarre une stack fonctionnelle, mais pas
> encore configurée : aucun compte admin, aucune clé GPG de signature,
> aucune base de sécurité chargée. Faites ces quatre étapes dans l'ordre
> juste après le premier déploiement.

1. **Create the first admin / Créer le premier admin** — open
   `http://<host>:3003`; the first-run setup wizard appears automatically
   (see [Security Warning](#security-warning--avertissement-securite)
   below).

2. **Generate a GPG signing key / Générer une clé GPG de signature** —
   Settings page → GPG section → **"Générer une nouvelle clé"** (admin
   only, `POST /settings/gpg/generate`). Do this **before uploading or
   importing your first package**.
   > `conf/distributions` (the reprepro config that tells it which key to
   > sign `Release` with) is written once, automatically, at backend
   > startup — **before** any admin has had the chance to log in and
   > generate a key, so it starts out without a signing key configured.
   > `POST /settings/gpg/generate` automatically re-initializes
   > `conf/distributions` (and re-signs RPM/APK metadata) with the new key
   > right after generating it — no separate step needed, and it's safe to
   > run even if some distributions already have packages.

3. **Sync sources / update security databases / Synchroniser les sources —
   mettre à jour les bases de sécurité** — Sources page → **"Synchroniser"**
   (`POST /import/sync/start`, maintainer+). This refreshes the Grype CVE
   database, the CISA KEV catalog, FIRST.org EPSS scores, and the upstream
   APT/RPM/APK security-source package index in one pass. It also runs
   automatically once a day (`security_sync_daily`, 03:00 by default,
   configurable from the Settings page), but on a fresh install you don't
   want to wait until 3 AM for accurate CVE data.

4. **Verify / Vérifier** — the Supervision page (`/supervision`, or `GET
   /health`) should report `"status": "healthy"` across the board once the
   steps above are done (`gpg.ok: true` in particular — see the callout in
   step 2 if it's still `false`).

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
`.env.example` → `.env` (read by `docker compose` itself) and
`backend.env.example` → `backend.env` (backend-only secrets/config, never
read by `docker-compose.yaml` itself). Full reference — every variable in
both files, not just a curated subset. **No variable is declared in both
files** — each line below appears as a literal `KEY=value` in exactly one
example file; the other file, where relevant, only carries an explanatory
comment pointing back to it.

> **EN — How the two files relate:** the `backend` service loads
> `env_file: [backend.env, .env]`, in that order — **when a Compose file
> lists more than one `env_file`, entries lower in the list win**, so a
> variable set in *both* files silently resolves to `.env`'s value. On top
> of that, `docker-compose.yaml` additionally redefines `DATABASE_URL`,
> `JWT_SECRET_KEY` and `CORS_ORIGINS` in the `backend` service's own
> `environment:` block, which in Compose always outranks *any* `env_file`
> value — so those three have **no effect at all** if set in either `.env`
> or `backend.env`; set `POSTGRES_PASSWORD` (not `DATABASE_URL` directly),
> `JWT_SECRET_KEY` and `CORS_ORIGINS` in `.env` instead, as documented in
> the tables below.
>
> **FR — Relation entre les deux fichiers :** le service `backend` charge
> `env_file: [backend.env, .env]`, dans cet ordre — **quand un fichier
> Compose liste plusieurs `env_file`, c'est le dernier de la liste qui
> gagne** en cas de clé présente dans les deux : une variable définie dans
> les *deux* fichiers prend donc silencieusement la valeur de `.env`. En
> plus de cela, `docker-compose.yaml` redéfinit également `DATABASE_URL`,
> `JWT_SECRET_KEY` et `CORS_ORIGINS` dans le bloc `environment:` du service
> `backend`, qui en Compose a toujours priorité sur *n'importe quelle*
> valeur `env_file` — ces trois variables n'ont donc **aucun effet** si
> définies dans `.env` ou dans `backend.env` : définissez plutôt
> `POSTGRES_PASSWORD` (pas `DATABASE_URL` directement), `JWT_SECRET_KEY` et
> `CORS_ORIGINS` dans `.env`, comme documenté dans les tableaux ci-dessous.

### `.env` — read by `docker compose` itself

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | PostgreSQL password — the actual source of truth for the DB password; feeds both the `db` service (initializes Postgres with it) and the `backend` service's `DATABASE_URL` (reconstructed from it), keeping the two in sync automatically. **Change from the default in production** |
| `JWT_SECRET_KEY` | Token signing secret — **required in production** (`docker-compose.yaml` hardcodes `ENV=production`, and the backend refuses to start if this is left at `change-me-in-production`). This is where it takes effect — see the precedence note above |
| `CORS_ORIGINS` | Comma-separated allowed origins. Same precedence note as `JWT_SECRET_KEY` above |
| `REACT_APP_API_URL` | Only used when building the frontend from source (`docker-compose.build.yml`) — leave empty (default), non-empty bakes an absolute URL into the JS bundle and breaks cross-host access |
| `REACT_APP_REPO_URL` | Same "build from source only" caveat. Leave empty (default) — the frontend derives the apt-repo's public URL from `window.location` at runtime for client install instructions. Only set explicitly if `APT_PORT` is remapped away from `80` |
| `REACT_APP_RPM_REPO_URL` | Same as `REACT_APP_REPO_URL`, RPM repo equivalent — leave empty unless `RPM_REPO_PORT` is remapped away from `8080` |
| `REPOD_VERSION` | Image tag to pull (`latest`, `v1.2.3`…) |
| `BIND_HOST` | `0.0.0.0` (default, ports reachable externally) or `127.0.0.1` (reverse-proxy setups — ports host-only) |
| `FRONTEND_PORT` | Host port for the frontend (default `3003`) |
| `BACKEND_PORT` | Host port for the backend API (default `8000`) |
| `APT_PORT` | Host port for the APT repo (default `80`) |
| `APT_TLS_PORT` | APT repo port when `docker-compose.tls.yml` is active (default `8085`) — port 80 is reclaimed by the TLS reverse proxy in that mode |
| `RPM_REPO_PORT` | Host port for the RPM repo (default `8080`) |
| `REPOD_DOMAIN` / `CERTBOT_EMAIL` | Optional — only used by `docker-compose.letsencrypt.yml` (public domain + ACME contact email) |
| `REPOS_NFS_MOUNT` | Optional — only used by `docker-compose.ha.yml` (shared NFS/EFS mount point for multi-replica HA, must already be mounted on every host) |

`WEBHOOK_SECRET` is *not* declared here — `docker-compose.yaml` never
redefines it, so `backend.env`'s value applies as-is; see the `backend.env`
table below (declaring it in both files would just re-introduce the
`env_file` ordering trap described above).

> `REPO_FORMAT` is **not** an overridable env var in either file — it's
> hardcoded to `all` in `docker-compose.yaml`. See [REPO_FORMAT modes](#repo_format-modes-apt--rpm--apk--all)
> above.

### `backend.env` — backend-only, via `env_file` (never read by `docker-compose.yaml` itself)

| Variable | Purpose |
|---|---|
| `JWT_EXPIRE_MINUTES` | Token lifetime in minutes (default `60`) |
| `SETTINGS_ENCRYPTION_KEY` | Encrypts secrets in `settings.json` (SMTP/LDAP password, OIDC `client_secret`); falls back to `JWT_SECRET_KEY` if unset (not recommended) |
| `REPOD_LICENSE_VENDOR_KEY` | Signs/verifies Enterprise license keys — **required in production** (startup fails immediately if unset or default; only warns in dev) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD_HASH` | Pre-provision the first admin, skipping the setup wizard — see [Security Warning](#security-warning--avertissement-securite) below |
| `SETUP_TOKEN` | Optional — protects `POST /api/v1/setup` during the window between container start and first-admin creation (requires header `X-Setup-Token`) |
| `AUTH_RATELIMIT_PER_MINUTE` | Login rate limit, requests/minute per IP (default `10`) |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_MINUTES` | Per-account lockout after N consecutive failed logins (default `5`), for M minutes (default `15`) — persistent per account, independent of the per-IP rate limit above |
| `SSH_HOST` / `SSH_USER` | Optional — **not** the Enterprise fleet-inventory feature. Powers the "Télécharger depuis Internet" button on the Packages page: the backend SSHes into the **Docker host machine** (not a remote fleet client) and runs `download-package-dep.sh` there via `apt`. Leave both empty to disable the button (returns an explicit error, no other impact). |
| `SSH_KEY_PATH` | Ed25519 private key path inside the backend container for the connection above (default `/home/appuser/.ssh/id_ed25519`) |
| `SSH_PORT` | SSH port for the same connection (default `22`) |
| `WEBHOOK_SECRET` | HMAC secret verifying `X-Hub-Signature-256` on `/webhooks/github` and `/webhooks/kev` — **required in production** |
| `WEBHOOK_SIGNATURE_SKIP` | Bypasses that signature check — **dev/test only, never enable in production** (default `false`) |
| `METRICS_TOKEN` | Optional Bearer token protecting `GET /metrics` (Prometheus) — unset means unauthenticated |
| `MANIFEST_CACHE_TTL` | In-memory `.deb`/`.rpm`/`.apk` metadata cache TTL, seconds (default `30`) |
| `SQL_ECHO` | Logs every SQL statement executed by SQLAlchemy — debug only, very verbose |
| `EMAIL_TEMPLATES_DIR` / `AUTH_DIR` | Email template overrides / password-reset tokens (defaults `/repos/templates/email`, `/repos/auth`). ⚠ Neither has a dedicated volume in the default `docker-compose.yaml` — contents don't survive a `backend` container recreate unless you add your own bind mount |
| `REPREPRO_DISTS` / `REPREPRO_CONTAINER` | Advanced, APT-only — default distribution list used by `remove_package()` when none is passed explicitly (default `jammy,noble,focal,bookworm`, keep in sync with `services/distributions_apt.py:VALID_CODENAMES` if you change it), and the container name used only when calling it with `via_docker=True` (dev-only, e.g. `docker-compose.dev.yml`) |

`POOL_DIR`, `MANIFEST_DIR`, `STAGING_INCOMING`, `STAGING_QUARANTINE`,
`AUDIT_DIR`, `INDEX_PATH`, `ADD_DEB_SCRIPT`, `ADD_RPM_SCRIPT`, `IMPORTS_DIR`,
`CLAMAV_DB_DIR`, `SETTINGS_PATH`, `GRYPE_DB_CACHE_DIR`, `SECURITY_CACHE_DIR`,
`NGINX_LOGS_DIR`, `GNUPG_HOME`, `REPREPRO_BASE`, `DISTS_DIR`, `CONF_DIR`,
`REPO_BASE`, `APK_REPO_BASE`, `TRUSTED_PROXIES` are **not** in
`backend.env.example` at all — they're internal paths hardcoded in the
`environment:` block of `docker-compose.yaml`, coupled one-to-one to its own
volume declarations. Only change these directly in `docker-compose.yaml`,
in lockstep with its volumes.

---

## Uninstall & Reinstall / Desinstallation et reinstallation

> **EN** — Full teardown removes every container, image, network, and **all
> persisted data** — PostgreSQL and everything under `./repos/` (uploaded
> packages, manifests, GPG keyring, audit log, settings). This is
> irreversible. If you need to keep anything, back it up first (see
> `backup.sh`) before running this.
>
> **FR** — Une désinstallation complète supprime tous les conteneurs,
> images, réseaux, et **toutes les données persistées** — PostgreSQL et
> tout ce qui se trouve sous `./repos/` (paquets uploadés, manifests,
> trousseau GPG, journal d'audit, réglages). C'est irréversible. Si vous
> devez conserver quelque chose, faites une sauvegarde avant (voir
> `backup.sh`).

### Uninstall / Désinstallation

```bash
# 1. Stop and remove containers, network, and the named Postgres volume
docker compose down -v --remove-orphans

# 2. Remove every Repod image (forces a fresh pull on next install)
docker images --format '{{.Repository}}:{{.Tag}}' | grep '^ghcr.io/repod-ce/' | xargs -r docker rmi -f

# 3. Wipe persisted data and local config
sudo rm -rf repos/*
rm -f .env backend.env
```

> ⚠ **`docker compose down -v` only removes the named Docker volume**
> (`postgres_data`) — it does **not** touch `./repos/`, which is a bind
> mount, not a Docker volume. Skip step 3 (or only remove specific
> subdirectories of `repos/`) if you want to reinstall while **keeping**
> your existing packages/settings/GPG key; run it in full for a genuinely
> clean slate.

### Reinstall / Réinstallation

```bash
# Optional — only if you also want to update Repod itself
git pull

cp .env.example .env
cp backend.env.example backend.env
# Edit both files — see "Environment variables" above. For a real fresh
# install, generate brand-new secrets (don't reuse old ones, unless you
# deliberately kept the PostgreSQL volume/repos data from step 3 above and
# need continuity — in that case POSTGRES_PASSWORD in particular MUST match
# the value Postgres was originally initialized with, or the backend won't
# be able to authenticate).

docker compose pull
docker compose up -d
```

Then repeat [Post-deployment setup](#post-deployment-setup--configuration-post-deploiement)
above — create the first admin, generate a GPG key (and re-init
distributions), sync sources — a fresh database means all of that starts
from zero again.

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
