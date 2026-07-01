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
                    +-------------+-------------+
                    |             |             |
              +-----+-----+ +----+----+ +-----+-----+
              | ClamAV    | | Grype   | | reprepro  |
              | Antivirus | | CVE DB  | | createrepo|
              +-----------+ +---------+ +-----------+
                                  |
                         +--------+----------+
                         | APT/RPM/APK Repo  |
                         | nginx :80         |
                         +-------------------+
```

3 Docker containers: `frontend` (Nginx/React :3003) - `backend` (FastAPI :8000) - `apt-repo` (Nginx+reprepro :80)

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

## Community vs Enterprise

> **EN** -- This **Community** edition is production-ready for managing an
> APT/RPM/APK repository with ClamAV/Grype scanning, RBAC, audit logging,
> package import, and a health dashboard. Advanced features (fleet inventory,
> SSH scanning, remote deployment, automated backups, LDAP/OIDC/MFA,
> webhooks, SLA alerts, scheduled mirroring, high availability) are **visible
> in the UI but locked** -- they require an **Enterprise** license.
>
> **FR** -- Cette edition **Community** est complete et utilisable en
> production. Certaines fonctionnalites avancees (inventaire de flotte, scan
> SSH, deploiement distant, sauvegardes automatisees, LDAP/OIDC/MFA,
> webhooks, alertes SLA, mirroring planifie, haute disponibilite) sont
> **visibles dans l'interface mais verrouillees** -- elles necessitent une
> licence **Enterprise**.

See [getrepod.com/#pricing](https://getrepod.com/#pricing).

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
