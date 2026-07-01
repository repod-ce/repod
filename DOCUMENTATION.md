# APT Repo Manager — Documentation

> Gestionnaire de dépôt APT privé avec interface web, validation de paquets, gestion des utilisateurs et synchronisation automatique des sources de sécurité.

---

## Table des matières

1. [Architecture](#1-architecture)
2. [Prérequis](#2-prérequis)
3. [Installation et démarrage rapide](#3-installation-et-démarrage-rapide)
4. [Configuration](#4-configuration)
5. [Premier démarrage](#5-premier-démarrage)
6. [Fonctionnalités](#6-fonctionnalités)
7. [Gestion des utilisateurs et rôles](#7-gestion-des-utilisateurs-et-rôles)
8. [Configuration du dépôt APT côté client](#8-configuration-du-dépôt-apt-côté-client)
9. [Commandes de dépannage](#9-commandes-de-dépannage)
10. [Points d'attention pour la production](#10-points-dattention-pour-la-production)
11. [Structure des fichiers](#11-structure-des-fichiers)

---

## 1. Architecture

Le projet est composé de quatre services Docker :

```
┌─────────────────────────────────────────────────────┐
│                    Réseau Docker                     │
│                                                     │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │   frontend   │    │        backend           │   │
│  │  React/Nginx │    │   FastAPI + uvicorn       │   │
│  │  port 3000   │───▶│   port 8000              │   │
│  └──────────────┘    │   ClamAV intégré         │   │
│                      └──────────┬───────────────┘   │
│                                 │ docker exec        │
│  ┌──────────────────────────────▼───────────────┐   │
│  │              apt-repo                        │   │
│  │        Nginx + reprepro                      │   │
│  │        port 80 (dépôt APT)                   │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘

Volumes partagés :
  ./repos/pool          → fichiers .deb
  ./repos/manifests     → métadonnées des paquets
  ./repos/staging       → zone de staging (incoming / quarantine)
  ./repos/audit         → journaux d'audit (JSONL)
  ./repos/auth          → base SQLite des utilisateurs
  ./repos/clamav-db     → signatures ClamAV
  ./repos/package-index → index SQLite des sources APT externes
  ./.gnupg              → clé GPG de signature du dépôt
```

### Flux d'un upload de paquet

```
Client → POST /upload/ → staging/incoming/
                       → validation (format, SHA256, ClamAV, GPG, dépendances)
                         ├─ échec → staging/quarantine/  (audit FAILURE)
                         └─ succès → pool/  →  reprepro includedeb  →  dists/
                                    → manifest.json → index.json
                                    → audit SUCCESS
```

---

## 2. Prérequis

| Composant | Version minimale |
|-----------|-----------------|
| Docker Engine | 24.x |
| Docker Compose | v2.x (`docker compose`) |
| RAM | 2 Go minimum, 4 Go recommandé (ClamAV) |
| Disque | 20 Go minimum pour le pool de paquets |

---

## 3. Installation et démarrage rapide

```bash
# 1. Cloner le dépôt
git clone <url-du-repo> && cd repodata

# 2. Créer les fichiers de configuration
cp .env.example .env
cp backend.env.example backend.env

# 3. Adapter les URLs dans .env
#    PUBLIC_URL, REACT_APP_API_URL, REACT_APP_REPO_URL

# 4. Construire et démarrer
docker compose up -d --build

# 5. Vérifier que les services sont up
docker compose ps
```

Se connecter sur `http://<IP>:3000` avec `admin` / `changeme`.

> **Changer le mot de passe admin immédiatement après le premier login** (menu Utilisateurs → Réinitialiser).

---

## 4. Configuration

### 4.1 Fichier `.env` (docker-compose)

| Variable | Description | Exemple |
|----------|-------------|---------|
| `PUBLIC_URL` | URL publique du frontend | `http://<host>:3000` (ex. `http://192.0.2.10:3000`) |
| `REACT_APP_API_URL` | URL de l'API backend (injectée au build React) — laisser vide en production | (vide) |
| `REACT_APP_REPO_URL` | URL du dépôt APT pour les clients | `http://<host>:80` (ex. `http://192.0.2.10:80`) |
| `APP_VERSION` | Tag d'image Docker | `v1.0.0` |

> `<host>` désigne l'IP ou le nom de domaine de **votre** serveur Repod — remplacez-le par votre propre adresse (les exemples `192.0.2.10` utilisent une plage réservée à la documentation, RFC 5737).

> `REACT_APP_API_URL` est **injectée au moment du build Docker** du frontend. Changer cette variable nécessite un `docker compose build frontend`.

### 4.2 Fichier `backend.env` (secrets backend)

| Variable | Description | Obligatoire en prod |
|----------|-------------|---------------------|
| `JWT_SECRET_KEY` | Clé de signature des tokens JWT | ✅ Générer avec `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `JWT_EXPIRE_MINUTES` | Durée de vie des tokens (défaut : 60) | Non |
| `ADMIN_USERNAME` | Nom du compte admin initial | Non (défaut : `admin`) |
| `ADMIN_PASSWORD_HASH` | Hash bcrypt du mot de passe admin | ✅ Voir ci-dessous |
| `CORS_ORIGINS` | Origines CORS autorisées (virgule-séparées) | ✅ |
| `AUTH_RATELIMIT_PER_MINUTE` | Limite de requêtes d'auth par IP/min | Non (non appliqué actuellement) |
| `SSH_HOST` | IP hôte pour SSH (download-package-dep.sh) | Si feature SSH utilisée |
| `POOL_DIR` | Chemin du pool de paquets | Non (défaut dans docker-compose) |
| `SETTINGS_PATH` | Chemin du fichier settings.json | Non (défaut dans docker-compose) |

**Générer un hash bcrypt pour le mot de passe admin :**
```bash
docker run --rm python:3.12-slim python3 -c \
  "from passlib.hash import bcrypt; print(bcrypt.hash('VOTRE_MOT_DE_PASSE').replace('\$', '\$\$'))"
```

### 4.3 Paramètres applicatifs (`/settings/` dans l'UI)

Ces paramètres sont stockés dans `/repos/settings.json` et modifiables via l'interface :

| Section | Clé | Description |
|---------|-----|-------------|
| `sync` | `enabled` | Active/désactive la sync automatique |
| `sync` | `hour` / `minute` | Heure du cron quotidien (Europe/Paris) |
| `sources` | `ubuntu-jammy` etc. | Active/désactive les sources APT externes |
| `notifications` | `webhook_url` | URL Slack/Teams/Mattermost pour les rapports de sync |
| `notifications` | `webhook_enabled` | Active les notifications |
| `retention` | `audit_days` | Rétention des logs d'audit en jours |
| `validation` | `sha256_check` | Vérifie le SHA256 à l'import |
| `validation` | `clamav_scan` | Active le scan ClamAV |
| `validation` | `max_upload_size_mb` | Taille max d'upload (non encore appliquée au niveau HTTP) |

---

## 5. Premier démarrage

### 5.1 Initialisation automatique

Au démarrage, le backend :
1. Initialise la base SQLite `users.db` et crée le compte admin si elle est vide
2. Démarre le scheduler APScheduler pour la sync sécurité quotidienne
3. Démarre freshclam daemon pour les mises à jour ClamAV (toutes les 12h)

Le container `apt-repo` :
1. Génère une clé GPG si elle n'existe pas (stockée dans `.gnupg`)
2. Génère le fichier `conf/distributions`
3. Initialise les répertoires reprepro

### 5.2 Initialisation des distributions APT

Après le premier démarrage, aller dans **Distributions → Initialiser** pour créer les métadonnées reprepro de toutes les distributions (`jammy`, `noble`, `focal`, `bookworm`).

### 5.3 Vérification post-démarrage

```bash
# Vérifier que tous les containers tournent
docker compose ps

# Tester l'API
curl http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Vérifier le dépôt APT
curl -I http://localhost:80/repos/

# Consulter les logs
docker compose logs -f backend
docker compose logs -f apt-repo
```

---

## 6. Fonctionnalités

### 6.1 Upload de paquets

**Via l'interface** → Onglet *Upload*
**Via l'API :**
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}' | jq -r .access_token)

curl -X POST http://localhost:8000/upload/ \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@monpaquet_1.0.0_amd64.deb" \
  -F "distribution=jammy"
```

**Pipeline de validation :**
1. Format `.deb` (dpkg-deb --info)
2. SHA256 vs index Packages.gz (si paquet importé depuis internet)
3. Scan ClamAV
4. Vérification signature GPG (optionnel)
5. Résolution des dépendances (avertissement, non bloquant)

### 6.2 Import depuis internet

L'import télécharge un paquet et ses dépendances directement depuis les miroirs APT indexés (Ubuntu, Debian).

**Prérequis :** lancer une synchronisation des sources d'abord (Onglet *Import → Synchroniser*).

```
Onglet Import → Rechercher "curl" → Importer avec dépendances
```

Les paquets sont regroupés par *groupe d'import* pour faciliter la traçabilité.

### 6.3 Synchronisation des sources de sécurité

Sources gérées : Ubuntu Jammy/Noble/Focal security, Debian Bookworm security.

- **Automatique** : cron quotidien à l'heure configurée dans les paramètres
- **Manuel** : Onglet *Import → Sync sécurité*
- **Notification** : webhook Slack/Teams configurable

### 6.4 Distributions

Le dépôt supporte plusieurs distributions simultanées :

| Codename | OS |
|----------|----|
| `jammy` | Ubuntu 22.04 LTS |
| `noble` | Ubuntu 24.04 LTS |
| `focal` | Ubuntu 20.04 LTS |
| `bookworm` | Debian 12 |

**Promotion** : déplacer un paquet d'une distribution de staging vers la production.
**Migration** : copier tous les paquets d'une distribution vers une autre.

### 6.5 Audit

Toutes les actions (upload, import, suppression, login, sync) sont journalisées en JSONL dans `repos/audit/YYYY-MM-DD.jsonl`.

```bash
# Lire les logs du jour
cat repos/audit/$(date +%Y-%m-%d).jsonl | jq .
```

---

## 7. Gestion des utilisateurs et rôles

### Rôles disponibles

| Rôle | Permissions |
|------|-------------|
| `admin` | Tout : utilisateurs, paramètres, toutes opérations |
| `maintainer` | Upload, import, suppression, promotion, sync, lecture audit |
| `uploader` | Upload et import uniquement |
| `auditor` | Lecture de tout + accès aux logs d'audit, aucune modification |
| `reader` | Lecture seule des paquets |

### Gestion via l'API

```bash
# Créer un utilisateur
curl -X POST http://localhost:8000/auth/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"cicd","password":"motdepasse","role":"uploader"}'

# Lister les utilisateurs
curl http://localhost:8000/auth/users \
  -H "Authorization: Bearer $TOKEN"

# Changer son propre mot de passe
curl -X POST http://localhost:8000/auth/change-password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"current_password":"changeme","new_password":"nouveau_mdp"}'
```

---

## 8. Configuration du dépôt APT côté client

### 8.1 Ajouter la clé GPG

```bash
# Télécharger et importer la clé publique du dépôt
curl -fsSL http://<IP-REPO>:80/repos/depot.gpg | sudo gpg --dearmor \
  -o /etc/apt/keyrings/depot-apt.gpg
```

### 8.2 Ajouter la source APT

```bash
echo "deb [signed-by=/etc/apt/keyrings/depot-apt.gpg] \
  http://<IP-REPO>:80/repos jammy main" \
  | sudo tee /etc/apt/sources.list.d/depot-prive.list

sudo apt update
```

### 8.3 Installer un paquet

```bash
sudo apt install <nom-du-paquet>
```

---

## 9. Commandes de dépannage

### Statut général

```bash
# État de tous les containers
docker compose ps

# Logs en temps réel
docker compose logs -f
docker compose logs -f backend
docker compose logs -f apt-repo
docker compose logs -f frontend

# Utilisation des ressources
docker stats
```

### Problèmes d'authentification

```bash
# Tester le login directement
curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'

# Vérifier les utilisateurs dans la DB
docker exec backend-api python3 -c "
import sqlite3
conn = sqlite3.connect('/repos/auth/users.db')
rows = conn.execute('SELECT username, role, active FROM users').fetchall()
for r in rows: print(r)
"

# Réinitialiser le mot de passe admin directement en DB
docker exec backend-api python3 -c "
from passlib.hash import bcrypt
import sqlite3
h = bcrypt.hash('nouveau_mdp')
conn = sqlite3.connect('/repos/auth/users.db')
conn.execute(\"UPDATE users SET hashed_password=? WHERE username='admin'\", (h,))
conn.commit()
print('OK')
"
```

### Problèmes CORS / API injoignable

```bash
# Vérifier les origines CORS configurées
docker exec backend-api env | grep CORS

# Tester la connectivité entre frontend et backend (depuis le container frontend)
docker exec frontend-ui wget -qO- http://backend-api:8000/auth/token

# Vérifier que REACT_APP_API_URL est correcte dans l'image frontend
docker exec frontend-ui env | grep REACT_APP
# (Note: variables React sont baked au build, pas visibles via env en runtime)
# Inspecter le JS compilé :
docker exec frontend-ui grep -o 'REACT_APP_API_URL[^"]*' \
  /usr/share/nginx/html/static/js/*.js 2>/dev/null | head -3
```

### Problèmes reprepro / dépôt APT

```bash
# Vérifier les distributions initialisées
docker exec depot-apt reprepro -b /usr/share/nginx/html/repos list jammy

# Lister tous les paquets d'une distribution
docker exec depot-apt reprepro -b /usr/share/nginx/html/repos listmatched jammy '*'

# Ajouter manuellement un .deb
docker exec depot-apt reprepro -b /usr/share/nginx/html/repos \
  includedeb jammy /usr/share/nginx/html/repos/pool/monpaquet_1.0.0_amd64.deb

# Supprimer un paquet d'une distribution
docker exec depot-apt reprepro -b /usr/share/nginx/html/repos \
  remove jammy nom-du-paquet

# Vérifier la config GPG et les clés
docker exec depot-apt gpg --list-keys

# Exporter la clé publique manuellement
docker exec depot-apt gpg --output /usr/share/nginx/html/repos/depot.gpg \
  --export $(docker exec depot-apt gpg --list-keys --with-colons | awk -F: '/^pub:/{print $5}')
```

### Problèmes ClamAV

```bash
# Statut ClamAV
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/security/clamav/status | jq

# Logs freshclam
docker exec backend-api cat /var/log/freshclam.log 2>/dev/null || \
  docker compose logs backend | grep -i clamav

# Mise à jour manuelle de la base ClamAV
docker exec backend-api freshclam --datadir=/var/lib/clamav

# Tester un scan
docker exec backend-api clamscan --no-summary /repos/pool/monpaquet_1.0.0_amd64.deb

# Si ClamAV échoue (DB corrompue)
docker exec backend-api rm -f /var/lib/clamav/*.cvd /var/lib/clamav/*.cld
docker compose restart backend
```

### Problèmes d'index

```bash
# Resynchroniser l'index depuis les manifests (via API)
curl -X POST http://localhost:8000/artifacts/admin/sync-index \
  -H "Authorization: Bearer $TOKEN"

# Inspecter l'index directement
docker exec backend-api cat /repos/manifests/index.json | python3 -m json.tool | head -50

# Lister les manifests disponibles
docker exec backend-api ls /repos/manifests/*.manifest.json 2>/dev/null | wc -l

# Vérifier le pool
docker exec backend-api ls /repos/pool/*.deb 2>/dev/null | wc -l
```

### Reconstruire un service sans tout arrêter

```bash
# Reconstruire et redémarrer seulement le frontend (si .env a changé)
docker compose up -d --build frontend

# Reconstruire le backend
docker compose up -d --build backend

# Redémarrer un service sans rebuild
docker compose restart backend
docker compose restart apt-repo
```

### Arrêt et nettoyage

```bash
# Arrêter sans supprimer les données
docker compose down

# Arrêter et supprimer les images (les volumes/données sont conservés)
docker compose down --rmi all

# DANGER : tout supprimer y compris les volumes (perte de données !)
docker compose down -v --rmi all
```

### Vérifier les logs d'audit applicatifs

```bash
# Logs du jour
cat repos/audit/$(date +%Y-%m-%d).jsonl | python3 -m json.tool

# Dernières actions
ls -t repos/audit/*.jsonl | head -1 | xargs tail -20 | python3 -m json.tool

# Filtrer les échecs
cat repos/audit/*.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('status') in ('FAILURE','ERROR'):
            print(json.dumps(e, indent=2))
    except: pass
"
```

---

## 10. Points d'attention pour la production

### Priorité CRITIQUE — à corriger avant exposition publique

| # | Problème | Correction |
|---|----------|------------|
| 1 | **Docker socket exposé au backend** | Remplacer `docker exec` par un socket Unix dédié ou un agent reprepro séparé |
| 2 | **Backend tourne en root** | Ajouter `USER appuser` dans le `Dockerfile` backend |
| 3 | **Pas de rate limiting sur `/auth/token`** | Intégrer `slowapi` ou `fastapi-limiter` |
| 4 | **Paramètre `distribution` non validé** | Valider contre `VALID_CODENAMES` avant d'appeler le script shell |
| 5 | **Token JWT non invalidé à la désactivation** | Vérifier `active=1` dans la DB au moment de `get_current_user` |

### Priorité ÉLEVÉE

| # | Problème | Correction |
|---|----------|------------|
| 6 | **Pas de TLS** | Ajouter un service Caddy ou nginx reverse proxy avec certificats Let's Encrypt |
| 7 | **Port 8000 exposé directement** | Lier à `127.0.0.1:8000` et passer par le reverse proxy |
| 8 | **Dépendances Python non épinglées** | Épingler toutes les versions dans `requirements.txt` |
| 9 | **Pas de limite de taille HTTP** | Ajouter `client_max_body_size` dans nginx et validation dans le code |
| 10 | **`add_package.py` avec `shell=True`** | Supprimer ce fichier ou réécrire sans `shell=True` |

### Recommandations opérationnelles

```bash
# Changer le mot de passe admin après installation
# Générer une vraie clé JWT
python3 -c "import secrets; print(secrets.token_hex(32))"

# Sauvegarder régulièrement
tar -czf backup-$(date +%Y%m%d).tar.gz \
  repos/auth/users.db \
  repos/manifests/ \
  .gnupg/ \
  repos/conf/
```

---

## 11. Structure des fichiers

```
repodata/
├── .env                    ← Variables docker-compose (ne pas committer)
├── .env.example            ← Modèle .env
├── backend.env             ← Secrets backend (ne pas committer)
├── backend.env.example     ← Modèle backend.env
├── docker-compose.yaml     ← Orchestration des 3 services
├── Dockerfile              ← Image apt-repo (nginx + reprepro)
│
├── backend/
│   ├── Dockerfile
│   ├── entrypoint.sh       ← Démarre ClamAV daemon puis uvicorn
│   ├── main.py             ← App FastAPI + scheduler APScheduler
│   ├── requirements.txt
│   ├── auth/               ← JWT, rôles, gestion utilisateurs SQLite
│   ├── routers/            ← Endpoints FastAPI
│   └── services/           ← Logique métier (validation, index, audit...)
│
├── frontend/
│   ├── Dockerfile          ← Build React + Nginx
│   ├── nginx.conf
│   └── src/
│       ├── api.js          ← Client Axios (REACT_APP_API_URL)
│       ├── context/AuthContext.js
│       ├── pages/          ← LoginPage, DashboardPage, ImportPage...
│       └── components/
│
├── nginx/
│   └── repo.conf           ← Config nginx du dépôt APT (port 80)
│
├── scripts/
│   ├── add-deb.sh          ← Wrapper reprepro includedeb via docker exec
│   └── init-repo.sh        ← Génération clé GPG + init reprepro
│
└── repos/                  ← Données persistantes (volumes Docker)
    ├── auth/users.db       ← Base SQLite des utilisateurs
    ├── pool/               ← Fichiers .deb
    ├── manifests/          ← Métadonnées JSON de chaque paquet
    ├── staging/            ← incoming/ et quarantine/
    ├── audit/              ← Logs JSONL par date
    ├── package-index/      ← Index SQLite des sources APT externes
    ├── clamav-db/          ← Signatures ClamAV
    └── conf/distributions  ← Configuration reprepro
```
