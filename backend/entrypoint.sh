#!/bin/bash
set -e

CLAMAV_DB_DIR="${CLAMAV_DB_DIR:-/var/lib/clamav}"
ENV="${ENV:-development}"

# ─── ClamAV (root requis) ────────────────────────────────────────────────────

echo "[entrypoint] Initialisation ClamAV..."

chown -R clamav:clamav "$CLAMAV_DB_DIR" 2>/dev/null || true
chmod -R g+w "$CLAMAV_DB_DIR" 2>/dev/null || true   # appuser peut écrire via groupe clamav
usermod -aG clamav appuser 2>/dev/null || true        # appuser rejoint le groupe clamav
mkdir -p /var/log/clamav && chown clamav:clamav /var/log/clamav && chmod g+w /var/log/clamav 2>/dev/null || true

if [ ! -f "$CLAMAV_DB_DIR/main.cvd" ] && [ ! -f "$CLAMAV_DB_DIR/main.cld" ]; then
    echo "[entrypoint] Base ClamAV absente — téléchargement initial..."
    freshclam --datadir="$CLAMAV_DB_DIR" 2>&1 | tail -5 || echo "[entrypoint] Avertissement: freshclam initial échoué (mode offline ?)"
else
    echo "[entrypoint] Base ClamAV trouvée dans le volume."
fi

echo "[entrypoint] Démarrage freshclam daemon (mises à jour automatiques)..."
freshclam --daemon \
    --datadir="$CLAMAV_DB_DIR" \
    --log=/var/log/freshclam.log \
    --checks=2 \
    2>/dev/null || echo "[entrypoint] freshclam daemon non disponible"

# ─── clamd daemon (signatures chargées une fois en mémoire) ──────────────────
echo "[entrypoint] Démarrage clamd daemon..."
mkdir -p /var/run/clamav
chown clamav:clamav /var/run/clamav
clamd 2>/dev/null &
CLAMD_PID=$!
# Attendre que le socket soit prêt (max 30s)
for i in $(seq 1 30); do
    if [ -S /var/run/clamav/clamd.ctl ]; then
        echo "[entrypoint] clamd prêt (socket OK)."
        # Rendre le socket accessible à appuser
        chmod 666 /var/run/clamav/clamd.ctl 2>/dev/null || true
        break
    fi
    sleep 1
done
if [ ! -S /var/run/clamav/clamd.ctl ]; then
    echo "[entrypoint] Avertissement: clamd socket non disponible — les scans utiliseront clamscan en fallback."
fi

# ─── Permissions volumes (root requis, avant le drop) ────────────────────────

echo "[entrypoint] Correction des permissions sur les volumes..."

for DIR in \
    /repos/apk \
    /repos/audit \
    /repos/auth \
    /repos/backups \
    /repos/conf \
    /repos/db \
    /repos/dists \
    /repos/grype-db \
    /repos/imports \
    /repos/logs \
    /repos/manifests \
    /repos/package-index \
    /repos/pool \
    /repos/security \
    /repos/staging; do
    if [ -d "$DIR" ]; then
        chown -R appuser:appuser "$DIR" 2>/dev/null || true
    fi
done

# Répertoires distributions RPM — créer si absents PUIS corriger ownership
# (Docker crée les bind-mounts manquants en root:root, appuser ne peut pas écrire)
# REPO_BASE peut valoir /repos (mode rpm seul) ou /repos/rpm (mode both)
RPM_REPO_BASE="${REPO_BASE:-/repos}"
for DISTRO in almalinux8 almalinux9 rocky8 rocky9 centos-stream9 oraclelinux8 \
              oraclelinux9 fedora opensuse-leap-15.5 opensuse-leap-15.6 \
              opensuse-leap opensuse-tumbleweed; do
    for ARCH in x86_64 aarch64 noarch; do
        mkdir -p "${RPM_REPO_BASE}/${DISTRO}/${ARCH}/repodata" 2>/dev/null || true
    done
    chown -R appuser:appuser "${RPM_REPO_BASE}/${DISTRO}" 2>/dev/null || true
done

# Trousseau GPG partagé (remplace le docker socket pour les opérations GPG)
GNUPG_DIR="${GNUPG_HOME:-/repos/gnupg}"
if [ -d "$GNUPG_DIR" ]; then
    chown -R appuser:appuser "$GNUPG_DIR" 2>/dev/null || true
    chmod 700 "$GNUPG_DIR" 2>/dev/null || true
elif [ -n "$GNUPG_DIR" ]; then
    mkdir -p "$GNUPG_DIR" && chown appuser:appuser "$GNUPG_DIR" && chmod 700 "$GNUPG_DIR" || true
fi

# Templates email — services/email_templates.py:_ensure_defaults() les crée
# lui-même à la volée au premier GET /templates, mais fait un mkdir(parents=True)
# depuis appuser : jamais présent dans aucun bind mount déclaré par
# docker-compose.yaml (contrairement à pool/dists/manifests/...), donc
# /repos/templates n'existe pas encore au premier démarrage et /repos lui-même
# n'est pas writable par appuser (root:root 755) — la création échoue avec
# PermissionError, jamais rattrapée, et la page Templates email reste
# silencieusement vide (l'erreur 500 n'est pas affichée, juste catch{} côté
# frontend). Pré-créer le répertoire ici, comme pour GNUPG_DIR ci-dessus.
TEMPLATES_DIR="${EMAIL_TEMPLATES_DIR:-/repos/templates/email}"
mkdir -p "$TEMPLATES_DIR" && chown -R appuser:appuser "$(dirname "$TEMPLATES_DIR")" || true

# settings.json et son répertoire parent
SETTINGS_FILE="${SETTINGS_PATH:-/repos/settings.json}"
SETTINGS_DIR="$(dirname "$SETTINGS_FILE")"
chown appuser:appuser "$SETTINGS_DIR" 2>/dev/null || true
# Si le fichier hôte n'existait pas au premier `up`, Docker a créé un
# répertoire vide à la place du bind-mount fichier — le remplacer par un
# fichier JSON vide pour que le backend puisse le lire/écrire normalement.
if [ -d "$SETTINGS_FILE" ]; then
    rmdir "$SETTINGS_FILE" 2>/dev/null && echo '{}' > "$SETTINGS_FILE"
fi
if [ -f "$SETTINGS_FILE" ]; then
    chown appuser:appuser "$SETTINGS_FILE" 2>/dev/null || true
fi

# ─── Auto-génération des secrets au premier démarrage ────────────────────────

GENERATED_ENV="/repos/.generated-secrets"
if [ -z "$JWT_SECRET_KEY" ] || [ "$JWT_SECRET_KEY" = "change-me-in-production" ]; then
    if [ ! -f "$GENERATED_ENV" ]; then
        echo "[entrypoint] Premier démarrage — génération des secrets..."
        cat > "$GENERATED_ENV" <<SECRETS
JWT_SECRET_KEY=$(openssl rand -hex 32)
WEBHOOK_SECRET=$(openssl rand -hex 32)
SETTINGS_ENCRYPTION_KEY=$(openssl rand -hex 32)
REPOD_LICENSE_VENDOR_KEY=$(openssl rand -hex 32)
SECRETS
        chown appuser:appuser "$GENERATED_ENV" 2>/dev/null || true
        chmod 600 "$GENERATED_ENV"
        echo "[entrypoint] Secrets générés dans $GENERATED_ENV"
    fi
    echo "[entrypoint] Chargement des secrets auto-générés..."
    set -a
    . "$GENERATED_ENV"
    set +a
fi

# ─── Certificat TLS auto-signé ──────────────────────────────────────────────

CERT_DIR="/repos/certs"
if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "[entrypoint] Génération du certificat TLS auto-signé (10 ans)..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -subj "/CN=repod/O=Repod/C=FR" \
        2>/dev/null || true
    if [ -f "$CERT_DIR/server.crt" ]; then
        chmod 600 "$CERT_DIR/server.key" 2>/dev/null || true
        chown -R appuser:appuser "$CERT_DIR" 2>/dev/null || true
        echo "[entrypoint] Certificat TLS créé: $CERT_DIR/server.crt"
    else
        echo "[entrypoint] Avertissement: génération TLS échouée (mode HTTP uniquement)"
    fi
else
    echo "[entrypoint] Certificat TLS existant trouvé."
fi

# ─── Migrations Alembic (PostgreSQL) ─────────────────────────────────────────

echo "[entrypoint] Attente PostgreSQL et exécution des migrations Alembic..."
# Lancer les migrations en tant qu'appuser (DATABASE_URL doit être défini)
if [ -n "$DATABASE_URL" ]; then
    gosu appuser python -m alembic upgrade head && echo "[entrypoint] Migrations OK." \
        || echo "[entrypoint] AVERTISSEMENT : migrations Alembic échouées (DB non disponible ?)"
else
    echo "[entrypoint] AVERTISSEMENT : DATABASE_URL non défini — migrations ignorées."
fi

# ─── Drop de privilèges → appuser ────────────────────────────────────────────

# Résolution des IPs de confiance pour le reverse-proxy
TRUSTED_PROXIES="${TRUSTED_PROXIES:-127.0.0.1}"

if [ "$ENV" = "production" ]; then
    echo "[entrypoint] Mode PRODUCTION — démarrage sans rechargement automatique"
    exec gosu appuser python -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --proxy-headers \
        --forwarded-allow-ips="${TRUSTED_PROXIES}" \
        --workers 1
else
    echo "[entrypoint] Mode DÉVELOPPEMENT — rechargement automatique activé"
    exec gosu appuser python -m uvicorn main:app \
        --host 0.0.0.0 \
        --port 8000 \
        --proxy-headers \
        --forwarded-allow-ips="*" \
        --reload
fi
