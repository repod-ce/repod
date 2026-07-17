#!/bin/bash
# =============================================================================
# backup.sh — Sauvegarde de production APT Repo Manager
# =============================================================================
# Usage :
#   ./backup.sh                    → backup dans ./backups/ (défaut)
#   BACKUP_DIR=/mnt/nas ./backup.sh → backup vers un NAS
#   ./backup.sh --dry-run           → liste ce qui serait sauvegardé
# =============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-$(pwd)/backups}"
REPOS_DIR="${REPOS_DIR:-$(pwd)/repos}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="repod_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"
DRY_RUN=false
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# ── Parsing des arguments ─────────────────────────────────────────────────────
for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=true ;;
        *) echo "Usage: $0 [--dry-run]"; exit 1 ;;
    esac
done

# ── Couleurs ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${GREEN}[backup]${NC} $*"; }
warn() { echo -e "${YELLOW}[backup]${NC} $*"; }
fail() { echo -e "${RED}[backup]${NC} $*" >&2; exit 1; }

# ── Vérifications préliminaires ───────────────────────────────────────────────
[ -d "$REPOS_DIR" ] || fail "Répertoire repos introuvable : $REPOS_DIR"

if $DRY_RUN; then
    warn "Mode DRY-RUN — aucune écriture"
    if [ -n "${DATABASE_URL:-}" ]; then
        log "  + base PostgreSQL (pg_dump via DATABASE_URL)"
    else
        warn "  - base PostgreSQL (DATABASE_URL non défini, NON sauvegardée)"
    fi
    log "Répertoires qui seraient sauvegardés :"
    for d in pool manifests audit security gnupg settings.json; do
        path="$REPOS_DIR/$d"
        [ -e "$path" ] && log "  + $path" || warn "  - $path (absent)"
    done
    exit 0
fi

mkdir -p "$BACKUP_PATH"
log "Début de la sauvegarde → ${BACKUP_PATH}"

# ── 1. Base de données PostgreSQL (users, manifests, inventaire, CVE, ...) ───
if [ -n "${DATABASE_URL:-}" ]; then
    if command -v pg_dump &>/dev/null; then
        pg_dump "$DATABASE_URL" -F c -f "$BACKUP_PATH/postgres.dump"
        log "Base PostgreSQL sauvegardée (pg_dump, format custom : postgres.dump)"
    else
        fail "pg_dump introuvable — impossible de sauvegarder la base PostgreSQL (DATABASE_URL=${DATABASE_URL})"
    fi
else
    fail "DATABASE_URL non défini — impossible de sauvegarder la base PostgreSQL. Définissez DATABASE_URL=postgresql://user:pass@host:5432/repod"
fi

# ── 1bis. Base SQLite legacy (anciennes installations pré-migration Postgres) ─
if [ -f "$REPOS_DIR/auth/users.db" ]; then
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$REPOS_DIR/auth/users.db" ".backup '$BACKUP_PATH/users.db'"
        log "users.db legacy sauvegardée (sqlite3 .backup)"
    else
        cp "$REPOS_DIR/auth/users.db" "$BACKUP_PATH/users.db"
        warn "sqlite3 absent — copie directe de users.db legacy (potentiellement incohérente)"
    fi
fi

# ── 1ter. Pool de paquets (store canonique .deb/.rpm/.apk) ───────────────────
if [ -d "$REPOS_DIR/pool" ]; then
    mkdir -p "$BACKUP_PATH/pool"
    cp -r "$REPOS_DIR/pool/." "$BACKUP_PATH/pool/"
    POOL_COUNT=$(find "$BACKUP_PATH/pool" -type f | wc -l)
    log "Pool de paquets sauvegardé ($POOL_COUNT fichiers)"
else
    warn "Répertoire pool absent — aucun paquet sauvegardé"
fi

# ── 2. Fichiers de configuration ──────────────────────────────────────────────
for f in settings.json; do
    [ -f "$REPOS_DIR/$f" ] && cp "$REPOS_DIR/$f" "$BACKUP_PATH/$f" && log "$f sauvegardé"
done

# ── 3. Logs d'audit (JSONL) ───────────────────────────────────────────────────
if [ -d "$REPOS_DIR/audit" ]; then
    mkdir -p "$BACKUP_PATH/audit"
    cp -r "$REPOS_DIR/audit/." "$BACKUP_PATH/audit/"
    AUDIT_COUNT=$(find "$BACKUP_PATH/audit" -name "*.jsonl" | wc -l)
    log "Audit logs sauvegardés ($AUDIT_COUNT fichiers)"
fi

# ── 4. Tokens et sécurité ─────────────────────────────────────────────────────
if [ -d "$REPOS_DIR/security" ]; then
    mkdir -p "$BACKUP_PATH/security"
    cp -r "$REPOS_DIR/security/." "$BACKUP_PATH/security/"
    log "Répertoire security sauvegardé"
fi

# ── 5. Manifestes et index paquets ───────────────────────────────────────────
if [ -d "$REPOS_DIR/manifests" ]; then
    mkdir -p "$BACKUP_PATH/manifests"
    cp -r "$REPOS_DIR/manifests/." "$BACKUP_PATH/manifests/"
    MANIFEST_COUNT=$(find "$BACKUP_PATH/manifests" -name "*.json" | wc -l)
    log "Manifestes sauvegardés ($MANIFEST_COUNT fichiers)"
fi

# ── 6. Clés GPG ───────────────────────────────────────────────────────────────
if [ -d "$REPOS_DIR/gnupg" ]; then
    mkdir -p "$BACKUP_PATH/gnupg"
    cp -rp "$REPOS_DIR/gnupg/." "$BACKUP_PATH/gnupg/" 2>/dev/null || true
    chmod 700 "$BACKUP_PATH/gnupg"
    log "Trousseau GPG sauvegardé"
elif [ -d ".gnupg" ]; then
    mkdir -p "$BACKUP_PATH/gnupg"
    cp -rp ".gnupg/." "$BACKUP_PATH/gnupg/" 2>/dev/null || true
    chmod 700 "$BACKUP_PATH/gnupg"
    log "Trousseau GPG (.gnupg) sauvegardé"
fi

# ── 7. Archive compressée ────────────────────────────────────────────────────
ARCHIVE="${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" "$BACKUP_NAME"
rm -rf "$BACKUP_PATH"
ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)
log "Archive créée : ${ARCHIVE} (${ARCHIVE_SIZE})"

# ── 8. Rétention : suppression des backups trop anciens ──────────────────────
if [ "$RETENTION_DAYS" -gt 0 ]; then
    DELETED=$(find "$BACKUP_DIR" -name "repod_backup_*.tar.gz" \
        -mtime "+${RETENTION_DAYS}" -print -delete | wc -l)
    [ "$DELETED" -gt 0 ] && log "Rétention : $DELETED ancien(s) backup(s) supprimé(s) (>${RETENTION_DAYS}j)"
fi

# ── 9. Résumé ────────────────────────────────────────────────────────────────
echo ""
log "Sauvegarde terminée avec succès"
log "  Archive : $ARCHIVE ($ARCHIVE_SIZE)"
log "  Rétention : ${RETENTION_DAYS} jours"
echo ""
log "Pour restaurer :"
log "  tar -xzf $ARCHIVE -C /tmp/restore"
log "  pg_restore -d \"\$DATABASE_URL\" --clean --if-exists /tmp/restore/${BACKUP_NAME}/postgres.dump"
log "  cp /tmp/restore/${BACKUP_NAME}/settings.json $REPOS_DIR/"
log "  cp -r /tmp/restore/${BACKUP_NAME}/pool/.      $REPOS_DIR/pool/"
log "  cp -r /tmp/restore/${BACKUP_NAME}/audit/.     $REPOS_DIR/audit/"
log "  cp -r /tmp/restore/${BACKUP_NAME}/security/.  $REPOS_DIR/security/"
log "  cp -r /tmp/restore/${BACKUP_NAME}/manifests/. $REPOS_DIR/manifests/"
log "  cp -rp /tmp/restore/${BACKUP_NAME}/gnupg/.    $REPOS_DIR/gnupg/"
log "  (si présent) cp /tmp/restore/${BACKUP_NAME}/users.db $REPOS_DIR/auth/  # legacy SQLite"
log "  Puis régénérer les dépôts depuis pool/ : reprepro (APT) ou createrepo_c --update (RPM)"
