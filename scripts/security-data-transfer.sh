#!/usr/bin/env bash
# =============================================================================
# security-data-transfer.sh — fetch/import du bundle de données de sécurité
# (ClamAV, base de vulnérabilités Grype, EPSS, CISA KEV) pour transfert
# air-gap (clé USB, disque relais) entre un hôte connecté à internet
# ("relais") et une instance repod sans accès internet.
#
# Pour un déploiement air-gap complet, voir aussi le guide "Air-gapped
# security data updates" sur docs.getrepod.com (procédure détaillée pas à
# pas). Ce script couvre uniquement les 4 sources qui alimentent le
# pipeline de scan CVE — pas le contenu des dépôts eux-mêmes.
#
# Usage :
#   bash scripts/security-data-transfer.sh fetch  [chemin_sortie.tar.gz] [--image <tag>]
#   bash scripts/security-data-transfer.sh import <chemin_archive.tar.gz>
#
# "fetch" s'exécute sur l'hôte relais (connecté à internet) — il réutilise
# les mêmes outils/code que la production (freshclam, grype, et le module
# services/cve_enrichment.py) via l'image backend repod elle-même, pour
# garantir que le format des fichiers produits est strictement identique à
# ce que produirait une instance repod normale.
#
# "import" s'exécute sur l'instance air-gappée, une fois l'archive transférée
# par un support offline (clé USB, disque, etc. — selon la politique de
# sécurité du site).
# =============================================================================
set -euo pipefail

IMAGE=""
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --image)
            IMAGE="$2"
            shift 2
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL[@]:-}"

usage() {
    echo "Usage : $0 fetch  [chemin_sortie.tar.gz] [--image <tag>]" >&2
    echo "        $0 import <chemin_archive.tar.gz>" >&2
    exit 1
}

[ $# -ge 1 ] || usage
MODE="$1"

resolve_image() {
    if [ -n "$IMAGE" ]; then
        echo "$IMAGE"
        return
    fi
    local existing
    existing="$(docker compose images -q backend 2>/dev/null || true)"
    if [ -n "$existing" ]; then
        echo "$existing"
        return
    fi
    echo "[security-data-transfer] Aucune image backend existante trouvée — construction (peut prendre plusieurs minutes, compilation Nuitka incluse)..." >&2
    docker build -q -t repod-security-fetch ./backend >&2
    echo "repod-security-fetch"
}

case "$MODE" in
    fetch)
        OUT="${2:-./security-data-$(date +%Y%m%d).tar.gz}"
        IMG="$(resolve_image)"
        echo "[security-data-transfer] Image utilisée : $IMG"

        WORKDIR="$(mktemp -d)"
        trap 'rm -rf "$WORKDIR"' EXIT
        mkdir -p "$WORKDIR/clamav-db" "$WORKDIR/grype-db" "$WORKDIR/security"

        # --user <host_uid>:<host_gid> : sans ça, les 3 containers écrivent en
        # root (aucun USER dans backend/Dockerfile), donc les fichiers produits
        # dans le bind mount finissent appartenant à root sur l'hôte — illisibles/
        # non supprimables par l'utilisateur ayant lancé ce script (constaté en
        # test réel : tar/rm échouent en "Permission denied" sur grype-db/*).
        # freshclam tente en interne de passer à l'utilisateur "clamav" (UID
        # 100/GID 102 dans l'image) via DatabaseOwner — impossible sans être
        # root, mais ClamAV se contente d'un avertissement et continue en tant
        # que l'utilisateur courant (déjà non-root), donc --user ne casse rien.
        HOST_UID_GID="$(id -u):$(id -g)"

        echo "[security-data-transfer] ClamAV (freshclam)..."
        # --log pointé dans le bind mount (déjà accessible en écriture à
        # HOST_UID_GID) : le chemin par défaut (/var/log/clamav/) est root:root
        # dans l'image et --user le rend inaccessible, sinon (constaté en test réel).
        docker run --rm --user "$HOST_UID_GID" -v "$WORKDIR/clamav-db:/var/lib/clamav" \
            --entrypoint freshclam "$IMG" --datadir=/var/lib/clamav \
            --log=/var/lib/clamav/freshclam-fetch.log \
            || echo "[security-data-transfer] Avertissement : freshclam a échoué (voir sortie ci-dessus) — le bundle continuera sans mise à jour ClamAV."

        echo "[security-data-transfer] Base de vulnérabilités Grype (grype db update)..."
        docker run --rm --user "$HOST_UID_GID" -v "$WORKDIR/grype-db:/repos/grype-db" \
            -e GRYPE_DB_CACHE_DIR=/repos/grype-db \
            --entrypoint grype "$IMG" db update \
            || echo "[security-data-transfer] Avertissement : grype db update a échoué — le bundle continuera sans mise à jour Grype."

        echo "[security-data-transfer] EPSS (FIRST.org) + CISA KEV..."
        docker run --rm --user "$HOST_UID_GID" -v "$WORKDIR/security:/repos/security" \
            -e SECURITY_CACHE_DIR=/repos/security \
            --entrypoint python3 "$IMG" -c '
from services.cve_enrichment import refresh_kev, refresh_epss_bulk
ok_kev = refresh_kev()
ok_epss, n = refresh_epss_bulk()
kev_msg = "ok" if ok_kev else "ECHEC"
epss_msg = ("ok, " + str(n) + " scores") if ok_epss else "ECHEC"
print("KEV: " + kev_msg + " -- EPSS: " + epss_msg)
' || echo "[security-data-transfer] Avertissement : rafraîchissement EPSS/KEV a échoué."

        cat > "$WORKDIR/MANIFEST.txt" <<EOF
Bundle de données de sécurité repod — généré le $(date -u +%Y-%m-%dT%H:%M:%SZ)

Contenu :
  clamav-db/   signatures ClamAV (freshclam --datadir)
  grype-db/    base de vulnérabilités Grype (grype db update)
  security/    epss_cache.json + kev_cache.json (FIRST.org EPSS / CISA KEV)

Image backend utilisée pour la génération : $IMG
EOF

        tar -C "$WORKDIR" -czf "$OUT" clamav-db grype-db security MANIFEST.txt
        echo "[security-data-transfer] Export terminé : $OUT ($(du -h "$OUT" | cut -f1))"
        ;;
    import)
        [ $# -ge 2 ] || usage
        ARCHIVE="$2"
        [ -f "$ARCHIVE" ] || { echo "Archive introuvable : $ARCHIVE" >&2; exit 1; }

        CLAMAV_DIR="${CLAMAV_HOST_DIR:-./repos/clamav-db}"
        GRYPE_DIR="${GRYPE_HOST_DIR:-./repos/grype-db}"
        SECURITY_HOST_DIR_LOCAL="${SECURITY_HOST_DIR:-./repos/security}"
        mkdir -p "$CLAMAV_DIR" "$GRYPE_DIR" "$SECURITY_HOST_DIR_LOCAL"

        STAGING="$(mktemp -d)"
        trap 'rm -rf "$STAGING"' EXIT
        tar -C "$STAGING" -xzf "$ARCHIVE"

        [ -d "$STAGING/clamav-db" ] && cp -a "$STAGING/clamav-db/." "$CLAMAV_DIR/"
        [ -d "$STAGING/grype-db" ] && cp -a "$STAGING/grype-db/." "$GRYPE_DIR/"
        [ -d "$STAGING/security" ] && cp -a "$STAGING/security/." "$SECURITY_HOST_DIR_LOCAL/"

        echo "[security-data-transfer] Import terminé :"
        echo "  ClamAV          -> $CLAMAV_DIR"
        echo "  Grype DB        -> $GRYPE_DIR"
        echo "  EPSS/KEV        -> $SECURITY_HOST_DIR_LOCAL"
        echo
        echo "ClamAV nécessite un redémarrage (clamd charge les signatures en mémoire" \
             "une fois au démarrage — voir entrypoint.sh) :"
        echo "  docker compose restart backend"
        echo "Grype/EPSS/KEV sont relus depuis le disque à chaque scan/requête —" \
             "aucun redémarrage requis pour eux."
        ;;
    *)
        usage
        ;;
esac
