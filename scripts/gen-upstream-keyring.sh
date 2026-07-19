#!/usr/bin/env bash
# =============================================================================
# gen-upstream-keyring.sh
# (Re)génère backend/security-keys/upstream-archive-keyring.gpg — le trousseau
# de clés PUBLIQUES Ubuntu/Debian utilisé par
# services/package_index_apt.py:_verify_inrelease_gpg() pour authentifier
# InRelease avant de faire confiance à un Packages.gz synchronisé.
#
# Ce ne sont jamais des clés tapées/collées à la main : elles viennent
# exclusivement des paquets officiels ubuntu-keyring (déjà présent sur
# Ubuntu) et debian-archive-keyring (téléchargé directement depuis
# ftp.debian.org, la source la plus à jour — le paquet mirroré par Ubuntu
# universe est souvent une version plus ancienne, sans les clés des
# releases Debian récentes).
#
# Usage :
#   bash scripts/gen-upstream-keyring.sh
#
# Quand le relancer :
#   - Ajout d'une nouvelle distro Debian dans DEFAULT_SOURCES (ex: trixie)
#     -> ajouter les clés debian-archive-<codename>-{automatic,security-automatic}
#     ci-dessous.
#   - Rotation d'une clé Ubuntu/Debian annoncée officiellement (rare, les
#     archives publient toujours l'ancienne ET la nouvelle clé en parallèle
#     pendant la transition).
#
# Sortie : backend/security-keys/upstream-archive-keyring.gpg
# =============================================================================
set -euo pipefail

OUT_DIR="$(dirname "$0")/../backend/security-keys"
OUT_FILE="$OUT_DIR/upstream-archive-keyring.gpg"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"

echo "== Clés Ubuntu (paquet ubuntu-keyring, déjà installé sur Ubuntu) =="
if [ ! -f /usr/share/keyrings/ubuntu-archive-keyring.gpg ]; then
  sudo apt-get update -y && sudo apt-get install -y ubuntu-keyring
fi
gpg --no-default-keyring --keyring "$OUT_FILE" \
    --import /usr/share/keyrings/ubuntu-archive-keyring.gpg

echo "== Clés Debian (paquet debian-archive-keyring, téléchargé direct depuis ftp.debian.org) =="
DEBIAN_KEYRING_DEB_URL="$(
  curl -sSL http://ftp.debian.org/debian/pool/main/d/debian-archive-keyring/ \
    | grep -oE 'debian-archive-keyring_[0-9.]+_all\.deb' | sort -V | tail -1
)"
curl -sSL -o "$WORK_DIR/debian-archive-keyring.deb" \
    "http://ftp.debian.org/debian/pool/main/d/debian-archive-keyring/$DEBIAN_KEYRING_DEB_URL"
( cd "$WORK_DIR" && ar x debian-archive-keyring.deb && tar xf data.tar.xz )

# Une clé par release Debian activement synchronisée dans DEFAULT_SOURCES —
# ajouter une ligne ici pour chaque nouvelle distro Debian ajoutée au projet.
for key in \
    debian-archive-bookworm-automatic \
    debian-archive-bookworm-security-automatic \
; do
  gpg --no-default-keyring --keyring "$OUT_FILE" \
      --import "$WORK_DIR/usr/share/keyrings/${key}.gpg"
done

echo ""
echo "== Trousseau final =="
gpg --no-default-keyring --keyring "$OUT_FILE" --list-keys | grep -E "^pub|uid"
echo ""
echo "Écrit : $OUT_FILE"
