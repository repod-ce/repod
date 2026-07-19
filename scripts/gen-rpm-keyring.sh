#!/usr/bin/env bash
# =============================================================================
# gen-rpm-keyring.sh
# (Re)génère backend/security-keys/rpm-archive-keyring.gpg — le trousseau de
# clés PUBLIQUES utilisé par services/package_index_rpm.py:_verify_repomd_gpg()
# pour authentifier repomd.xml (via repomd.xml.asc) avant de faire confiance
# au SHA-256 de primary.xml qu'il contient.
#
# Toutes les clés viennent directement des dépôts officiels de chaque distro
# (jamais tapées/collées à la main) — identifiées en vérifiant en direct
# quel keyid signe réellement le repomd.xml.asc de chaque source de
# DEFAULT_SOURCES (gpg --list-packets), puis en confirmant que le fichier de
# clé récupéré au chemin officiel produit bien GOODSIG sur ce même repomd.xml.
#
# Couverture : AlmaLinux 8/9/10, Rocky Linux 8/9/10, CentOS Stream, openSUSE
# (Leap + Tumbleweed, même clé de signature "openSUSE Project Signing Key").
#
# PAS de clé pour Fedora/EPEL/Oracle Linux : ces dépôts ne publient aucun
# repomd.xml.asc (confirmé : 404 sur les 3) — _verify_repomd_gpg() le
# détecte et journalise un avertissement au lieu d'échouer, voir le
# docstring de la fonction pour le raisonnement complet.
#
# Usage :
#   bash scripts/gen-rpm-keyring.sh
#
# Quand le relancer :
#   - Ajout d'une nouvelle distro/version RPM dans DEFAULT_SOURCES qui publie
#     un repomd.xml.asc -> ajouter sa clé ci-dessous.
#   - Rotation d'une clé annoncée officiellement par la distro.
#
# Sortie : backend/security-keys/rpm-archive-keyring.gpg
# =============================================================================
set -euo pipefail

OUT_DIR="$(dirname "$0")/../backend/security-keys"
OUT_FILE="$OUT_DIR/rpm-archive-keyring.gpg"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"
rm -f "$OUT_FILE"

declare -A KEYS=(
  ["almalinux-8"]="https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-8"
  ["almalinux-9"]="https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-9"
  ["almalinux-10"]="https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux-10"
  ["rocky-8"]="https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-8"
  ["rocky-9"]="https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9"
  ["rocky-10"]="https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-10"
  ["centos-official"]="https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official"
  # openSUSE publie une clé par répertoire de dépôt (gpg-pubkey-*.asc) ; celle
  # ci-dessous (keyid 29B700A4) est celle qui signe réellement repomd.xml.asc
  # pour Leap 15.6 ET Tumbleweed (confirmé via gpg --list-packets sur les deux).
  ["opensuse"]="https://download.opensuse.org/distribution/leap/15.6/repo/oss/gpg-pubkey-29b700a4-62b07e22.asc"
)

for name in "${!KEYS[@]}"; do
  echo "== Clé $name =="
  curl -sSL -o "$WORK_DIR/$name.asc" "${KEYS[$name]}"
  gpg --no-default-keyring --keyring "$OUT_FILE" --import "$WORK_DIR/$name.asc"
done

echo ""
echo "== Trousseau final =="
gpg --no-default-keyring --keyring "$OUT_FILE" --list-keys --keyid-format LONG | grep -E "^pub|uid"
echo ""
echo "Écrit : $OUT_FILE"
