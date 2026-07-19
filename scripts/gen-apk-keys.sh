#!/usr/bin/env bash
# =============================================================================
# gen-apk-keys.sh
# (Re)télécharge les clés RSA PUBLIQUES Alpine dans
# backend/security-keys/apk-keys/ — utilisées par
# services/package_index_apk.py:_verify_apkindex_signature() pour authentifier
# APKINDEX.tar.gz.
#
# Contrairement aux trousseaux GPG (APT/RPM), Alpine ne signe pas avec GPG :
# APKINDEX.tar.gz est la concaténation de deux flux gzip — le premier est une
# archive tar contenant un fichier ".SIGN.RSA.<nom-clé>.rsa.pub" dont le
# contenu est la signature RSA brute (openssl dgst -sha1 -sign) calculée sur
# les octets COMPRESSÉS du second flux gzip (celui qui contient APKINDEX +
# DESCRIPTION une fois décompressé). Vérifié en direct : `openssl dgst -sha1
# -verify` réussit sur le flux compressé, échoue sur le tar décompressé —
# confirmant qu'abuild-sign signe bien le fichier .tar.gz final, pas son
# contenu décompressé.
#
# Chaque fichier de clé est nommé EXACTEMENT comme le nom de fichier de
# signature embarqué dans l'archive (".SIGN.RSA.<nom>" -> "<nom>"), pour que
# _verify_apkindex_signature() puisse résoudre la bonne clé publique
# directement par nom sans deviner.
#
# Couverture confirmée en direct : les 8 sources DEFAULT_SOURCES (Alpine
# 3.18/3.19/3.20/3.21 × main/community) utilisent toutes la même clé
# "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub" (génération 2021,
# encore active à ce jour) — une seule clé suffit pour l'instant, mais le
# format par-fichier ci-dessus permet d'en ajouter d'autres sans changer de
# schéma le jour où Alpine fait tourner ses clés.
#
# Usage :
#   bash scripts/gen-apk-keys.sh
#
# Sortie : backend/security-keys/apk-keys/*.rsa.pub
# =============================================================================
set -euo pipefail

OUT_DIR="$(dirname "$0")/../backend/security-keys/apk-keys"
mkdir -p "$OUT_DIR"

KEYS=(
  "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
)

for key in "${KEYS[@]}"; do
  echo "== Clé $key =="
  curl -sSL -o "$OUT_DIR/$key" "https://alpinelinux.org/keys/$key"
done

echo ""
echo "Écrit dans : $OUT_DIR"
ls -la "$OUT_DIR"
