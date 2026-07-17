#!/bin/bash
# Repod Enterprise RPM — add-rpm.sh
# Ajoute un paquet .rpm dans la distribution cible et met à jour les métadonnées.
#
# Arguments :
#   $1 = distribution cible (ex: almalinux8, rocky8, centos-stream9)
#   $2 = nom du fichier .rpm (juste le filename, pas le chemin complet)
#   $3 = architecture (optionnel — détectée depuis le nom de fichier sinon)

DISTRIB="${1:-almalinux8}"
FILENAME="${2}"
ARCH_ARG="${3:-}"

REPO_BASE="${REPO_BASE:-/repos}"
GNUPGHOME="${GNUPG_HOME:-/repos/gnupg}"

if [ -z "$FILENAME" ]; then
    echo "Erreur : nom de fichier manquant" >&2
    echo "Usage: add-rpm.sh <distrib> <filename.rpm> [arch]" >&2
    exit 1
fi

RPM_PATH="${REPO_BASE}/pool/${FILENAME}"

if [ ! -f "$RPM_PATH" ]; then
    echo "Erreur : fichier introuvable : ${RPM_PATH}" >&2
    exit 1
fi

# Détecter l'architecture depuis le nom du fichier (ex: pkg-1.0-1.x86_64.rpm)
if [ -n "$ARCH_ARG" ]; then
    ARCH="$ARCH_ARG"
elif echo "$FILENAME" | grep -qE '\.noarch\.rpm$'; then
    ARCH="noarch"
elif echo "$FILENAME" | grep -qE '\.aarch64\.rpm$'; then
    ARCH="aarch64"
elif echo "$FILENAME" | grep -qE '\.i686\.rpm$'; then
    ARCH="i686"
elif echo "$FILENAME" | grep -qE '\.x86_64\.rpm$'; then
    ARCH="x86_64"
else
    # Fallback : lire depuis les métadonnées RPM
    ARCH=$(rpm -qp --queryformat '%{ARCH}' --nosignature --noplugins "$RPM_PATH" 2>/dev/null || echo "x86_64")
fi

DISTRIB_DIR="${REPO_BASE}/${DISTRIB}/${ARCH}"
mkdir -p "${DISTRIB_DIR}"

echo "Copie de ${FILENAME} dans ${DISTRIB}/${ARCH}..."
cp "${RPM_PATH}" "${DISTRIB_DIR}/"

echo "Mise à jour des métadonnées createrepo_c pour ${DISTRIB}/${ARCH}..."
createrepo_c --update --quiet "${DISTRIB_DIR}"

RC=$?
if [ $RC -ne 0 ]; then
    echo "Erreur: createrepo_c a retourné le code ${RC}" >&2
    exit $RC
fi

# Signer repomd.xml avec GPG (clé DepotRPM)
REPOMD="${DISTRIB_DIR}/repodata/repomd.xml"
if [ -f "$REPOMD" ] && command -v gpg >/dev/null 2>&1; then
    GNUPGHOME="$GNUPGHOME" gpg --batch --yes --detach-sign --armor \
        --output "${REPOMD}.asc" "${REPOMD}" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "repomd.xml signé avec succès."
    else
        echo "Avertissement : signature GPG de repomd.xml échouée (non bloquant)."
    fi
fi

echo "OK : ${FILENAME} ajouté dans ${DISTRIB}/${ARCH}"
exit 0
