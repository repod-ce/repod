#!/bin/bash
# Repod Enterprise — add-deb.sh
# Appelle reprepro directement (installé dans le container backend).
# Les volumes repos/conf, repos/dists, repos/db, repos/pool sont partagés.
#
# Arguments :
#   $1 = distribution cible (ex: jammy, noble, focal, bookworm)
#   $2 = nom du fichier .deb (pas le chemin complet — juste le filename)

DISTRIB="${1:-jammy}"
FILENAME="${2}"
REPREPRO_BASE="${REPREPRO_BASE:-/repos}"
GNUPGHOME="${GNUPG_HOME:-/repos/gnupg}"

if [ -z "$FILENAME" ]; then
    echo "Erreur : nom de fichier manquant" >&2
    echo "Usage: add-deb.sh <distrib> <filename.deb>" >&2
    exit 1
fi

DEB_PATH="${REPREPRO_BASE}/pool/${FILENAME}"

if [ ! -f "$DEB_PATH" ]; then
    echo "Erreur : fichier introuvable : ${DEB_PATH}" >&2
    exit 1
fi

echo "Ajout de ${FILENAME} dans la distribution ${DISTRIB}..."
GNUPGHOME="$GNUPGHOME" reprepro -b "${REPREPRO_BASE}" includedeb "${DISTRIB}" "${DEB_PATH}" 2>&1

RC=$?
if [ $RC -eq 0 ]; then
    echo "OK : ${FILENAME} ajouté dans ${DISTRIB}"
else
    echo "Avertissement : reprepro a retourné le code ${RC} pour ${FILENAME} (peut déjà être présent)"
fi
exit $RC
