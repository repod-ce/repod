#!/bin/bash

set -e  # Arrêter le script en cas d'erreur
set -u  # Erreur si une variable est non définie

REPO_DIR="/usr/share/nginx/html/repos"
GPG_HOME="/root/.gnupg"
DISTRIBUTIONS_FILE="${REPO_DIR}/conf/distributions"

echo "🚀 Initialisation du dépôt APT..."

# 📌 Vérifier si `gpg` et `reprepro` sont installés
if ! command -v gpg >/dev/null 2>&1; then
    echo "❌ ERREUR: gpg n'est pas installé. Installez-le avec 'sudo apt install gnupg'."
    exit 1
fi

if ! command -v reprepro >/dev/null 2>&1; then
    echo "❌ ERREUR: reprepro n'est pas installé. Installez-le avec 'sudo apt install reprepro'."
    exit 1
fi

# 📌 Vérifier les permissions du dossier GPG
echo "🔍 Vérification des permissions de ${GPG_HOME}..."
chown -R root:root "${GPG_HOME}"
chmod 700 "${GPG_HOME}"

# 📌 Vérifier si une clé GPG existe, sinon la générer
if ! gpg --list-keys | grep -q "DepotAPT"; then
    echo "🔑 Génération d'une nouvelle clé GPG..."
    gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: DepotAPT
Name-Email: depot@local
Expire-Date: 0
%no-protection
%commit
EOF
    echo "✅ Nouvelle clé GPG générée."
else
    echo "✅ Clé GPG déjà existante."
fi

# 🔎 Récupérer l'ID long de la clé GPG
GPG_KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^pub:/ {print $5}')

# 📌 Vérifier si `GPG_KEY_ID` est vide
if [[ -z "$GPG_KEY_ID" ]]; then
    echo "❌ ERREUR: Impossible de récupérer l'ID de la clé GPG !"
    exit 1
fi

echo "🔑 Clé GPG détectée : $GPG_KEY_ID"

# 📌 Générer ou mettre à jour le fichier `distributions`
echo "📝 Mise à jour du fichier distributions..."
mkdir -p ${REPO_DIR}/conf
cat <<EOF > "$DISTRIBUTIONS_FILE"
Origin: MonDepot
Label: MonDepot
Suite: stable
Codename: bookworm
Architectures: amd64 i386
Components: main
Description: Dépôt privé de paquets Debian
Contents:
SignWith: $GPG_KEY_ID
EOF

# 📤 Exporter la clé publique pour les clients APT (format binaire .gpg)
echo "📤 Exportation de la clé publique..."
gpg --yes --output ${REPO_DIR}/depot.gpg --export "$GPG_KEY_ID"
chmod 644 ${REPO_DIR}/depot.gpg

# 📂 Vérifier et générer la structure du dépôt
echo "📂 Vérification et création des dossiers du dépôt..."
mkdir -p ${REPO_DIR}/conf ${REPO_DIR}/dists ${REPO_DIR}/pool ${REPO_DIR}/db
chmod 755 ${REPO_DIR} ${REPO_DIR}/conf ${REPO_DIR}/dists ${REPO_DIR}/pool ${REPO_DIR}/db

# 🛠 Initialiser le dépôt si ce n'est pas déjà fait
if [ ! -f "${REPO_DIR}/dists/bookworm/Release" ]; then
    echo "📦 Initialisation du dépôt APT..."
    reprepro -b ${REPO_DIR} export
else
    echo "✅ Dépôt APT déjà initialisé."
fi

echo "🎯 Dépôt prêt à être utilisé !"
