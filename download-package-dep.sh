#!/bin/bash

# Vérifier si un paquet est fourni
if [ -z "$1" ]; then
    echo "Usage: $0 <nom_du_paquet>"
    exit 1
fi

PAQUET=$1
TMP_DIR="/tmp/apt-repo"
CONTAINER_NAME="depot-apt"
CONTAINER_REPO_PATH="/usr/share/nginx/html/repos/pool/"

# Créer le dossier temporaire sur l'hôte
mkdir -p $TMP_DIR
cd $TMP_DIR

echo "🔽 Téléchargement du paquet $PAQUET et de ses dépendances..."

# Télécharger uniquement les paquets réellement disponibles
DEPS=$(apt-rdepends $PAQUET | grep -E '^[a-zA-Z0-9.+-]+$' | while read dep; do
    apt-cache show "$dep" | grep -q "Filename:" && echo "$dep"
done)

if [ -z "$DEPS" ]; then
    echo "❌ Aucun paquet téléchargeable trouvé pour $PAQUET. Vérifiez son nom."
    exit 1
fi

# Télécharger les paquets en ignorant les erreurs `_apt`
sudo apt-get download $PAQUET $DEPS

# Modifier les permissions pour éviter l'erreur `_apt`
sudo chmod -R a+r $TMP_DIR/*.deb 2>/dev/null

# Vérifier s'il y a bien des fichiers téléchargés
if ! ls $TMP_DIR/*.deb 1> /dev/null 2>&1; then
    echo "❌ Aucun fichier .deb téléchargé. Vérifiez le nom du paquet et ses dépendances."
    exit 1
fi

echo "✅ Téléchargement terminé."

# Vérifier si le conteneur est en cours d'exécution
if ! sudo docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Erreur : Le conteneur '$CONTAINER_NAME' n'est pas en cours d'exécution."
    exit 1
fi

# Vérifier qu'il y a bien des fichiers à copier avant d'exécuter `docker cp`
if ls $TMP_DIR/*.deb 1> /dev/null 2>&1; then
    echo "📦 Copie des paquets dans le conteneur..."
    sudo docker cp $TMP_DIR/. $CONTAINER_NAME:$CONTAINER_REPO_PATH
else
    echo "❌ Aucun fichier .deb à copier dans le conteneur."
    exit 1
fi

# Exécuter le script dans le conteneur
echo "📌 Exécution du script dans le conteneur..."
sudo docker exec -ti $CONTAINER_NAME sh add-deb.sh

# Nettoyer les fichiers temporaires sur l'hôte
rm -rf $TMP_DIR

echo "✅ Paquet $PAQUET et ses dépendances ajoutés au dépôt APT dans '$CONTAINER_NAME' !"
