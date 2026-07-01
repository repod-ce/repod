# Partir de Nginx basé sur Debian Bookworm
FROM nginx:1.27.4-bookworm

# Définition des variables d'environnement
ENV REPO_DIR=/usr/share/nginx/html/repos
ENV GPG_HOME=/root/.gnupg

# Mettre à niveau les paquets de base de l'image (correctifs de sécurité
# Debian déjà publiés mais pas encore présents dans l'image nginx:bookworm)
RUN apt update && apt upgrade -y && rm -rf /var/lib/apt/lists/*

# Installer les outils nécessaires
RUN apt update && apt install -y \
    reprepro \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Créer la structure du dépôt
RUN mkdir -p ${REPO_DIR}/conf ${REPO_DIR}/dists ${REPO_DIR}/pool ${REPO_DIR}/db && \
    chown -R nginx:nginx ${REPO_DIR} && \
    chmod -R 755 ${REPO_DIR}

# Copier la configuration Nginx et supprimer la config par défaut
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx/repo.conf /etc/nginx/conf.d/repo.conf

# Copier le script d'initialisation et lui donner les permissions d'exécution
COPY scripts/init-repo.sh /init-repo.sh
RUN chmod +x /init-repo.sh

# Exécuter le script d'init avant de lancer Nginx
CMD ["/bin/sh", "-c", "/init-repo.sh && nginx -g 'daemon off;'"]
