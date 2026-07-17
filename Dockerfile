# Partir de Nginx basé sur Debian Bookworm
FROM nginx:1.27.4-bookworm

# Mettre à niveau les paquets de base de l'image (correctifs de sécurité
# Debian déjà publiés mais pas encore présents dans l'image nginx:bookworm)
RUN apt update && apt upgrade -y && rm -rf /var/lib/apt/lists/*

# Ce conteneur ne fait que servir les fichiers statiques du dépôt (dists/,
# pool/, conf/, db/ — tous bind-mountés depuis ./repos/ dans
# docker-compose.yaml) : il ne gère ni reprepro ni GPG. C'est le backend qui
# exécute reprepro et gère la clé GPG partagée (/repos/gnupg) directement
# contre le volume /repos partagé — voir CLAUDE.md. reprepro/gnupg n'ont donc
# pas besoin d'être installés ici.

# Copier la configuration Nginx et supprimer la config par défaut
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx/repo.conf /etc/nginx/conf.d/repo.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
