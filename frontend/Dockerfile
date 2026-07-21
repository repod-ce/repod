# Étape 1 : Build de React
FROM node:18 AS build
WORKDIR /app

# Ces trois URLs restent vides par défaut — le frontend dérive une valeur
# correcte à l'exécution depuis window.location (voir src/api.js:getRepoUrl()/
# getRpmRepoUrl()/getExternalApiUrl()) plutôt que de figer un "localhost" dans
# le bundle, faux pour toute machine cliente réelle qui copierait ces
# commandes. Ne définir ces ARG que pour un domaine dédié explicite (ex. TLS).
ARG REACT_APP_API_URL=
ENV REACT_APP_API_URL=$REACT_APP_API_URL

ARG REACT_APP_REPO_URL=
ENV REACT_APP_REPO_URL=$REACT_APP_REPO_URL

ARG REACT_APP_RPM_REPO_URL=
ENV REACT_APP_RPM_REPO_URL=$REACT_APP_RPM_REPO_URL

# Version affichée dans le centre d'aide (bas de menu) — injectée au build
# depuis le tag de release ; "dev" en local (docker-compose.build.yml).
ARG REACT_APP_VERSION=dev
ENV REACT_APP_VERSION=$REACT_APP_VERSION

COPY package.json package-lock.json ./
RUN npm install
COPY . .
RUN npm run build

# Étape 2 : Serveur Nginx
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Crée le fichier 50x.html requis par la directive error_page nginx
RUN echo '<!DOCTYPE html><html><head><title>Erreur serveur</title></head><body><h2>Erreur serveur temporaire. Veuillez réessayer.</h2></body></html>' \
    > /usr/share/nginx/html/50x.html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
