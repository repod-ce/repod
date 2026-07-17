# Étape 1 : Build de React
FROM node:18 AS build
WORKDIR /app

# L'URL de l'API est injectée au moment du build
ARG REACT_APP_API_URL=http://localhost:8000
ENV REACT_APP_API_URL=$REACT_APP_API_URL

ARG REACT_APP_REPO_URL=http://localhost:80
ENV REACT_APP_REPO_URL=$REACT_APP_REPO_URL

ARG REACT_APP_RPM_REPO_URL=http://localhost:8080
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
