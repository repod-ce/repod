# Étape 1 : Construction des dépendances
FROM python:3.10 AS builder

WORKDIR /app

# Installer pip et les dépendances dans un dossier temporaire
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --target=/dependencies -r requirements.txt

# Télécharger le binaire Grype (scanner CVE) dans le builder
RUN apt-get update -y && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin/

# Étape 2 : Exécution (runtime)
FROM python:3.10-slim

WORKDIR /app

# Copier uniquement les dépendances depuis l'étape précédente
COPY --from=builder /dependencies /usr/local/lib/python3.10/site-packages/

# Ajouter le dossier contenant les binaires Python au PATH
ENV PATH="/usr/local/bin:$PATH"

# Mettre à niveau les paquets de base de l'image (correctifs de sécurité
# Debian déjà publiés mais pas encore présents dans l'image python:3.10-slim)
RUN apt-get update -y && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Installer OpenSSH Client pour permettre au conteneur d’exécuter SSH vers l’hôte
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    openssh-client \
    dpkg \
    gpg \
    gpg-agent \
    apt-rdepends \
    clamav \
    clamav-daemon \
    gosu \
    reprepro \
    rpm \
    createrepo-c \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copier le binaire Grype depuis le builder
# NOTE : docker CLI supprimé — les opérations GPG passent par volume partagé (GNUPG_HOME)
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype

# Créer le groupe et l’utilisateur applicatif (UID/GID 1000)
RUN groupadd -g 1000 appuser && \
    useradd -m -u 1000 -g appuser -s /bin/bash appuser

# Copier le code de l’application
COPY . .

# Donner la propriété du répertoire applicatif à appuser
RUN chown -R appuser:appuser /app

# Rendre l'entrypoint exécutable (reste root pour ClamAV + gosu)
RUN chmod +x /app/entrypoint.sh

# L'entrypoint tourne en root, drop vers appuser via gosu
# (nécessaire pour freshclam + chown des volumes au démarrage)

# Exposer le port 8000
EXPOSE 8000

# Healthcheck : vérifie que l'API répond (endpoint /health/live, sans auth, sans Swagger)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live')" \
    || exit 1

# Entrypoint : démarre freshclam daemon puis uvicorn
ENTRYPOINT ["/app/entrypoint.sh"]
