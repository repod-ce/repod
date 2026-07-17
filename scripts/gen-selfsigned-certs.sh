#!/usr/bin/env bash
# =============================================================================
# gen-selfsigned-certs.sh
# Génère un certificat TLS auto-signé pour Repod (environnements internes).
#
# Usage :
#   bash scripts/gen-selfsigned-certs.sh [HOSTNAME_OR_IP]
#
#   Exemples :
#     bash scripts/gen-selfsigned-certs.sh                   # IP auto-détectée
#     bash scripts/gen-selfsigned-certs.sh repod.local       # nom DNS
#     bash scripts/gen-selfsigned-certs.sh 192.168.56.10     # IP fixe
#
# Sortie :
#   repos/certs/tls/cert.pem   — certificat X.509 (10 ans)
#   repos/certs/tls/key.pem    — clé privée RSA-4096
#
# Notes :
#   - Ce certificat n'est PAS validé par une CA publique.
#   - Pour la production avec un domaine public, utiliser Let's Encrypt :
#       docker compose -f docker-compose.yaml -f docker-compose.tls.yml \
#                      -f docker-compose.letsencrypt.yml up -d
#   - Pour les clients `apt` ou `curl`, ajouter le certificat aux CA de confiance :
#       sudo cp repos/certs/tls/cert.pem /usr/local/share/ca-certificates/repod.crt
#       sudo update-ca-certificates
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$REPO_ROOT/repos/certs/tls"

# ── Détection de l'hôte ──────────────────────────────────────────────────────
if [[ $# -ge 1 ]]; then
    HOST_PARAM="$1"
else
    # Auto-détection de l'IP principale
    HOST_PARAM="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")"
    echo "[TLS] Hôte auto-détecté : $HOST_PARAM"
fi

# Détecter si c'est une IP ou un DNS
if [[ "$HOST_PARAM" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="IP:$HOST_PARAM,IP:127.0.0.1,DNS:localhost"
    CN="$HOST_PARAM"
else
    SAN="DNS:$HOST_PARAM,DNS:localhost,IP:127.0.0.1"
    CN="$HOST_PARAM"
fi

echo "[TLS] Génération du certificat auto-signé pour : $CN"
echo "[TLS] SAN : $SAN"
echo "[TLS] Répertoire : $CERTS_DIR"

mkdir -p "$CERTS_DIR"

# ── Génération ───────────────────────────────────────────────────────────────
openssl req -x509 -nodes \
    -newkey rsa:4096 \
    -keyout "$CERTS_DIR/key.pem" \
    -out    "$CERTS_DIR/cert.pem" \
    -sha256 \
    -days   3650 \
    -subj   "/CN=$CN/O=Repod/OU=Private Repository/C=FR" \
    -addext "subjectAltName=$SAN" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth"

chmod 600 "$CERTS_DIR/key.pem"
chmod 644 "$CERTS_DIR/cert.pem"

echo ""
echo "✔ Certificat généré :"
openssl x509 -in "$CERTS_DIR/cert.pem" -noout -subject -dates -fingerprint -sha256
echo ""
echo "Pour faire confiance à ce certificat sur cette machine :"
echo "  sudo cp '$CERTS_DIR/cert.pem' /usr/local/share/ca-certificates/repod.crt"
echo "  sudo update-ca-certificates"
echo ""
echo "Pour démarrer avec TLS :"
echo "  docker compose -f docker-compose.yaml -f docker-compose.tls.yml up -d"
