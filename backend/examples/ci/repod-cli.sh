#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# repod-cli.sh — CLI portable pour l'API repod
# Compatible : GitHub Actions, GitLab CI, Jenkins, Drone, tout shell POSIX
#
# Usage :
#   ./repod-cli.sh login
#   ./repod-cli.sh upload <fichier.deb> [distribution] [arch]
#   ./repod-cli.sh vulnerabilities [distribution]
#   ./repod-cli.sh packages [distribution]
#
# Variables d'environnement requises :
#   REPOD_URL       URL de l'instance repod (ex. https://repo.example.com)
#   REPOD_USERNAME  Nom d'utilisateur repod
#   REPOD_PASSWORD  Mot de passe repod
#
# Variable optionnelle (renseignée automatiquement par 'login') :
#   REPOD_TOKEN     JWT d'accès (si déjà obtenu, skip login)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Couleurs (désactivées si pas de terminal) ─────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; RESET=''
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

info()  { echo -e "${GREEN}[repod]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[repod]${RESET} $*" >&2; }
error() { echo -e "${RED}[repod] ERREUR${RESET} : $*" >&2; exit 1; }

_require_env() {
  for var in "$@"; do
    [ -n "${!var:-}" ] || error "Variable d'environnement requise non définie : $var"
  done
}

_api() {
  # Usage : _api GET /api/v1/packages  (retourne le corps JSON)
  local METHOD="$1"
  local PATH="$2"
  shift 2
  curl -sf -X "$METHOD" \
    -H "Authorization: Bearer $REPOD_TOKEN" \
    -H "Accept: application/json" \
    "$@" \
    "${REPOD_URL}${PATH}"
}

# ── Commande : login ──────────────────────────────────────────────────────────

cmd_login() {
  _require_env REPOD_URL REPOD_USERNAME REPOD_PASSWORD
  info "Authentification sur $REPOD_URL..."

  local RESPONSE
  RESPONSE=$(curl -sf -X POST \
    --data-urlencode "username=$REPOD_USERNAME" \
    --data-urlencode "password=$REPOD_PASSWORD" \
    "$REPOD_URL/api/v1/auth/token")

  REPOD_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')
  [ -n "$REPOD_TOKEN" ] && [ "$REPOD_TOKEN" != "null" ] \
    || error "Authentification échouée (vérifiez REPOD_USERNAME / REPOD_PASSWORD)"

  export REPOD_TOKEN
  info "Token obtenu (valide ~60 min)"
  echo "$REPOD_TOKEN"
}

_ensure_token() {
  if [ -z "${REPOD_TOKEN:-}" ]; then
    warn "REPOD_TOKEN non défini — tentative de login automatique"
    _require_env REPOD_USERNAME REPOD_PASSWORD
    cmd_login > /dev/null
  fi
}

# ── Commande : upload ─────────────────────────────────────────────────────────

cmd_upload() {
  local DEB="${1:-}"
  local DISTRIBUTION="${2:-jammy}"
  local ARCH="${3:-amd64}"

  [ -n "$DEB" ] || error "Usage: $0 upload <fichier.deb> [distribution] [arch]"
  [ -f "$DEB" ] || error "Fichier introuvable : $DEB"
  _require_env REPOD_URL
  _ensure_token

  info "Upload de $DEB → distribution=$DISTRIBUTION arch=$ARCH"
  local HTTP_CODE
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $REPOD_TOKEN" \
    -F "file=@$DEB" \
    -F "distribution=$DISTRIBUTION" \
    "$REPOD_URL/api/v1/upload")

  case "$HTTP_CODE" in
    200|201) info "✅ $DEB publié avec succès (HTTP $HTTP_CODE)" ;;
    409)     warn "⚠️  Paquet déjà présent dans le dépôt (HTTP 409)" ;;
    *)       error "Upload échoué pour $DEB (HTTP $HTTP_CODE)" ;;
  esac
}

# ── Commande : vulnerabilities ────────────────────────────────────────────────

cmd_vulnerabilities() {
  local DISTRIBUTION="${1:-}"
  _require_env REPOD_URL
  _ensure_token

  local URL="$REPOD_URL/api/v1/security/vulnerabilities?per_page=200"
  [ -n "$DISTRIBUTION" ] && URL="${URL}&distribution=${DISTRIBUTION}"

  info "Récupération des vulnérabilités${DISTRIBUTION:+ (distribution: $DISTRIBUTION)}..."
  local RESPONSE
  RESPONSE=$(_api GET "/api/v1/security/vulnerabilities?per_page=200${DISTRIBUTION:+&distribution=$DISTRIBUTION}")

  local TOTAL CRITICAL HIGH MEDIUM
  TOTAL=$(echo "$RESPONSE"    | jq '.vulnerabilities.total // 0')
  CRITICAL=$(echo "$RESPONSE" | jq '[.vulnerabilities.items[] | select(.severity == "Critical")] | length')
  HIGH=$(echo "$RESPONSE"     | jq '[.vulnerabilities.items[] | select(.severity == "High")]     | length')
  MEDIUM=$(echo "$RESPONSE"   | jq '[.vulnerabilities.items[] | select(.severity == "Medium")]   | length')

  echo "📊 Vulnérabilités repod :"
  echo "   Total    : $TOTAL"
  echo "   Critical : $CRITICAL"
  echo "   High     : $HIGH"
  echo "   Medium   : $MEDIUM"

  # Sortie JSON brute sur stdout (pipe-friendly)
  echo "$RESPONSE"

  # Exit code non-nul si CVE critique détectée
  [ "$CRITICAL" -eq 0 ] || { warn "$CRITICAL CVE critique(s) détectée(s)"; exit 2; }
}

# ── Commande : packages ───────────────────────────────────────────────────────

cmd_packages() {
  local DISTRIBUTION="${1:-}"
  _require_env REPOD_URL
  _ensure_token

  local PATH="/api/v1/packages/"
  [ -n "$DISTRIBUTION" ] && PATH="${PATH}?distribution=${DISTRIBUTION}"

  info "Liste des paquets${DISTRIBUTION:+ (distribution: $DISTRIBUTION)}..."
  _api GET "$PATH"
}

# ── Aide ──────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage : $(basename "$0") <commande> [arguments]

Commandes :
  login                              Obtenir un token JWT (stocké dans REPOD_TOKEN)
  upload <fichier.deb> [dist] [arch] Publier un paquet .deb
  vulnerabilities [distribution]     Lister les vulnérabilités (exit 2 si CVE critique)
  packages [distribution]            Lister les paquets du dépôt

Variables d'environnement :
  REPOD_URL       (requis) URL de l'instance repod
  REPOD_USERNAME  (requis) Nom d'utilisateur
  REPOD_PASSWORD  (requis) Mot de passe
  REPOD_TOKEN     (optionnel) JWT pré-obtenu (skip login)

Exemples :
  export REPOD_URL=https://repo.example.com
  export REPOD_USERNAME=ci-bot
  export REPOD_PASSWORD=secret

  $(basename "$0") upload mypackage_1.0.0_amd64.deb jammy
  $(basename "$0") vulnerabilities jammy
EOF
  exit 0
}

# ── Point d'entrée ────────────────────────────────────────────────────────────

CMD="${1:-}"
case "$CMD" in
  login)           shift; cmd_login "$@" ;;
  upload)          shift; cmd_upload "$@" ;;
  vulnerabilities) shift; cmd_vulnerabilities "$@" ;;
  packages)        shift; cmd_packages "$@" ;;
  help|--help|-h)  usage ;;
  "")              usage ;;
  *)               error "Commande inconnue : '$CMD'. Lancez '$0 help' pour l'aide." ;;
esac
