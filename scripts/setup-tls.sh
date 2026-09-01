#!/usr/bin/env bash
# =============================================================================
# setup-tls.sh
# Point d'entrée unique pour fournir le certificat TLS de Repod, quelle que
# soit son origine : auto-signé, autorité interne (easy-rsa, AD CS) ou
# Let's Encrypt.
#
# Le chemin canonique ne change jamais :
#   repos/certs/tls/cert.pem   - certificat, feuille puis intermédiaires
#   repos/certs/tls/key.pem    - clé privée, non chiffrée
#
# C'est ce couple que lisent nginx (nginx/tls-proxy.conf) et Traefik
# (traefik/dynamic.yml). Aucun fichier de configuration suivi par git n'a donc
# à être modifié après une émission ou un renouvellement.
#
# Usage :
#   setup-tls.sh self-signed [--san dns:a --san ip:1.2.3.4 ...] [HÔTE_OU_IP]
#   setup-tls.sh csr --san dns:a --san ip:1.2.3.4 [--cn NOM] [--key-type TYPE]
#   setup-tls.sh import --cert F [--key F] [--chain F]
#   setup-tls.sh import --pkcs12 F [--password-file F]
#   setup-tls.sh letsencrypt --domain D --email E [--staging]
#   setup-tls.sh renew
#   setup-tls.sh status
#
# Exemples :
#   # Dépôt joint sous trois noms et une IP, requête à faire signer par la PKI
#   bash scripts/setup-tls.sh csr \
#        --san dns:repod.example.com --san dns:repod --san ip:192.0.2.10
#
#   # Retour de l'autorité : la clé de pending/ est reprise automatiquement
#   bash scripts/setup-tls.sh import --cert repod.crt --chain ca-chain.pem
#
#   # Export PFX d'AD CS
#   bash scripts/setup-tls.sh import --pkcs12 repod.pfx
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

CERTS_DIR="$REPO_ROOT/repos/certs/tls"
PENDING_DIR="$CERTS_DIR/pending"
CERT_FILE="$CERTS_DIR/cert.pem"
KEY_FILE="$CERTS_DIR/key.pem"
LETSENCRYPT_DIR="$REPO_ROOT/repos/certs/letsencrypt"

NGINX_PROXY_CONTAINER="repod-proxy"
TRAEFIK_CONTAINER="repod-traefik"

# Fichiers Compose utilisés par les modes letsencrypt et renew. Surchargeable
# pour les déploiements qui empilent d'autres overlays.
DEFAULT_COMPOSE_FILES="-f docker-compose.yaml -f docker-compose.tls.yml -f docker-compose.letsencrypt.yml"

TMP_DIR=""
# Un « [[ ]] && rm » suffirait, mais son statut d'échec deviendrait celui du
# script entier : le trap EXIT est la dernière commande exécutée.
cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

# ── Sorties ──────────────────────────────────────────────────────────────────

info() { echo "[TLS] $*"; }
warn() { echo "[TLS] Avertissement : $*" >&2; }
die()  { echo "[TLS] Erreur : $*" >&2; exit 1; }

usage() {
    sed -n '3,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ── Analyse des SAN ──────────────────────────────────────────────────────────
# Accepte « --san dns:a --san ip:1.2.3.4 », « --san a,b,1.2.3.4 » et les deux
# mélangés. Le préfixe est optionnel : sans lui, ce qui a la forme d'une IPv4
# ou d'une IPv6 devient IP:, tout le reste devient DNS:.

SAN_ENTRIES=()

classify_san() {
    local raw="$1" value
    case "$raw" in
        dns:*|DNS:*) echo "DNS:${raw#*:}"; return ;;
        ip:*|IP:*)   echo "IP:${raw#*:}";  return ;;
    esac
    value="$raw"
    if [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$value" == *:* ]]; then
        echo "IP:$value"
    else
        echo "DNS:$value"
    fi
}

add_san() {
    local item
    # Découpage sur les virgules pour accepter « --san a,b »
    IFS=',' read -ra _items <<< "$1"
    for item in "${_items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -z "$item" ]] && continue
        SAN_ENTRIES+=("$(classify_san "$item")")
    done
}

san_string() {
    local IFS=','
    echo "${SAN_ENTRIES[*]}"
}

# Nom commun par défaut : première entrée DNS, à défaut première entrée IP.
default_cn() {
    local entry
    for entry in "${SAN_ENTRIES[@]}"; do
        [[ "$entry" == DNS:* ]] && { echo "${entry#DNS:}"; return; }
    done
    echo "${SAN_ENTRIES[0]#IP:}"
}

# Configuration OpenSSL commune à la génération auto-signée et à la requête :
# les deux ne diffèrent que par la présence de -x509 dans l'appel à openssl req.
write_openssl_conf() {
    local conf="$1" cn="$2" san="$3"
    cat > "$conf" <<EOF
[req]
distinguished_name = dn
req_extensions     = v3_req
x509_extensions    = v3_req
prompt             = no

[dn]
CN = $cn
O  = Repod
OU = Private Repository
C  = FR

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = $san
EOF
}

genpkey_args() {
    case "$1" in
        rsa4096) echo "-algorithm RSA -pkeyopt rsa_keygen_bits:4096" ;;
        rsa2048) echo "-algorithm RSA -pkeyopt rsa_keygen_bits:2048" ;;
        ec-p256) echo "-algorithm EC -pkeyopt ec_paramgen_curve:P-256" ;;
        ec-p384) echo "-algorithm EC -pkeyopt ec_paramgen_curve:P-384" ;;
        *) die "type de clé inconnu : $1 (rsa4096, rsa2048, ec-p256, ec-p384)" ;;
    esac
}

# ── Contrôles sur un couple certificat/clé ───────────────────────────────────

# Découpe un PEM multi-certificats : $2 reçoit la feuille, $3 le reste.
split_chain() {
    local bundle="$1" leaf="$2" rest="$3"
    awk -v leaf="$leaf" -v rest="$rest" '
        /-----BEGIN CERTIFICATE-----/ { n++ }
        { if (n <= 1) print > leaf; else print > rest }
    ' "$bundle"
    [[ -f "$rest" ]] || : > "$rest"
}

dn_of() { openssl x509 -in "$1" -noout -"$2" -nameopt RFC2253 | sed "s/^$2=//"; }

check_key_usable() {
    local key="$1"
    if grep -qE 'ENCRYPTED' "$key"; then
        die "la clé privée est chiffrée par une phrase de passe.
       nginx et Traefik démarrent sans terminal, aucune phrase ne peut être
       saisie. Déchiffrer d'abord :
         openssl pkey -in $key -out cle-dechiffree.pem"
    fi
    openssl pkey -in "$key" -noout -passin pass: >/dev/null 2>&1 \
        || die "clé privée illisible : $key"
}

check_pair_matches() {
    local cert="$1" key="$2" cert_pub key_pub
    cert_pub="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null)" \
        || die "certificat illisible : $cert"
    key_pub="$(openssl pkey -in "$key" -pubout -passin pass: 2>/dev/null)" \
        || die "clé privée illisible : $key"
    [[ "$cert_pub" == "$key_pub" ]] || die "le certificat et la clé privée ne correspondent pas.
       Le certificat reçu a probablement été émis pour une autre requête.
       Rien n'a été écrit, le certificat en service est intact."
}

check_chain() {
    local bundle="$1" count leaf rest subject issuer
    count="$(grep -c -- '-----BEGIN CERTIFICATE-----' "$bundle" || true)"
    leaf="$TMP_DIR/chain-leaf.pem"
    rest="$TMP_DIR/chain-rest.pem"
    split_chain "$bundle" "$leaf" "$rest"

    subject="$(dn_of "$leaf" subject)"
    issuer="$(dn_of "$leaf" issuer)"

    if [[ "$count" -le 1 ]]; then
        if [[ "$subject" != "$issuer" ]]; then
            warn "le fichier ne contient que le certificat feuille, sans la ou les
       autorités intermédiaires. Les clients qui ne connaissent que la racine
       échoueront sur « unable to get local issuer certificate ». Ajouter la
       chaîne avec --chain, ou concaténer feuille puis intermédiaires."
        fi
        return
    fi

    local next_subject
    next_subject="$(openssl x509 -in "$rest" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
    if [[ "$issuer" != "$next_subject" ]]; then
        warn "l'ordre de la chaîne semble incorrect : l'émetteur de la feuille
       ($issuer) ne correspond pas au sujet du certificat suivant
       ($next_subject). L'ordre attendu est feuille, puis intermédiaires."
    fi
}

check_validity() {
    local cert="$1"
    openssl x509 -in "$cert" -noout -checkend 0 >/dev/null \
        || die "le certificat est déjà expiré : $(openssl x509 -in "$cert" -noout -enddate)"
    openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null \
        || warn "le certificat expire dans moins de 30 jours ($(openssl x509 -in "$cert" -noout -enddate))"
}

describe_cert() {
    local cert="$1"
    openssl x509 -in "$cert" -noout -subject -issuer -dates -fingerprint -sha256 \
        | sed 's/^/       /'
    local san
    san="$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
           | tail -n +2 | tr -d ' ' | sed 's/^/       SAN: /')"
    [[ -n "$san" ]] && echo "$san"
}

# ── Installation au chemin canonique ─────────────────────────────────────────

ensure_tmp() { [[ -n "$TMP_DIR" ]] || TMP_DIR="$(mktemp -d)"; }

install_pem() {
    local cert="$1" key="$2"

    [[ -f "$cert" ]] || die "certificat introuvable : $cert"
    [[ -f "$key"  ]] || die "clé privée introuvable : $key"

    ensure_tmp

    check_key_usable "$key"
    check_pair_matches "$cert" "$key"
    check_chain "$cert"
    check_validity "$cert"

    mkdir -p "$CERTS_DIR"
    # Écriture atomique : tant que les contrôles n'ont pas tous abouti, le
    # certificat en service n'est pas touché.
    install -m 644 "$cert" "$CERT_FILE.tmp"
    install -m 600 "$key"  "$KEY_FILE.tmp"
    mv "$CERT_FILE.tmp" "$CERT_FILE"
    mv "$KEY_FILE.tmp"  "$KEY_FILE"

    info "Certificat installé :"
    describe_cert "$CERT_FILE"

    reload_proxy
}

# ── Rechargement du proxy ────────────────────────────────────────────────────

container_running() {
    command -v docker >/dev/null 2>&1 || return 1
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

reload_proxy() {
    if container_running "$NGINX_PROXY_CONTAINER"; then
        if docker exec "$NGINX_PROXY_CONTAINER" nginx -t >/dev/null 2>&1; then
            docker exec "$NGINX_PROXY_CONTAINER" nginx -s reload
            info "Proxy nginx rechargé ($NGINX_PROXY_CONTAINER)."
        else
            warn "nginx -t échoue dans $NGINX_PROXY_CONTAINER, rechargement annulé.
       Diagnostic : docker exec $NGINX_PROXY_CONTAINER nginx -t"
        fi
    elif container_running "$TRAEFIK_CONTAINER"; then
        # Le watch de traefik.yml porte sur dynamic.yml, pas sur les fichiers
        # de certificat qu'il référence : un redémarrage est nécessaire.
        docker restart "$TRAEFIK_CONTAINER" >/dev/null
        info "Traefik redémarré ($TRAEFIK_CONTAINER)."
    else
        info "Aucun proxy en cours d'exécution, rien à recharger."
    fi
}

# ── Mode : certificat auto-signé ─────────────────────────────────────────────

cmd_self_signed() {
    local cn="" days=3650 key_type="rsa4096" host=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --san)      add_san "$2"; shift 2 ;;
            --cn)       cn="$2"; shift 2 ;;
            --days)     days="$2"; shift 2 ;;
            --key-type) key_type="$2"; shift 2 ;;
            -h|--help)  usage ;;
            -*)         die "option inconnue pour self-signed : $1" ;;
            *)          host="$1"; shift ;;
        esac
    done

    # Sans --san, on délègue au script historique : même certificat qu'avant,
    # aux mêmes SAN implicites (localhost et 127.0.0.1 en plus de l'hôte).
    if [[ ${#SAN_ENTRIES[@]} -eq 0 ]]; then
        if [[ -n "$host" ]]; then
            bash "$SCRIPT_DIR/gen-selfsigned-certs.sh" "$host"
        else
            bash "$SCRIPT_DIR/gen-selfsigned-certs.sh"
        fi
        reload_proxy
        return
    fi

    [[ -n "$host" ]] && add_san "$host"
    [[ -z "$cn" ]] && cn="$(default_cn)"

    TMP_DIR="$(mktemp -d)"
    local conf="$TMP_DIR/openssl.cnf"
    write_openssl_conf "$conf" "$cn" "$(san_string)"

    info "Génération d'un certificat auto-signé pour : $cn"
    info "SAN : $(san_string)"

    # shellcheck disable=SC2046  # découpage voulu des arguments de genpkey
    openssl genpkey $(genpkey_args "$key_type") -out "$TMP_DIR/key.pem" 2>/dev/null
    openssl req -x509 -new -key "$TMP_DIR/key.pem" -out "$TMP_DIR/cert.pem" \
        -days "$days" -sha256 -config "$conf" -extensions v3_req

    install_pem "$TMP_DIR/cert.pem" "$TMP_DIR/key.pem"

    echo ""
    info "Ce certificat n'est validé par aucune autorité. Pour lui faire"
    info "confiance sur une machine cliente :"
    echo "  sudo cp $CERT_FILE /usr/local/share/ca-certificates/repod.crt"
    echo "  sudo update-ca-certificates"
}

# ── Mode : requête de signature (CSR) ────────────────────────────────────────

cmd_csr() {
    local cn="" key_type="rsa4096" force=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --san)      add_san "$2"; shift 2 ;;
            --cn)       cn="$2"; shift 2 ;;
            --key-type) key_type="$2"; shift 2 ;;
            --force)    force=1; shift ;;
            -h|--help)  usage ;;
            *)          die "option inconnue pour csr : $1" ;;
        esac
    done

    [[ ${#SAN_ENTRIES[@]} -gt 0 ]] || die "au moins un --san est requis.
       Exemple : --san dns:repod.example.com --san dns:repod --san ip:192.0.2.10"
    [[ -z "$cn" ]] && cn="$(default_cn)"

    if [[ -f "$PENDING_DIR/request.csr" && $force -eq 0 ]]; then
        die "une requête est déjà en attente dans $PENDING_DIR.
       La régénérer produirait une nouvelle clé, et le certificat que
       l'autorité renverra pour la requête précédente ne correspondrait plus.
       Forcer avec --force si la requête précédente est abandonnée."
    fi

    mkdir -p "$PENDING_DIR"
    chmod 700 "$PENDING_DIR"

    TMP_DIR="$(mktemp -d)"
    local conf="$TMP_DIR/openssl.cnf"
    write_openssl_conf "$conf" "$cn" "$(san_string)"

    info "Génération de la clé ($key_type) et de la requête pour : $cn"
    info "SAN : $(san_string)"

    # shellcheck disable=SC2046  # découpage voulu des arguments de genpkey
    openssl genpkey $(genpkey_args "$key_type") -out "$TMP_DIR/key.pem" 2>/dev/null
    openssl req -new -key "$TMP_DIR/key.pem" -out "$TMP_DIR/request.csr" \
        -sha256 -config "$conf"

    install -m 600 "$TMP_DIR/key.pem"     "$PENDING_DIR/key.pem"
    install -m 644 "$TMP_DIR/request.csr" "$PENDING_DIR/request.csr"

    echo ""
    info "Requête écrite dans $PENDING_DIR/request.csr"
    info "La clé reste dans $PENDING_DIR : le certificat en service n'est pas touché."
    echo ""
    openssl req -in "$PENDING_DIR/request.csr" -noout -subject -nameopt RFC2253 | sed 's/^/       /'
    openssl req -in "$PENDING_DIR/request.csr" -noout -text \
        | sed -n '/Subject Alternative Name/,+1p' | tail -1 | sed 's/^ */       SAN: /'
    echo ""
    cat <<EOF
Soumission à l'autorité :

  AD CS      Enrôlement web (certsrv), « Submit a certificate request by using
             a base-64-encoded CMC or PKCS #10 file », coller le contenu de
             request.csr. Le modèle utilisé doit accepter les SAN fournis dans
             la requête, sans quoi l'autorité les remplace silencieusement par
             ceux de l'annuaire.

  easy-rsa   easyrsa import-req $PENDING_DIR/request.csr repod
             easyrsa sign-req server repod

Au retour du certificat signé, la clé en attente est reprise automatiquement :

  bash scripts/setup-tls.sh import --cert repod.crt --chain ca-chain.pem
EOF
}

# ── Mode : import d'un certificat existant ───────────────────────────────────

cmd_import() {
    local cert="" key="" chain="" pkcs12="" password_file="" password=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --cert)          cert="$2"; shift 2 ;;
            --key)           key="$2"; shift 2 ;;
            --chain)         chain="$2"; shift 2 ;;
            --pkcs12|--pfx)  pkcs12="$2"; shift 2 ;;
            --password-file) password_file="$2"; shift 2 ;;
            --password)      password="$2"; shift 2 ;;
            -h|--help)       usage ;;
            *)               die "option inconnue pour import : $1" ;;
        esac
    done

    TMP_DIR="$(mktemp -d)"

    if [[ -n "$pkcs12" ]]; then
        [[ -f "$pkcs12" ]] || die "fichier PKCS#12 introuvable : $pkcs12"
        [[ -n "$cert$key$chain" ]] && die "--pkcs12 ne se combine pas avec --cert, --key ou --chain"

        local passin="pass:"
        if [[ -n "$password_file" ]]; then
            passin="file:$password_file"
        elif [[ -n "$password" ]]; then
            passin="pass:$password"
        fi

        info "Extraction du PKCS#12 : $pkcs12"
        openssl pkcs12 -in "$pkcs12" -clcerts -nokeys -passin "$passin" \
            -out "$TMP_DIR/leaf.pem" 2>/dev/null \
            || die "extraction impossible. Mot de passe erroné ? Utiliser --password-file."
        openssl pkcs12 -in "$pkcs12" -cacerts -nokeys -passin "$passin" \
            -out "$TMP_DIR/chain.pem" 2>/dev/null || : > "$TMP_DIR/chain.pem"
        openssl pkcs12 -in "$pkcs12" -nocerts -nodes -passin "$passin" 2>/dev/null \
            | openssl pkey -out "$TMP_DIR/key.pem" \
            || die "clé privée absente du PKCS#12 : $pkcs12"

        # openssl insère un en-tête lisible avant chaque bloc PEM, sans effet
        # sur la lecture mais bruyant dans un fichier destiné à durer.
        strip_pem "$TMP_DIR/leaf.pem"
        strip_pem "$TMP_DIR/chain.pem"

        cat "$TMP_DIR/leaf.pem" "$TMP_DIR/chain.pem" > "$TMP_DIR/cert.pem"
        install_pem "$TMP_DIR/cert.pem" "$TMP_DIR/key.pem"
        return
    fi

    [[ -n "$cert" ]] || die "--cert est requis (ou --pkcs12 pour un export AD CS)"
    [[ -f "$cert" ]] || die "certificat introuvable : $cert"

    if [[ -z "$key" ]]; then
        [[ -f "$PENDING_DIR/key.pem" ]] || die "--key non fourni et aucune clé en attente dans $PENDING_DIR.
       Fournir --key, ou générer d'abord la requête avec « setup-tls.sh csr »."
        key="$PENDING_DIR/key.pem"
        info "Clé reprise de la requête en attente : $key"
    fi
    [[ -f "$key" ]] || die "clé privée introuvable : $key"

    # La clé et le certificat sont passés à leur emplacement d'origine : les
    # messages d'erreur citent alors le fichier de l'utilisateur, pas une copie
    # temporaire. install_pem ne fait que les lire.
    if [[ -n "$chain" ]]; then
        [[ -f "$chain" ]] || die "chaîne introuvable : $chain"
        cat "$cert" "$chain" > "$TMP_DIR/cert.pem"
        install_pem "$TMP_DIR/cert.pem" "$key"
    else
        install_pem "$cert" "$key"
    fi

    # La requête est honorée : la clé vit désormais au chemin canonique.
    if [[ "$key" == "$PENDING_DIR/key.pem" ]]; then
        rm -rf "$PENDING_DIR"
        info "Requête en attente honorée, $PENDING_DIR supprimé."
    fi
}

# Ne garde que les blocs PEM d'un fichier produit par openssl pkcs12.
strip_pem() {
    local file="$1"
    [[ -s "$file" ]] || return 0
    awk '/-----BEGIN/ { keep = 1 } keep { print } /-----END/ { keep = 0 }' "$file" > "$file.clean"
    mv "$file.clean" "$file"
}

# ── Mode : Let's Encrypt ─────────────────────────────────────────────────────

compose() {
    local files="${REPOD_COMPOSE_FILES:-$DEFAULT_COMPOSE_FILES}"
    # shellcheck disable=SC2086  # la liste de -f doit être découpée
    (cd "$REPO_ROOT" && docker compose $files "$@")
}

cmd_letsencrypt() {
    local domain="" email=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)  domain="$2"; shift 2 ;;
            --email)   email="$2"; shift 2 ;;
            --staging) export CERTBOT_STAGING="--staging"; shift ;;
            -h|--help) usage ;;
            *)         die "option inconnue pour letsencrypt : $1" ;;
        esac
    done

    [[ -n "$domain" ]] || die "--domain est requis"
    [[ -n "$email"  ]] || die "--email est requis"

    export REPOD_DOMAIN="$domain" CERTBOT_EMAIL="$email"

    if container_running "$TRAEFIK_CONTAINER"; then
        die "l'overlay actif est Traefik, qui gère ACME nativement.
       Voir le bloc commenté en fin de traefik/traefik.yml : définir le
       certResolver plutôt que de passer par certbot."
    fi

    # Amorçage : nginx refuse de démarrer sans certificat, et sans nginx le
    # challenge HTTP-01 n'est pas servi sur :80. Un auto-signé temporaire lève
    # la dépendance circulaire.
    if [[ ! -f "$CERT_FILE" ]]; then
        info "Aucun certificat en place, génération d'un auto-signé temporaire"
        info "pour permettre au proxy de démarrer et de servir le challenge ACME."
        bash "$SCRIPT_DIR/gen-selfsigned-certs.sh" "$domain"
    fi

    # --scale certbot=0 : le service certbot est un one-shot, il n'a rien à
    # faire dans le démarrage de la pile.
    info "Démarrage de la pile (le challenge ACME est servi sur :80)"
    compose up -d --scale certbot=0

    info "Demande du certificat pour $domain"
    compose run --rm certbot \
        || die "certbot a échoué. Vérifier que $domain pointe bien vers cette
       machine et que le port 80 est joignable depuis Internet."

    install_letsencrypt "$domain"
}

install_letsencrypt() {
    local domain="$1"
    local live="$LETSENCRYPT_DIR/live/$domain"

    [[ -f "$live/fullchain.pem" ]] || die "certificat Let's Encrypt introuvable : $live/fullchain.pem"
    install_pem "$live/fullchain.pem" "$live/privkey.pem"
}

cmd_renew() {
    local domain="${REPOD_DOMAIN:-}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain)  domain="$2"; shift 2 ;;
            -h|--help) usage ;;
            *)         die "option inconnue pour renew : $1" ;;
        esac
    done

    if [[ -z "$domain" ]]; then
        # Un seul domaine dans live/ : inutile de le faire répéter.
        local candidates=()
        [[ -d "$LETSENCRYPT_DIR/live" ]] && while IFS= read -r d; do
            candidates+=("$(basename "$d")")
        done < <(find "$LETSENCRYPT_DIR/live" -mindepth 1 -maxdepth 1 -type d)
        [[ ${#candidates[@]} -eq 1 ]] || die "domaine indéterminé : préciser --domain ou définir REPOD_DOMAIN"
        domain="${candidates[0]}"
    fi

    export REPOD_DOMAIN="$domain"

    # L'entrypoint du service certbot est figé sur « certonly » : il est
    # remplacé ici, le reste des options (webroot, deploy-hook) venant du
    # fichier de renouvellement écrit par certbot à l'émission.
    info "Renouvellement pour $domain"
    compose run --rm --entrypoint certbot certbot renew

    # Le deploy-hook de docker-compose.letsencrypt.yml a déjà recopié le
    # certificat ; l'installation locale rejoue les contrôles et recharge le
    # proxy, y compris si le hook n'a pas tourné (certificat encore valide).
    install_letsencrypt "$domain"
}

# ── Mode : état ──────────────────────────────────────────────────────────────

cmd_status() {
    if [[ -f "$CERT_FILE" ]]; then
        info "Certificat en service : $CERT_FILE"
        describe_cert "$CERT_FILE"
        if [[ -f "$KEY_FILE" ]]; then
            if openssl x509 -in "$CERT_FILE" -noout -pubkey 2>/dev/null \
               | diff -q - <(openssl pkey -in "$KEY_FILE" -pubout -passin pass: 2>/dev/null) >/dev/null 2>&1
            then
                echo "       Clé privée : correspond"
            else
                warn "la clé privée $KEY_FILE ne correspond pas au certificat"
            fi
        else
            warn "clé privée absente : $KEY_FILE"
        fi
        openssl x509 -in "$CERT_FILE" -noout -checkend 2592000 >/dev/null \
            || warn "expiration dans moins de 30 jours"
    else
        info "Aucun certificat installé ($CERT_FILE absent)."
        info "Démarrer avec : bash scripts/setup-tls.sh self-signed"
    fi

    if [[ -f "$PENDING_DIR/request.csr" ]]; then
        echo ""
        info "Requête en attente de signature : $PENDING_DIR/request.csr"
        openssl req -in "$PENDING_DIR/request.csr" -noout -subject -nameopt RFC2253 | sed 's/^/       /'
    fi

    echo ""
    if container_running "$NGINX_PROXY_CONTAINER"; then
        info "Proxy actif : nginx ($NGINX_PROXY_CONTAINER)"
    elif container_running "$TRAEFIK_CONTAINER"; then
        info "Proxy actif : Traefik ($TRAEFIK_CONTAINER)"
    else
        info "Aucun proxy TLS en cours d'exécution."
    fi
}

# ── Aiguillage ───────────────────────────────────────────────────────────────

command -v openssl >/dev/null 2>&1 || die "openssl est requis"

[[ $# -ge 1 ]] || usage 1

mode="$1"; shift
case "$mode" in
    self-signed|selfsigned) cmd_self_signed "$@" ;;
    csr)                    cmd_csr "$@" ;;
    import)                 cmd_import "$@" ;;
    letsencrypt|le)         cmd_letsencrypt "$@" ;;
    renew)                  cmd_renew "$@" ;;
    status)                 cmd_status "$@" ;;
    -h|--help|help)         usage ;;
    *)                      die "mode inconnu : $mode (voir --help)" ;;
esac
