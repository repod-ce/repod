"""
Service MFA TOTP (P2-3).

Fournit les primitives cryptographiques pour la double authentification :
  • generate_totp_secret()       → base32 secret (32 chars, 160 bits)
  • get_totp_uri(secret, user)   → otpauth:// URI (pour les applis TOTP)
  • generate_qr_code_base64(uri) → PNG base64 (affiché dans le frontend)
  • verify_totp(secret, code)    → bool (with_valid_window ±1 intervalle)

Flux d'activation :
  1. L'utilisateur appelle POST /api/v1/auth/mfa/setup
     → generate_totp_secret() + get_totp_uri() + generate_qr_code_base64()
     → secret stocké dans users.totp_pending_secret
  2. L'utilisateur scanne le QR code et soumet un code TOTP
     → POST /api/v1/auth/mfa/confirm avec {totp_code}
     → verify_totp(pending_secret, code) → si True : active le MFA

Flux de login avec MFA :
  1. POST /api/v1/auth/token → si mfa_enabled : retourner {mfa_required:true, mfa_token}
  2. POST /api/v1/auth/mfa/authenticate → {mfa_token, totp_code}
     → verify_totp(totp_secret, code) → si True : retourner {access_token}
"""
import base64
import io
import urllib.parse

import pyotp
import qrcode
from PIL import Image

ISSUER = "repod"


def generate_totp_secret() -> str:
    """
    Génère un secret TOTP en base32 (32 caractères = 160 bits).
    Compatible RFC 6238 / RFC 4648.
    """
    return pyotp.random_base32(length=32)


def get_totp_uri(secret: str, username: str, issuer: str = ISSUER) -> str:
    """
    Génère l'URI otpauth:// compatible avec Google Authenticator, Authy, etc.

    Format : otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code_base64(uri: str) -> str:
    """
    Génère un QR code PNG encodé en base64 à partir d'une URI TOTP.
    La chaîne retournée peut être utilisée directement dans une balise HTML :
        <img src="data:image/png;base64,{result}" />
    """
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Vérifie un code TOTP contre le secret.

    valid_window=1 accepte le code de l'intervalle précédent et du suivant
    (tolère les petites dérives d'horloge).

    Retourne False (pas d'exception) pour tout secret ou code invalide.
    """
    if not code or not code.isdigit() or len(code) != 6:
        return False
    try:
        totp = pyotp.TOTP(secret)
        result = totp.verify(code, valid_window=valid_window)
        return bool(result)
    except Exception:
        return False
