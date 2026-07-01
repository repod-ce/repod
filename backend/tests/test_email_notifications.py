"""
Module : test_email_notifications.py
Rôle   : Tests unitaires pour services/email_notifications.py
         (SMTP de base : réinitialisation de mot de passe + test de config)
Expose : TestGetEmailCfg · TestSendEmail · TestSendTestEmail
Dépend : pytest, unittest.mock, services.email_notifications
"""
import email as _email_lib
import email.header
import base64
import re

import smtplib
from unittest.mock import patch, MagicMock

from services.email_notifications import (
    _send_email,
    _send_email_to,
    _get_email_cfg,
    send_test_email,
)


# ── Helpers MIME ──────────────────────────────────────────────────────────────

def _decode_mime_body(raw_msg: str) -> str:
    """
    Décode un message MIME brut (tel que passé à smtplib.sendmail) en texte
    lisible : sujet décodé + corps texte/html décodés, concaténés.

    Nécessaire car MIMEText(charset='utf-8') encode systématiquement le corps
    en base64, même pour du contenu ASCII, dès que le type de charset est utf-8.
    """
    msg = _email_lib.message_from_string(raw_msg)

    parts: list[str] = []

    # Décode le sujet (RFC 2047 base64 ou QP pour les non-ASCII)
    raw_subject = msg.get("Subject", "")
    for encoded_bytes, charset in _email_lib.header.decode_header(raw_subject):
        if isinstance(encoded_bytes, bytes):
            parts.append(encoded_bytes.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(encoded_bytes)

    # Décode chaque partie texte ou html
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)   # décode base64/QP → bytes
            if payload:
                cs = part.get_content_charset() or "utf-8"
                parts.append(payload.decode(cs, errors="replace"))

    return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# _get_email_cfg
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetEmailCfg:

    def test_returns_none_when_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            assert _get_email_cfg() is None

    def test_returns_none_when_smtp_host_missing(self, email_settings):
        email_settings["email"]["smtp_host"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _get_email_cfg() is None

    def test_returns_none_when_to_addresses_missing(self, email_settings):
        email_settings["email"]["to_addresses"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _get_email_cfg() is None

    def test_returns_cfg_when_valid(self, email_settings):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _get_email_cfg()
        assert result is not None
        assert result["smtp_host"] == "smtp.test.local"


# ═══════════════════════════════════════════════════════════════════════════════
# _send_email — BUG #1 : to_override manquant dans la signature
# ═══════════════════════════════════════════════════════════════════════════════

class TestSendEmail:
    """
    BUG #1 — auth/router.py:379 appelle :
        _send_email(subject, body_html, body_text, to_override=user["email"])
    Avant correctif → TypeError: got an unexpected keyword argument 'to_override'
    """

    # ── Chemins d'échec (pas de connexion SMTP) ──────────────────────────────

    def test_returns_false_when_email_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            assert _send_email("Sujet", "<p>html</p>", "texte") is False

    def test_returns_false_when_no_recipients_configured(self, email_settings):
        email_settings["email"]["to_addresses"] = "  ,  ,  "  # blancs seulement
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            assert _send_email("Sujet", "<p>html</p>", "texte") is False

    # ── BUG #1 — Tests rouges avant correctif ────────────────────────────────

    def test_to_override_routes_email_to_specified_address(
        self, email_settings, mock_smtp
    ):
        """
        ❌ ROUGE avant fix — TypeError: _send_email() got an unexpected
           keyword argument 'to_override'
        ✅ VERT après fix  — L'email part vers to_override, pas vers to_addresses
        """
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email(
                "Reset password — APT Repo Manager",
                "<p>Lien de réinitialisation</p>",
                "Lien de réinitialisation",
                to_override="user.specifique@company.com",
            )

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        # DOIT être l'override, pas "admin@test.local" (to_addresses configuré)
        assert recipients == ["user.specifique@company.com"]

    def test_to_override_ignores_configured_to_addresses(
        self, email_settings, mock_smtp
    ):
        """to_addresses configuré ne doit PAS être utilisé quand to_override est fourni."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte",
                        to_override="override@test.com")

        _, recipients, _ = mock_server.sendmail.call_args.args
        assert "admin@test.local" not in recipients
        assert recipients == ["override@test.com"]

    def test_to_override_empty_string_returns_false(
        self, email_settings, mock_smtp
    ):
        """to_override avec chaîne vide (après strip) → False, pas d'envoi."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte",
                                 to_override="   ")

        assert result is False
        mock_server.sendmail.assert_not_called()

    def test_to_override_none_falls_back_to_to_addresses(
        self, email_settings, mock_smtp
    ):
        """to_override=None utilise les destinataires configurés dans to_addresses."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte",
                                 to_override=None)

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert recipients == ["admin@test.local"]

    # ── Comportements SMTP ────────────────────────────────────────────────────

    def test_uses_configured_recipients_without_override(
        self, email_settings, mock_smtp
    ):
        """Sans to_override, les destinataires viennent de to_addresses."""
        mock_class, mock_server = mock_smtp
        email_settings["email"]["to_addresses"] = "a@x.com, b@x.com , c@x.com"
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte")

        assert result is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert set(recipients) == {"a@x.com", "b@x.com", "c@x.com"}

    def test_starttls_called_on_port_587(self, email_settings, mock_smtp):
        """STARTTLS est appelé quand port=587 et use_tls=True."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.starttls.assert_called_once()

    def test_no_starttls_when_use_tls_false(self, email_settings, mock_smtp):
        """STARTTLS n'est PAS appelé si use_tls=False."""
        mock_class, mock_server = mock_smtp
        email_settings["email"]["use_tls"] = False
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.starttls.assert_not_called()

    def test_smtp_ssl_used_on_port_465(self, email_settings_ssl, mock_smtp_ssl):
        """smtplib.SMTP_SSL est instancié quand smtp_port=465."""
        mock_class, mock_server = mock_smtp_ssl
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_ssl):
            result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is True
        mock_class.assert_called_once()

    def test_login_called_with_credentials(self, email_settings, mock_smtp):
        """server.login() est appelé avec les credentials configurés."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Sujet", "<p>html</p>", "texte")
        mock_server.login.assert_called_once_with("repod@test.local", "s3cr3t")

    def test_auth_error_returns_false(self, email_settings, mock_smtp):
        """SMTPAuthenticationError → False (pas d'exception non catchée)."""
        mock_class, mock_server = mock_smtp
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"Incorrect authentication data"
        )
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is False

    def test_connect_error_returns_false(self, email_settings):
        """SMTPConnectError → False."""
        with patch("smtplib.SMTP",
                   side_effect=smtplib.SMTPConnectError(421, b"no route")):
            with patch("services.email_notifications.get_settings",
                       return_value=email_settings):
                result = _send_email("Sujet", "<p>html</p>", "texte")
        assert result is False

    def test_subject_prefixed_with_repod(self, email_settings, mock_smtp):
        """L'objet de l'email est préfixé par '[repod]'."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            _send_email("Mon sujet", "<p>html</p>", "texte")
        _, _, raw_msg = mock_server.sendmail.call_args.args
        assert "[repod]" in raw_msg
        assert "Mon sujet" in raw_msg


# ═══════════════════════════════════════════════════════════════════════════════
# send_test_email
# ═══════════════════════════════════════════════════════════════════════════════

class TestSendTestEmail:

    def test_returns_error_when_disabled(self, email_settings_disabled):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings_disabled):
            result = send_test_email()
        assert result["ok"] is False
        assert "désactivées" in result["error"]

    def test_returns_error_when_no_smtp_host(self):
        with patch("services.email_notifications.get_settings",
                   return_value={"email": {"enabled": True, "smtp_host": ""}}):
            result = send_test_email()
        assert result["ok"] is False
        assert "smtp_host" in result["error"]

    def test_returns_error_when_no_recipients(self, email_settings):
        email_settings["email"]["to_addresses"] = ""
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is False
        assert "destinataire" in result["error"].lower()

    def test_success_with_configured_recipients(self, email_settings, mock_smtp):
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is True
        assert result["error"] is None

    def test_to_override_used_as_sole_recipient(self, email_settings, mock_smtp):
        """send_test_email(to_override=...) envoie à l'adresse fournie."""
        mock_class, mock_server = mock_smtp
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email(to_override="test-override@company.com")

        assert result["ok"] is True
        _, recipients, _ = mock_server.sendmail.call_args.args
        assert recipients == ["test-override@company.com"]

    def test_smtp_failure_returns_error_dict(self, email_settings, mock_smtp):
        """Échec SMTP → ok=False avec message d'erreur, pas d'exception levée."""
        mock_class, mock_server = mock_smtp
        mock_server.sendmail.side_effect = Exception("network error")
        with patch("services.email_notifications.get_settings",
                   return_value=email_settings):
            result = send_test_email()
        assert result["ok"] is False
        assert result["error"] is not None


