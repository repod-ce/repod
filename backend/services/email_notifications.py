"""
Service de notifications email (SMTP).

Envoie des alertes par email pour :
  - notify_pending_review_email  : paquet en révision RSSI
  - notify_sla_expiring_email    : décisions CVE expirantes (SLA J-7)
  - notify_decision_email        : confirmation décision RSSI

Configuration dans settings.json → "email" :
  {
    "enabled": false,
    "smtp_host": "smtp.example.com",
    "smtp_port": 587,
    "smtp_user": "repod@example.com",
    "smtp_password": "secret",
    "from_address": "repod@example.com",
    "to_addresses": "rssi@example.com,admin@example.com",
    "use_tls": true
  }
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from services.settings import get_settings

logger = logging.getLogger("email_notifications")

# Retry sur erreurs de connexion SMTP transitoires uniquement — jamais sur un
# échec d'authentification (identifiants invalides = retry inutile).
_retry_smtp_transient = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type((
        smtplib.SMTPConnectError,
        smtplib.SMTPServerDisconnected,
        ConnectionError,
        TimeoutError,
        OSError,
    )),
)


def _get_email_cfg() -> dict | None:
    """Retourne la config email si activée et complète, sinon None."""
    cfg = get_settings().get("email", {})
    if not cfg.get("enabled"):
        return None
    if not cfg.get("smtp_host") or not cfg.get("to_addresses"):
        logger.warning("[email] Configuration incomplète — smtp_host ou to_addresses manquant")
        return None
    return cfg


def _send_email_to(subject: str, body_html: str, body_text: str, cfg: dict, recipients: list[str]) -> bool:
    """Envoie un email à une liste explicite de destinataires. Retourne True si OK."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[repod] {subject}"
    msg["From"]    = cfg.get("from_address", cfg.get("smtp_user", "repod@localhost"))
    msg["To"]      = ", ".join(recipients)

    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html",  "utf-8"))

    host = cfg["smtp_host"]
    port = int(cfg.get("smtp_port", 587))
    user = cfg.get("smtp_user", "")
    pwd  = cfg.get("smtp_password", "")
    tls  = cfg.get("use_tls", True)
    # Port 465 = SSL direct (SMTP_SSL) ; port 587/25 = STARTTLS ou plain
    use_ssl = (port == 465)

    try:
        _smtp_send(host, port, use_ssl, tls, user, pwd, msg, recipients)
        logger.info(f"[email] Envoyé '{subject}' → {recipients}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"[email] Authentification SMTP échouée : {e}")
    except smtplib.SMTPConnectError as e:
        logger.error(f"[email] Connexion SMTP impossible ({host}:{port}) : {e}")
    except Exception as e:
        logger.error(f"[email] Erreur envoi : {e}")
    return False


@_retry_smtp_transient
def _smtp_send(host: str, port: int, use_ssl: bool, tls: bool, user: str, pwd: str,
                msg: MIMEMultipart, recipients: list[str]) -> None:
    """Connexion + envoi SMTP avec retry/backoff sur erreurs réseau transitoires (3 tentatives)."""
    context = ssl.create_default_context()
    if use_ssl:
        cm = smtplib.SMTP_SSL(host, port, timeout=10, context=context)
    else:
        cm = smtplib.SMTP(host, port, timeout=10)
    with cm as server:
        if not use_ssl and tls:
            server.starttls(context=context)
        if user and pwd:
            server.login(user, pwd)
        server.sendmail(msg["From"], recipients, msg.as_string())


def _send_email(
    subject: str,
    body_html: str,
    body_text: str,
    to_override: str | None = None,
) -> bool:
    """
    Envoie un email aux destinataires configurés (ou à to_override). Retourne True si OK.

    to_override : si fourni et non-vide, remplace to_addresses pour cet envoi.
                  Usage : reset password, notifications par utilisateur.
    """
    cfg = _get_email_cfg()
    if not cfg:
        return False

    if to_override is not None:
        stripped = to_override.strip()
        recipients = [stripped] if stripped else []
    else:
        recipients = [r.strip() for r in cfg["to_addresses"].split(",") if r.strip()]

    if not recipients:
        return False
    return _send_email_to(subject, body_html, body_text, cfg, recipients)


def _base_style() -> str:
    return """
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             background: #f8fafc; margin: 0; padding: 20px; }
      .card { background: #fff; border-radius: 12px; border: 1px solid #e2e8f0;
              max-width: 600px; margin: 0 auto; overflow: hidden; }
      .header { background: #1e293b; padding: 20px 24px; }
      .header h1 { color: #fff; margin: 0; font-size: 18px; }
      .header p  { color: #94a3b8; margin: 4px 0 0; font-size: 13px; }
      .body { padding: 24px; }
      .badge { display: inline-block; padding: 2px 10px; border-radius: 99px;
               font-size: 12px; font-weight: 600; }
      .badge-red    { background: #fee2e2; color: #dc2626; }
      .badge-orange { background: #ffedd5; color: #ea580c; }
      .badge-amber  { background: #fef3c7; color: #d97706; }
      .badge-blue   { background: #dbeafe; color: #2563eb; }
      .badge-green  { background: #dcfce7; color: #16a34a; }
      .table { width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 13px; }
      .table th { background: #f1f5f9; padding: 8px 12px; text-align: left;
                  font-size: 11px; text-transform: uppercase; color: #64748b; }
      .table td { padding: 10px 12px; border-bottom: 1px solid #f1f5f9; }
      .mono { font-family: monospace; }
      .footer { padding: 16px 24px; background: #f8fafc;
                border-top: 1px solid #e2e8f0; font-size: 12px; color: #94a3b8; }
      .btn { display: inline-block; margin-top: 16px; padding: 10px 20px;
             background: #3b82f6; color: #fff; border-radius: 8px;
             text-decoration: none; font-size: 14px; font-weight: 600; }
    </style>
    """


# ─── Notifications ────────────────────────────────────────────────────────────

def notify_pending_review_email(
    package: str,
    version: str,
    arch: str,
    distribution: str,
    cve_counts: dict,
    worst_severity: str | None,
    kev_count: int = 0,
) -> bool:
    sev_badge = {
        "Critical": "badge-red",
        "High":     "badge-orange",
        "Medium":   "badge-amber",
        "Low":      "badge-blue",
    }.get(worst_severity, "badge-blue")

    cve_rows = "".join(
        f"<tr><td class='mono'>{s.capitalize()}</td><td><strong>{n}</strong></td></tr>"
        for s, n in cve_counts.items() if n > 0
    )
    kev_block = (
        f"<div style='background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;"
        f"padding:10px 14px;margin-top:12px;color:#dc2626;font-size:13px;'>"
        f"⚠️ <strong>{kev_count} CVE activement exploitée(s)</strong> dans le catalogue KEV CISA</div>"
    ) if kev_count else ""

    html = f"""<!DOCTYPE html><html><head>{_base_style()}</head><body>
    <div class='card'>
      <div class='header'>
        <h1>⏳ Paquet en attente de révision RSSI</h1>
        <p>{datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
      </div>
      <div class='body'>
        <p>Le paquet suivant a été importé mais nécessite une <strong>décision RSSI</strong>
           avant d'être publié dans le dépôt APT :</p>
        <table class='table'>
          <tr><th>Paquet</th><td class='mono'><strong>{package}</strong></td></tr>
          <tr><th>Version</th><td class='mono'>{version}</td></tr>
          <tr><th>Architecture</th><td>{arch}</td></tr>
          <tr><th>Distribution</th><td>{distribution}</td></tr>
          <tr><th>Sévérité max</th>
              <td><span class='badge {sev_badge}'>{worst_severity or "?"}</span></td></tr>
        </table>
        <table class='table' style='margin-top:12px'>
          <tr><th>Sévérité</th><th>Nb CVE</th></tr>
          {cve_rows or "<tr><td colspan='2'>Aucune CVE détectée</td></tr>"}
        </table>
        {kev_block}
        <a href='#' class='btn'>Accéder à la file de révision →</a>
      </div>
      <div class='footer'>Notification automatique — repod APT Repository Manager</div>
    </div></body></html>"""

    text = (
        f"Paquet en attente de révision RSSI\n"
        f"Paquet : {package} {version} ({arch}, {distribution})\n"
        f"Sévérité max : {worst_severity}\n"
        f"CVE : {', '.join(f'{s}={n}' for s, n in cve_counts.items() if n > 0)}\n"
        + (f"⚠ {kev_count} CVE dans KEV CISA\n" if kev_count else "")
    )

    return _send_email(
        f"Révision RSSI requise — {package} {version}",
        html, text
    )


def notify_sla_expiring_email(expiring: list[dict]) -> bool:
    if not expiring:
        return False

    action_labels = {
        "accept_risk":      "Risque accepté",
        "exception":        "Exception",
        "upgrade_required": "Upgrade requis",
    }

    rows = ""
    for d in expiring:
        days = d.get("remaining_days", 0)
        if days < 0:
            status_cell = "<span class='badge badge-red'>Expirée</span>"
        elif days == 0:
            status_cell = "<span class='badge badge-red'>Expire aujourd'hui</span>"
        elif days <= 3:
            status_cell = f"<span class='badge badge-red'>J-{days}</span>"
        else:
            status_cell = f"<span class='badge badge-amber'>J-{days}</span>"

        rows += (
            f"<tr><td class='mono'>{d['package']} {d.get('version','')}</td>"
            f"<td>{action_labels.get(d.get('action',''), d.get('action',''))}</td>"
            f"<td>{d.get('decided_by','?')}</td>"
            f"<td>{status_cell}</td></tr>"
        )

    html = f"""<!DOCTYPE html><html><head>{_base_style()}</head><body>
    <div class='card'>
      <div class='header'>
        <h1>⏰ Décisions CVE expirantes</h1>
        <p>{len(expiring)} décision(s) à renouveler</p>
      </div>
      <div class='body'>
        <p>Les décisions RSSI suivantes expirent bientôt ou sont déjà expirées.
           Les paquets expirés repasseront automatiquement en file de révision.</p>
        <table class='table'>
          <tr><th>Paquet</th><th>Décision</th><th>Décidé par</th><th>SLA</th></tr>
          {rows}
        </table>
        <a href='#' class='btn'>Gérer les décisions →</a>
      </div>
      <div class='footer'>Notification automatique — repod APT Repository Manager</div>
    </div></body></html>"""

    text = "Décisions CVE expirantes :\n" + "\n".join(
        f"  • {d['package']} {d.get('version','')} — {action_labels.get(d.get('action',''), '')} — J-{d.get('remaining_days',0)}"
        for d in expiring
    )

    return _send_email(
        f"SLA CVE — {len(expiring)} décision(s) expirante(s)",
        html, text
    )


def notify_decision_email(
    package: str,
    version: str,
    action: str,
    decided_by: str,
    justification: str,
    expires_in_days: int | None = None,
) -> bool:
    action_labels = {
        "accept_risk":      ("✅ Risque accepté",     "badge-green"),
        "exception":        ("🔓 Exception accordée", "badge-blue"),
        "reject":           ("🚫 Rejeté",             "badge-red"),
        "upgrade_required": ("🔼 Upgrade requis",     "badge-amber"),
    }
    label, badge = action_labels.get(action, (action, "badge-blue"))

    expire_row = (
        f"<tr><th>Expiration SLA</th><td>Dans <strong>{expires_in_days} jours</strong></td></tr>"
        if expires_in_days else ""
    )

    html = f"""<!DOCTYPE html><html><head>{_base_style()}</head><body>
    <div class='card'>
      <div class='header'>
        <h1>Décision RSSI enregistrée</h1>
        <p>{datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
      </div>
      <div class='body'>
        <table class='table'>
          <tr><th>Paquet</th><td class='mono'><strong>{package} {version}</strong></td></tr>
          <tr><th>Décision</th><td><span class='badge {badge}'>{label}</span></td></tr>
          <tr><th>Décidé par</th><td>{decided_by}</td></tr>
          {expire_row}
          <tr><th>Justification</th><td style='font-size:13px'>{justification[:300]}</td></tr>
        </table>
      </div>
      <div class='footer'>Notification automatique — repod APT Repository Manager</div>
    </div></body></html>"""

    text = (
        f"Décision RSSI : {label}\n"
        f"Paquet : {package} {version}\n"
        f"Décidé par : {decided_by}\n"
        f"Justification : {justification[:200]}\n"
        + (f"Expire dans : {expires_in_days} jours\n" if expires_in_days else "")
    )

    return _send_email(
        f"Décision RSSI — {package} {version} — {label}",
        html, text
    )


def notify_patch_available_email(
    package: str,
    version: str,
    target_version: str,
    depot_version: str,
    clients: list[dict],
    app_url: str = "",
) -> bool:
    """Notifie qu'un correctif demandé par le RSSI est disponible dans le dépôt."""
    rows = "".join(
        f"<tr><td>{c.get('label') or c['id']}</td></tr>" for c in clients[:20]
    ) or "<tr><td>Aucune machine concernée</td></tr>"

    deploy_row = ""
    if app_url and clients:
        client_ids = ",".join(str(c["id"]) for c in clients)
        deploy_url = f"{app_url}/deploy?package={package}&clients={client_ids}"
        deploy_row = f"<tr><th>Déployer</th><td><a href='{deploy_url}'>{deploy_url}</a></td></tr>"

    html = f"""<!DOCTYPE html><html><head>{_base_style()}</head><body>
    <div class='card'>
      <div class='header'>
        <h1>Correctif disponible</h1>
        <p>{datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
      </div>
      <div class='body'>
        <table class='table'>
          <tr><th>Paquet</th><td class='mono'><strong>{package} {version}</strong></td></tr>
          <tr><th>Version cible</th><td class='mono'>{target_version}</td></tr>
          <tr><th>Version disponible</th><td class='mono'><span class='badge badge-green'>{depot_version}</span></td></tr>
          {deploy_row}
        </table>
        <p style='margin-top:14px;font-size:13px'>Machines exposées au paquet vulnérable ({len(clients)}) :</p>
        <table class='table'>{rows}</table>
      </div>
      <div class='footer'>Notification automatique — repod APT Repository Manager</div>
    </div></body></html>"""

    text = (
        f"Correctif disponible pour {package} {version} -> {target_version}\n"
        f"Version dans le dépôt : {depot_version}\n"
        f"Machines concernées : {len(clients)}\n"
    )

    return _send_email(
        f"Correctif disponible — {package} {version}",
        html, text
    )


def send_test_email(to_override: str | None = None) -> dict:
    """Envoie un email de test. Retourne {ok, error}."""
    cfg = get_settings().get("email", {})
    if not cfg.get("enabled"):
        return {"ok": False, "error": "Notifications email désactivées dans les paramètres"}
    if not cfg.get("smtp_host"):
        return {"ok": False, "error": "smtp_host non configuré"}

    html = f"""<!DOCTYPE html><html><head>{_base_style()}</head><body>
    <div class='card'>
      <div class='header'><h1>✅ Test email repod</h1></div>
      <div class='body'>
        <p>Si vous recevez cet email, la configuration SMTP est correcte.</p>
        <p style='color:#64748b;font-size:13px'>
          Serveur : {cfg.get('smtp_host')}:{cfg.get('smtp_port', 587)}<br>
          Envoyé le : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}
        </p>
      </div>
      <div class='footer'>repod APT Repository Manager</div>
    </div></body></html>"""
    text = "Test email repod — configuration SMTP OK"

    # Envoi direct sans modifier settings.json
    recipients = [to_override.strip()] if to_override else [
        r.strip() for r in cfg.get("to_addresses", "").split(",") if r.strip()
    ]
    if not recipients:
        return {"ok": False, "error": "Aucun destinataire configuré (to_addresses vide)"}

    ok = _send_email_to("Test de configuration SMTP", html, text, cfg, recipients)
    return {"ok": ok, "error": None if ok else "Échec d'envoi — vérifiez les logs backend"}
