"""
services/notifications.py — Journalisation interne des événements notifiables.

Les canaux de livraison externes (webhook générique, Slack, Teams, email
d'alerte CVE) ne sont pas disponibles dans Repod Community.

notify(event_type, context) reste le point d'entrée appelé depuis
promotion.py / retention.py / main.py : il rend le
message via les templates ci-dessous et le consigne dans les logs
applicatifs (niveau INFO). Il ne lève jamais d'exception.
"""

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("notifications")

SUPPORTED_EVENTS = frozenset({
    "CVE_BLOCKED",
    "PENDING_REVIEW",
    "PROMOTION_APPROVED",
    "PROMOTION_REJECTED",
    "SLA_OVERDUE",
    "UPLOAD_FAILED",
    "VERSION_GC",
    "AUDIT_EXPORT_ARCHIVE",
    "AUDIT_EXPORT_USER",
    "INTEGRITY_ALERT",
    "SECURITY_PATCH",
    "SCHEDULER_JOB_FAILED",
})

# ── Templates ─────────────────────────────────────────────────────────────────

class _SafeDict(dict):
    """dict dont les clés manquantes retournent '{key}' — jamais de KeyError."""
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"


def _render(template: str, context: dict) -> str:
    """Substitue {key} dans template. Les valeurs ne sont jamais ré-interprétées."""
    return template.format_map(_SafeDict(context))


_TEMPLATES: dict[str, tuple[str, str]] = {
    "CVE_BLOCKED": (
        "🚨 [Repod] Promotion bloquée — CVE critique : {package}@{version}",
        (
            "La promotion du paquet {package}@{version} ({from_dist} → {to_dist}) "
            "a été BLOQUÉE par la politique CVE.\n\n"
            "Raison : {detail}\n\n"
            "Cette décision ne peut PAS être contournée même avec force=True.\n"
            "Une mise à jour du paquet est nécessaire avant toute promotion."
        ),
    ),
    "PENDING_REVIEW": (
        "⚠️ [Repod] Approbation RSSI requise : {package}@{version}",
        (
            "Le paquet {package}@{version} est en attente d'approbation RSSI "
            "({from_dist} → {to_dist}).\n\n"
            "Raison : {detail}\n\n"
            "Action requise : approuver ou rejeter via l'API ou le dashboard Repod."
        ),
    ),
    "PROMOTION_APPROVED": (
        "✅ [Repod] Promotion approuvée (override admin) : {package}@{version}",
        (
            "La promotion de {package}@{version} ({from_dist} → {to_dist}) "
            "a été approuvée avec override administrateur.\n\n"
            "Approuvé par : {user}\n"
            "Justification : {justification}\n"
            "Avertissements CVE : {warnings}"
        ),
    ),
    "PROMOTION_REJECTED": (
        "🚫 [Repod] Promotion refusée : {package}@{version}",
        (
            "La demande de promotion de {package}@{version} "
            "({from_dist} → {to_dist}) a été REFUSÉE par le RSSI.\n\n"
            "Refusée par : {user}\n"
            "Motif : {reason}\n\n"
            "Le paquet reste dans la distribution source. "
            "Une mise à jour corrigeant les CVE est nécessaire avant une nouvelle tentative."
        ),
    ),
    "SLA_OVERDUE": (
        "⏰ [Repod] SLA dépassé — {count} paquet(s) en attente de review",
        (
            "{count} paquet(s) dépasse(nt) le SLA de review ({max_age_days} jours) :\n\n"
            "{package_list}\n\n"
            "Veuillez prendre une décision de sécurité pour chacun dans Repod."
        ),
    ),
    "UPLOAD_FAILED": (
        "❌ [Repod] Échec d'import : {package}",
        (
            "L'import du paquet {package} a échoué.\n\n"
            "Raison : {detail}\n"
            "Importé par : {user}"
        ),
    ),
    "VERSION_GC": (
        "🗑️ [Repod] GC versions terminé : {versions_deleted} supprimée(s)",
        (
            "Le garbage collector de versions a terminé.\n\n"
            "Supprimées    : {versions_deleted}\n"
            "Ignorées (trop récentes) : {versions_skipped}\n"
            "Paquets vérifiés : {packages_checked}\n"
            "Politique : max_versions={max_versions}, min_age_days={min_age_days}"
        ),
    ),
    "AUDIT_EXPORT_ARCHIVE": (
        "📦 [Repod] Archive audit téléchargée par {user}",
        (
            "Une archive ZIP des journaux d'audit a été téléchargée.\n\n"
            "Téléchargée par : {user}\n"
            "Taille          : {size} octets\n"
            "Hôte            : {hostname}"
        ),
    ),
    "AUDIT_EXPORT_USER": (
        "👤 [Repod] Export RGPD utilisateur : {username}",
        (
            "Un export RGPD a été effectué pour l'utilisateur {username}.\n\n"
            "Demandé par : {user}\n"
            "Hôte        : {hostname}"
        ),
    ),
    "INTEGRITY_ALERT": (
        "⚠️ [Repod] Alerte intégrité des journaux d'audit",
        (
            "Une anomalie d'intégrité a été détectée dans les journaux d'audit.\n\n"
            "Fichier concerné : {file}\n"
            "Détail : {detail}\n"
            "Hôte   : {hostname}\n\n"
            "Vérifiez immédiatement l'intégrité des journaux via /audit/integrity."
        ),
    ),
    "SECURITY_PATCH": (
        "🔧 [Repod] Remédiation CVE — {client_label} — {package}",
        (
            "Remédiation automatique déclenchée sur {client_label} ({client_ip}).\n\n"
            "Paquet    : {package}\n"
            "CVE(s)    : {cve_ids}\n"
            "Sévérité  : {severity}\n"
            "Mode      : {mode}\n"
            "Action    : {action}\n\n"
            "Connectez-vous à repod pour suivre l'avancement du job {job_id}."
        ),
    ),
    "SCHEDULER_JOB_FAILED": (
        "🚨 [Repod] Échec de la tâche planifiée : {job_name}",
        (
            "La tâche planifiée « {job_name} » (id: {job_id}) a échoué.\n\n"
            "Date d'exécution prévue : {scheduled_run_time}\n"
            "Erreur : {error}\n"
            "Hôte   : {hostname}\n\n"
            "Consultez les logs du conteneur backend-api pour la trace complète."
        ),
    ),
}


def _enrich_context(context: dict) -> dict:
    """
    Enrichit le contexte avec des métadonnées système.

    Ajoute hostname (jamais écrasé si déjà présent) et un timestamp
    de génération. Ne lève jamais d'exception.
    """
    import socket
    enriched = dict(context)
    if "hostname" not in enriched:
        try:
            enriched["hostname"] = socket.gethostname()
        except Exception:
            enriched["hostname"] = "unknown"
    if "generated_at" not in enriched:
        enriched["generated_at"] = datetime.now(timezone.utc).isoformat()
    return enriched


def _render_event(event_type: str, context: dict) -> tuple[str, str]:
    """Retourne (subject, body_text). Fallback générique si type inconnu."""
    if event_type in _TEMPLATES:
        subject_tpl, body_tpl = _TEMPLATES[event_type]
    else:
        subject_tpl = "[Repod] Événement : {event_type}"
        body_tpl    = "Événement : {event_type}\n\nDétails : {detail}"
        context = {**context, "event_type": event_type}
    return _render(subject_tpl, context), _render(body_tpl, context)


def notify(event_type: str, context: dict[str, Any] | None = None) -> None:
    """
    Consigne un événement notifiable dans les logs applicatifs.

    Ne lève JAMAIS d'exception. Aucun canal de livraison externe n'est
    disponible en édition Community — l'audit trail persistant est assuré
    par services.audit.log(), appelé en parallèle sur chaque site d'appel.
    """
    if context is None:
        context = {}

    try:
        enriched_context = _enrich_context(context)
        subject, _body = _render_event(event_type, enriched_context)
        logger.info("[notifications] %s — %s", event_type, subject)
    except Exception as exc:
        logger.error("[notifications] Échec de rendu : %s", type(exc).__name__)


def notify_decision(
    package: str,
    version: str,
    action: str,
    decided_by: str,
    justification: str,
    expires_in_days: int | None = None,
) -> bool:
    """Notifie via le bus interne qu une decision RSSI vient d etre prise."""
    notify("security_decision", {
        "package": package,
        "version": version,
        "action": action,
        "decided_by": decided_by,
        "justification": justification,
        "expires_in_days": expires_in_days,
    })
    return True
