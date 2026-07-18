"""
services/email_templates.py — Moteur de templates email Jinja2.

Templates stockés dans /repos/templates/email/ (volume persistant).
Au premier appel, les templates par défaut sont copiés depuis DEFAULTS
si le fichier n'existe pas déjà sur le volume.

Usage :
    from services.email_templates import render_email_template, list_templates
    html = render_email_template("pending_review", context)
    templates = list_templates()
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import BaseLoader, Environment, TemplateNotFound

logger = logging.getLogger("email_templates")

TEMPLATES_DIR = Path(os.getenv("EMAIL_TEMPLATES_DIR", "/repos/templates/email"))

_BASE_STYLE = """
<style>
  body { margin:0; padding:0; background:#f1f5f9; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; }
  .wrapper { max-width:600px; margin:24px auto; background:#fff; border-radius:12px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,0.08); }
  .header { background:#1e293b; color:#fff; padding:20px 24px; }
  .header h1 { margin:0; font-size:16px; font-weight:700; }
  .header .ts { margin:4px 0 0; font-size:12px; color:#94a3b8; }
  .body { padding:24px; font-size:14px; color:#334155; line-height:1.6; }
  .label { font-size:11px; text-transform:uppercase; letter-spacing:0.5px; color:#64748b; font-weight:700; margin-bottom:4px; }
  .value { font-size:14px; color:#0f172a; font-weight:600; margin-bottom:14px; }
  .mono { font-family:'JetBrains Mono',monospace; }
  .table { width:100%; border-collapse:collapse; margin:12px 0; font-size:13px; }
  .table th { background:#f8fafc; padding:8px 12px; text-align:left; font-size:11px; text-transform:uppercase; color:#64748b; border-bottom:2px solid #e2e8f0; }
  .table td { padding:10px 12px; border-bottom:1px solid #f1f5f9; }
  .badge { display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:700; }
  .badge-red { background:#fee2e2; color:#dc2626; }
  .badge-orange { background:#ffedd5; color:#ea580c; }
  .badge-amber { background:#fef3c7; color:#d97706; }
  .badge-green { background:#dcfce7; color:#16a34a; }
  .badge-blue { background:#dbeafe; color:#2563eb; }
  .badge-gray { background:#f1f5f9; color:#475569; }
  .alert { padding:12px 16px; border-radius:8px; font-size:13px; margin:12px 0; }
  .alert-danger { background:#fef2f2; border:1px solid #fca5a5; color:#dc2626; }
  .alert-warning { background:#fffbeb; border:1px solid #fcd34d; color:#b45309; }
  .alert-success { background:#f0fdf4; border:1px solid #86efac; color:#16a34a; }
  .alert-info { background:#eff6ff; border:1px solid #93c5fd; color:#2563eb; }
  .btn { display:inline-block; padding:10px 20px; background:#3b82f6; color:#fff; border-radius:8px; text-decoration:none; font-size:14px; font-weight:600; }
  .footer { padding:16px 24px; background:#f8fafc; border-top:1px solid #e2e8f0; font-size:12px; color:#94a3b8; }
</style>
"""

DEFAULTS: dict[str, dict] = {
    "base": {
        "subject": "",
        "description": "Layout de base (header, footer, styles). Inclus automatiquement par tous les templates.",
        "body": """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">""" + _BASE_STYLE + """</head><body>
<div class="wrapper">
  <div class="header">
    <h1>{{ title }}</h1>
    <div class="ts">{{ timestamp }} — {{ instance_name }}</div>
  </div>
  <div class="body">
    {{ content }}
  </div>
  <div class="footer">
    {% if app_url %}<a href="{{ app_url }}" style="color:#3b82f6;">Ouvrir RepoD</a> — {% endif %}
    Ce message a ete genere automatiquement par RepoD.
  </div>
</div>
</body></html>""",
    },
    "pending_review": {
        "subject": "[RepoD] Paquet en attente de revision — {{ package }} {{ version }}",
        "description": "Envoye quand un paquet necessite une decision RSSI apres import.",
        "variables": ["package", "version", "arch", "distribution", "cve_counts", "worst_severity", "kev_count"],
        "body": """{% set title = "Paquet en attente de revision RSSI" %}
{% include "base" %}
{% block content %}
<p class="label">Paquet</p>
<p class="value mono">{{ package }} {{ version }} ({{ arch }})</p>
<p class="label">Distribution</p>
<p class="value">{{ distribution }}</p>
{% if worst_severity %}
<p class="label">Severite maximale</p>
<p class="value"><span class="badge badge-{{ 'red' if worst_severity == 'Critical' else 'orange' if worst_severity == 'High' else 'amber' if worst_severity == 'Medium' else 'blue' }}">{{ worst_severity }}</span></p>
{% endif %}
{% if cve_counts %}
<table class="table">
  <tr><th>Severite</th><th>Nombre</th></tr>
  {% for sev, count in cve_counts.items() %}{% if count > 0 %}
  <tr><td>{{ sev }}</td><td><strong>{{ count }}</strong></td></tr>
  {% endif %}{% endfor %}
</table>
{% endif %}
{% if kev_count %}
<div class="alert alert-danger">{{ kev_count }} CVE activement exploitee(s) dans le catalogue KEV CISA</div>
{% endif %}
<a href="{{ app_url }}/security" class="btn">Voir dans RepoD</a>
{% endblock %}""",
    },
    "security_decision": {
        "subject": "[RepoD] Decision — {{ action_label }} — {{ package }} {{ version }}",
        "description": "Envoye quand un RSSI prend une decision sur un paquet (accepter, rejeter, exception, upgrade).",
        "variables": ["package", "version", "action", "action_label", "decided_by", "justification", "expires_in_days"],
        "body": """{% set title = "Decision de securite enregistree" %}
<p class="label">Paquet</p>
<p class="value mono">{{ package }} {{ version }}</p>
<p class="label">Decision</p>
<p class="value">{{ action_label }}</p>
<p class="label">Decide par</p>
<p class="value">{{ decided_by }}</p>
<p class="label">Justification</p>
<p class="value">{{ justification[:300] }}</p>
{% if expires_in_days %}
<p class="label">Expiration</p>
<p class="value">{{ expires_in_days }} jours</p>
{% endif %}
<a href="{{ app_url }}/security" class="btn">Voir dans RepoD</a>""",
    },
    "escalation": {
        "subject": "[RepoD] Escalade {{ urgency }} — {{ package }} {{ version }}",
        "description": "Envoye quand un technicien escalade une CVE vers le RSSI.",
        "variables": ["package", "version", "escalated_by", "assigned_to", "urgency", "message", "cve_ids", "machine_names"],
        "body": """{% set title = "Escalade de securite" %}
{% set urgency_class = 'alert-danger' if urgency == 'critique' else 'alert-warning' if urgency == 'urgent' else 'alert-info' %}
<div class="alert {{ urgency_class }}">Urgence : <strong>{{ urgency }}</strong></div>
<p class="label">Paquet</p>
<p class="value mono">{{ package }} {{ version }}</p>
<p class="label">Escalade par</p>
<p class="value">{{ escalated_by }}</p>
<p class="label">Assigne a</p>
<p class="value">{{ assigned_to }}</p>
{% if message %}
<p class="label">Message</p>
<p class="value">{{ message }}</p>
{% endif %}
{% if cve_ids %}
<p class="label">CVE concernees</p>
<p class="value mono">{{ cve_ids | join(', ') }}</p>
{% endif %}
{% if machine_names %}
<p class="label">Machines impactees</p>
<p class="value">{{ machine_names | join(', ') }}</p>
{% endif %}
<a href="{{ app_url }}/security" class="btn">Traiter l'escalade</a>""",
    },
    "sla_overdue": {
        "subject": "[RepoD] SLA depasse — {{ expired_count }} decision(s) expiree(s)",
        "description": "Envoye quotidiennement quand des decisions CVE ont depasse leur SLA.",
        "variables": ["expired_count", "expiring_soon_count", "decisions"],
        "body": """{% set title = "Alerte SLA — decisions expirees" %}
<div class="alert alert-warning">{{ expired_count }} decision(s) expiree(s), {{ expiring_soon_count }} proche(s) de l'expiration.</div>
{% if decisions %}
<table class="table">
  <tr><th>Paquet</th><th>Version</th><th>Action</th><th>Expire</th></tr>
  {% for d in decisions[:20] %}
  <tr>
    <td class="mono">{{ d.package }}</td>
    <td>{{ d.version }}</td>
    <td>{{ d.action }}</td>
    <td>{{ d.expires_at[:10] if d.expires_at else '—' }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}
<a href="{{ app_url }}/security" class="btn">Voir les decisions</a>""",
    },
    "patch_available": {
        "subject": "[RepoD] Correctif disponible — {{ package }} {{ target_version }}",
        "description": "Envoye quand la version cible d'un upgrade_required est disponible dans le depot.",
        "variables": ["package", "version", "target_version", "depot_version", "machine_count"],
        "body": """{% set title = "Correctif disponible dans le depot" %}
<div class="alert alert-success">La version <strong>{{ target_version }}</strong> est maintenant dans le depot.</div>
<p class="label">Paquet</p>
<p class="value mono">{{ package }}</p>
<p class="label">Version actuelle (vulnerable)</p>
<p class="value mono">{{ version }}</p>
<p class="label">Version corrigee</p>
<p class="value mono">{{ target_version }}</p>
{% if machine_count %}
<p class="label">Machines concernees</p>
<p class="value">{{ machine_count }} machine(s)</p>
{% endif %}
<a href="{{ app_url }}/security" class="btn">Deployer le correctif</a>""",
    },
    "scheduler_job_failed": {
        "subject": "[RepoD] Tache planifiee echouee — {{ job_name }}",
        "description": "Envoye quand un job du scheduler (sync, backup, mirror...) echoue.",
        "variables": ["job_id", "job_name", "scheduled_run_time", "error"],
        "body": """{% set title = "Echec d'une tache planifiee" %}
<div class="alert alert-danger">La tache <strong>{{ job_name }}</strong> a echoue.</div>
<p class="label">Job ID</p>
<p class="value mono">{{ job_id }}</p>
<p class="label">Execution prevue</p>
<p class="value">{{ scheduled_run_time }}</p>
<p class="label">Erreur</p>
<p class="value" style="color:#dc2626;">{{ error }}</p>""",
    },
    "default": {
        "subject": "[RepoD] {{ event_type }}",
        "description": "Template de secours utilise quand aucun template specifique n'existe pour l'evenement.",
        "variables": ["event_type"],
        "body": """{% set title = event_type %}
<p>Un evenement <strong>{{ event_type }}</strong> s'est produit sur votre instance RepoD.</p>
{% for key, val in context.items() %}
{% if val and key not in ('timestamp', 'instance_name', 'app_url', 'hostname') %}
<p class="label">{{ key }}</p>
<p class="value">{{ val }}</p>
{% endif %}
{% endfor %}""",
    },
}


def _ensure_defaults():
    """Copie les templates par défaut si le répertoire n'existe pas encore."""
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    for name, tpl in DEFAULTS.items():
        path = TEMPLATES_DIR / f"{name}.html"
        if not path.exists():
            path.write_text(tpl["body"], encoding="utf-8")
        meta_path = TEMPLATES_DIR / f"{name}.json"
        if not meta_path.exists():
            import json
            meta = {"subject": tpl.get("subject", ""), "description": tpl.get("description", ""),
                    "variables": tpl.get("variables", [])}
            meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


def _get_env() -> Environment:
    _ensure_defaults()

    class _FileLoader(BaseLoader):
        def get_source(self, environment, template):
            path = TEMPLATES_DIR / f"{template}.html"
            if not path.exists():
                raise TemplateNotFound(template)
            source = path.read_text(encoding="utf-8")
            return source, str(path), lambda: path.stat().st_mtime == os.path.getmtime(path)

    return Environment(loader=_FileLoader(), autoescape=True)


def _common_context(context: dict) -> dict:
    from services.settings import get_settings
    settings = get_settings()
    now = datetime.now(timezone.utc)
    return {
        "timestamp": now.strftime("%d/%m/%Y %H:%M UTC"),
        "timestamp_iso": now.isoformat(),
        "instance_name": settings.get("app_name", "RepoD"),
        "app_url": (settings.get("app_url") or "").rstrip("/"),
        "context": context,
        **context,
    }


ACTION_LABELS = {
    "accept_risk": "Risque accepte",
    "exception": "Exception accordee",
    "reject": "Rejete / Quarantaine",
    "upgrade_required": "Upgrade requis",
}


def render_email_template(template_name: str, context: dict) -> tuple[str, str]:
    """
    Rend un template email. Retourne (subject, html_body).
    Si le template n'existe pas, utilise 'default'.
    """
    env = _get_env()
    ctx = _common_context(context)
    ctx["action_label"] = ACTION_LABELS.get(ctx.get("action", ""), ctx.get("action", ""))

    try:
        tpl = env.get_template(template_name)
    except TemplateNotFound:
        tpl = env.get_template("default")
        ctx["event_type"] = template_name

    body_content = tpl.render(**ctx)

    try:
        base = env.get_template("base")
        ctx["content"] = body_content
        ctx["title"] = ctx.get("title", template_name.replace("_", " ").title())
        html = base.render(**ctx)
    except TemplateNotFound:
        html = body_content

    import json
    meta_path = TEMPLATES_DIR / f"{template_name}.json"
    subject_tpl = "[RepoD] {{ event_type }}"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            subject_tpl = meta.get("subject", subject_tpl)
        except Exception:
            pass
    elif template_name in DEFAULTS:
        subject_tpl = DEFAULTS[template_name].get("subject", subject_tpl)

    # autoescape=False is correct here: this renders a plain-text email Subject
    # header, not HTML — HTML-escaping would corrupt legitimate characters
    # (&, <, >, quotes) in the rendered subject.
    subject_env = Environment(autoescape=False)  # nosec B701
    subject = subject_env.from_string(subject_tpl).render(**ctx)
    # Strip CR/LF to prevent email header injection via a crafted context value.
    subject = subject.replace("\r", " ").replace("\n", " ")

    return subject, html


def list_templates() -> list[dict]:
    """Liste tous les templates disponibles avec leur metadata."""
    _ensure_defaults()
    import json
    result = []
    for path in sorted(TEMPLATES_DIR.glob("*.html")):
        name = path.stem
        meta_path = TEMPLATES_DIR / f"{name}.json"
        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        is_default = (path.read_text(encoding="utf-8") == DEFAULTS.get(name, {}).get("body", ""))
        result.append({
            "name": name,
            "subject": meta.get("subject", ""),
            "description": meta.get("description", ""),
            "variables": meta.get("variables", []),
            "is_customized": not is_default,
        })
    return result


def get_template(name: str) -> dict:
    """Retourne le contenu + metadata d'un template."""
    import json
    _ensure_defaults()
    path = TEMPLATES_DIR / f"{name}.html"
    if not path.exists():
        return None
    meta_path = TEMPLATES_DIR / f"{name}.json"
    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "name": name,
        "subject": meta.get("subject", ""),
        "description": meta.get("description", ""),
        "variables": meta.get("variables", []),
        "body": path.read_text(encoding="utf-8"),
    }


def save_template(name: str, body: str, subject: str | None = None) -> dict:
    """Sauvegarde un template customisé."""
    import json
    _ensure_defaults()
    path = TEMPLATES_DIR / f"{name}.html"
    path.write_text(body, encoding="utf-8")
    if subject is not None:
        meta_path = TEMPLATES_DIR / f"{name}.json"
        meta = {}
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        meta["subject"] = subject
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return get_template(name)


def reset_template(name: str) -> dict:
    """Restaure un template à sa valeur par défaut."""
    if name not in DEFAULTS:
        return None
    path = TEMPLATES_DIR / f"{name}.html"
    path.write_text(DEFAULTS[name]["body"], encoding="utf-8")
    return get_template(name)


def preview_template(name: str, body: str | None = None) -> str:
    """Rend un template avec des données fictives pour preview."""
    sample = {
        "package": "openssl",
        "version": "3.0.14-1",
        "arch": "amd64",
        "distribution": "bookworm",
        "action": "accept_risk",
        "decided_by": "admin",
        "justification": "Risque acceptable apres analyse — pas de vecteur d'attaque dans notre contexte.",
        "expires_in_days": 30,
        "worst_severity": "High",
        "cve_counts": {"Critical": 1, "High": 3, "Medium": 2, "Low": 0},
        "kev_count": 1,
        "escalated_by": "technicien1",
        "assigned_to": "rssi",
        "urgency": "urgent",
        "message": "Plusieurs serveurs de production sont impactes.",
        "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"],
        "machine_names": ["web-01", "db-02", "app-03"],
        "expired_count": 3,
        "expiring_soon_count": 5,
        "decisions": [
            {"package": "curl", "version": "7.88.1", "action": "accept_risk", "expires_at": "2026-07-01T00:00:00"},
            {"package": "openssl", "version": "3.0.14", "action": "exception", "expires_at": "2026-06-28T00:00:00"},
        ],
        "job_id": "security_sync_daily",
        "job_name": "Sync securite APT",
        "scheduled_run_time": "2026-06-23T03:00:00",
        "target_version": "3.0.15-1",
        "depot_version": "3.0.15-1",
        "machine_count": 12,
        "event_type": name.upper(),
    }

    if body:
        env = Environment(autoescape=True)
        tpl = env.from_string(body)
        content = tpl.render(**_common_context(sample))
        try:
            base_env = _get_env()
            base = base_env.get_template("base")
            ctx = _common_context(sample)
            ctx["content"] = content
            ctx["title"] = name.replace("_", " ").title()
            return base.render(**ctx)
        except TemplateNotFound:
            return content

    _, html = render_email_template(name, sample)
    return html
