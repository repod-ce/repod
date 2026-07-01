"""
Moteur d'auto-assignation des décisions CVE.

Lit les règles dans settings.json["cve_assignment_rules"] :
[
  {"severity": "CRITICAL", "assign_to": "rssi-team", "type": "group"},
  {"severity": "HIGH",     "assign_to": "sec-lead",  "type": "user"},
  {"severity": "MEDIUM",   "assign_to": "ops-team",  "type": "group"}
]

La sévérité la plus haute présente dans les CVEs du paquet détermine l'assignation.
"""

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]


def _max_severity(severities: list[str]) -> str:
    """Retourne la sévérité la plus haute parmi la liste."""
    for sev in _SEVERITY_ORDER:
        if sev in [s.upper() for s in severities]:
            return sev
    return "UNKNOWN"


def auto_assign(cve_severities: list[str], rules: list[dict]) -> tuple[str | None, str | None]:
    """
    Détermine l'assignation automatique selon les règles configurées.

    Args:
        cve_severities: liste des sévérités CVE du paquet (ex: ["HIGH", "MEDIUM"])
        rules: liste de règles depuis settings["cve_assignment_rules"]

    Returns:
        (assigned_to, assigned_to_type) — ex: ("rssi-team", "group") ou (None, None)
    """
    if not rules or not cve_severities:
        return None, None

    max_sev = _max_severity(cve_severities)

    for rule in rules:
        if rule.get("severity", "").upper() == max_sev:
            return rule.get("assign_to"), rule.get("type")

    return None, None


def notify_assignment(
    package: str,
    version: str,
    assigned_to: str,
    assigned_to_type: str,
    cve_ids: list[str],
) -> None:
    """Envoie une notification email à l'assigné (user ou membres du groupe)."""
    try:
        from services.groups import get_group_members
        from services.email_notifications import _send_email
        from auth.users import get_user

        if assigned_to_type == "group":
            members = get_group_members(assigned_to)
            recipients = [m["email"] for m in members if m.get("email")]
        else:
            user = get_user(assigned_to)
            recipients = [user["email"]] if user and user.get("email") else []

        if not recipients:
            return

        cve_list = ", ".join(cve_ids[:5]) + ("…" if len(cve_ids) > 5 else "")
        subject = f"[repod] Décision CVE requise — {package} {version}"
        body = (
            f"Une décision de sécurité vous a été assignée.\n\n"
            f"Paquet : {package} {version}\n"
            f"CVEs   : {cve_list}\n\n"
            f"Connectez-vous à repod pour prendre une décision."
        )
        for email in recipients:
            _send_email(to=email, subject=subject, body=body)
    except Exception:
        pass
