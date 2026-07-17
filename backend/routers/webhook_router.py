"""
routers/webhook_router.py — P3-C : Endpoints webhooks entrants

  POST /webhooks/github  → GitHub Security Advisory / Dependabot
  POST /webhooks/kev     → CISA KEV (Known Exploited Vulnerabilities)

Authentification : HMAC-SHA256 via X-Hub-Signature-256 (convention GitHub).
  Secret : variable d'environnement WEBHOOK_SECRET.
  Si WEBHOOK_SECRET est vide → vérification désactivée (mode dev uniquement).

Authentification : signature HMAC uniquement — pas de JWT utilisateur.
Les webhooks proviennent de systèmes externes (GitHub, scripts internes).
"""

from __future__ import annotations

import json
import logging
import os

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from services.webhook import (
    parse_dependabot_alert,
    parse_github_advisory,
    parse_kev_entry,
    update_kev_flag,
    verify_github_signature,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

_WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")

# SEC-02 : opt-in explicite pour désactiver la vérification de signature.
# Ne doit être utilisé qu'en CI/tests locaux.
# En production : toujours False (WEBHOOK_SECRET est obligatoire au démarrage).
_WEBHOOK_SIGNATURE_SKIP: bool = (
    os.getenv("WEBHOOK_SIGNATURE_SKIP", "false").lower() == "true"
)


def _check_signature(body: bytes, sig_header: str | None) -> None:
    """
    Lève HTTPException(401) si la signature HMAC-SHA256 est invalide.
    Lève HTTPException(503) si WEBHOOK_SECRET n'est pas configuré
    (et que le bypass explicite WEBHOOK_SIGNATURE_SKIP n'est pas activé).

    SEC-02 : Le bypass silencieux a été supprimé — sans secret configuré,
    les endpoints webhook sont désactivés plutôt qu'ouverts à tous.
    """
    if not _WEBHOOK_SECRET:
        if _WEBHOOK_SIGNATURE_SKIP:
            logger.warning(
                "[webhook] WEBHOOK_SIGNATURE_SKIP=true — vérification désactivée "
                "(mode test uniquement, ne jamais utiliser en production)"
            )
            return
        # Secret manquant et pas de bypass → endpoint indisponible
        raise HTTPException(
            status_code=503,
            detail=(
                "Webhook endpoint désactivé : WEBHOOK_SECRET n'est pas configuré. "
                "Définissez WEBHOOK_SECRET dans backend.env avant d'activer les webhooks."
            ),
        )
    if not verify_github_signature(body, sig_header or "", _WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")


# ── GitHub Security Advisory ──────────────────────────────────────────────────

@router.post("/github")
async def receive_github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
    x_github_event: str | None = Header(None),
) -> JSONResponse:
    """
    Reçoit les webhooks GitHub (security_advisory, Dependabot alerts).

    Payload attendu : https://docs.github.com/en/webhooks/webhook-events-and-payloads#security_advisory
    """
    body = await request.body()
    _check_signature(body, x_hub_signature_256)

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event = x_github_event or "unknown"
    logger.info("[webhook] GitHub event reçu : %s", event)

    if event == "security_advisory":
        parsed = parse_github_advisory(payload)
        if parsed:
            cve_id = parsed["cve_id"]
            # Propager le flag KEV si c'est une vulnérabilité connue-exploitée
            # (dans l'Advisory, l'info KEV n'est pas toujours explicite —
            # on se contente d'auditer ici, le flag KEV viendra du endpoint /kev)
            _audit("webhook_github_advisory", parsed)
            logger.info("[webhook] Advisory traitée : %s (%s)", cve_id, parsed.get("severity"))
            return JSONResponse({"status": "processed", "cve_id": cve_id})
    elif event == "dependabot_alert":
        parsed = parse_dependabot_alert(payload)
        if parsed:
            cve_id = parsed["cve_id"]
            # Même convention que security_advisory ci-dessus : auditer, pas
            # de propagation automatique — un humain consulte le journal
            # d'audit et décide (le paquet/manifeste concerné est déjà
            # dans `parsed` pour ce faire).
            _audit("webhook_dependabot_alert", parsed)
            logger.info(
                "[webhook] Dependabot alert traitée : %s (%s, paquet=%s, état=%s)",
                cve_id, parsed.get("severity"), parsed.get("package"), parsed.get("alert_state"),
            )
            return JSONResponse({"status": "processed", "cve_id": cve_id})

    return JSONResponse({"status": "ignored", "event": event})


# ── CISA KEV ──────────────────────────────────────────────────────────────────

@router.post("/kev")
async def receive_kev_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(None),
) -> JSONResponse:
    """
    Reçoit les mises à jour CISA KEV.

    Accepte un objet JSON unique ou une liste d'entrées KEV.
    Pour chaque entrée valide, propage in_kev=True sur les manifests affectés.
    """
    body = await request.body()
    _check_signature(body, x_hub_signature_256)

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Accepte un objet unique OU une liste
    entries = payload if isinstance(payload, list) else [payload]

    processed: list[str] = []
    total_manifests_updated = 0

    for entry in entries:
        parsed = parse_kev_entry(entry)
        if not parsed:
            continue

        cve_id = parsed["cve_id"]
        n = update_kev_flag(cve_id)
        total_manifests_updated += n

        _audit("webhook_kev_entry", {**parsed, "manifests_updated": n})
        logger.info("[webhook] KEV %s → %d manifest(s) mis à jour", cve_id, n)
        processed.append(cve_id)

    return JSONResponse({
        "status": "processed",
        "cve_ids": processed,
        "count": len(processed),
        "manifests_updated": total_manifests_updated,
    })


# ── Audit ─────────────────────────────────────────────────────────────────────

def _audit(action: str, details: dict) -> None:
    """Enregistre l'événement dans le journal d'audit si disponible."""
    try:
        from services.audit import log as audit_log
        # Signature correcte : log(action, user, result, detail=...)
        audit_log(
            action,
            "webhook",
            "SUCCESS",
            detail=str(details)[:500],  # tronqué pour éviter des lignes JSONL géantes
        )
    except Exception as exc:   # pragma: no cover
        logger.warning("[webhook] Impossible d'auditer %s : %s", action, exc)
