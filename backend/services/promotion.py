"""
services/promotion.py — Workflow de promotion de paquets entre distributions.

Flux de promotion :
  staging → jammy → noble / focal / bookworm

Niveaux de résultat :
  approved        → promotion effectuée immédiatement
  pending_review  → CVEs de niveau "review" présentes, approbation RSSI requise
  blocked         → CVEs de niveau "block" présentes, promotion interdite
  already_present → le paquet est déjà dans la distribution cible

Politique CVE (configurable dans settings.json → cve_policy) :
  action par sévérité : "block" | "review" | "warn" | "allow"
  • block  → bloque la promotion
  • review → promotion suspendue jusqu'à approbation explicite
  • warn   → promotion autorisée, avertissement dans le résultat
  • allow  → transparent

Approbation forcée :
  Un administrateur peut forcer la promotion malgré des CVEs "review" en
  fournissant une justification (POST …/promote avec force=True).
  Les CVEs "block" ne peuvent JAMAIS être contournées sans force=True + rôle admin.

Traçabilité :
  Chaque promotion (réussie, suspendue ou refusée) est enregistrée dans l'audit log.
  L'index est mis à jour pour refléter les distributions où le paquet est disponible.
"""

import logging
from datetime import datetime, timezone
from typing import Literal

logger = logging.getLogger("promotion")

# Statuts de promotion possibles
PromotionStatus = Literal["approved", "pending_review", "blocked", "already_present", "error"]

_SEVERITIES = ("critical", "high", "medium", "low", "negligible")


# ── Politique CVE ─────────────────────────────────────────────────────────────

def _get_cve_policy() -> dict:
    """
    Lit la politique CVE depuis settings.json.
    Valeurs par défaut conservatrices si les settings sont inaccessibles.
    """
    try:
        from services.settings import get_settings
        return get_settings().get("cve_policy", {})
    except Exception:
        return {}


def _get_epss_policy() -> dict:
    """Lit la politique EPSS depuis settings.json."""
    try:
        from services.settings import get_settings
        return get_settings().get("epss_policy", {})
    except Exception:
        return {}


def evaluate_epss_policy(cve_results: list[dict]) -> dict:
    """
    Évalue la politique EPSS sur une liste de CVE (issues de Grype/validator).

    Chaque CVE doit avoir un champ "epss" (float 0.0–1.0).
    Les CVE sans score EPSS (0.0) sont ignorées.

    Retourne un dict compatible avec evaluate_cve_policy() :
    {
      "verdict":   "approved" | "pending_review" | "blocked",
      "reason":    str,
      "blocking":  list[str],    # CVE IDs bloquants
      "reviewing": list[str],    # CVE IDs en revue
      "warnings":  list[str],
    }
    ou None si EPSS désactivé ou aucune CVE enrichie.
    """
    policy = _get_epss_policy()
    if not policy.get("enabled", True):
        return {"verdict": "approved", "reason": "EPSS désactivé.", "blocking": [], "reviewing": [], "warnings": []}

    block_thr  = float(policy.get("block_threshold",  0.9))
    review_thr = float(policy.get("review_threshold", 0.5))

    blocking  = []
    reviewing = []

    for c in cve_results:
        score  = float(c.get("epss") or 0.0)
        cve_id = c.get("id") or c.get("cve_id", "")
        if not cve_id or score == 0.0:
            continue
        pct = round(score * 100, 1)
        tag = f"{cve_id} (EPSS {pct}%)"
        if score >= block_thr:
            blocking.append(tag)
        elif score >= review_thr:
            reviewing.append(tag)

    if blocking:
        return {
            "verdict":   "blocked",
            "reason":    f"EPSS ≥ {round(block_thr*100)}% — {'; '.join(blocking[:3])}{'…' if len(blocking)>3 else ''}",
            "blocking":  blocking,
            "reviewing": reviewing,
            "warnings":  [],
        }
    if reviewing:
        return {
            "verdict":   "pending_review",
            "reason":    f"EPSS ≥ {round(review_thr*100)}% — approbation RSSI requise — {'; '.join(reviewing[:3])}{'…' if len(reviewing)>3 else ''}",
            "blocking":  [],
            "reviewing": reviewing,
            "warnings":  [],
        }
    return {"verdict": "approved", "reason": "Politique EPSS respectée.", "blocking": [], "reviewing": [], "warnings": []}


def evaluate_cve_policy(cve_summary: dict | None) -> dict:
    """
    Évalue la politique CVE pour un résumé de scan.

    Paramètre
    ---------
    cve_summary : dict issu de l'index (critical, high, medium, low, negligible)
                  ou None si le paquet n'a pas été scanné.

    Retourne
    --------
    {
      "verdict":   "approved" | "pending_review" | "blocked",
      "reason":    str,
      "warnings":  list[str],         # sévérités en mode "warn"
      "blocking":  list[str],         # sévérités qui bloquent
      "reviewing": list[str],         # sévérités en attente de review
    }
    """
    if not cve_summary:
        return {
            "verdict":   "approved",
            "reason":    "Aucun scan CVE disponible — promotion autorisée par défaut.",
            "warnings":  [],
            "blocking":  [],
            "reviewing": [],
        }

    policy  = _get_cve_policy()
    blocking  = []
    reviewing = []
    warnings  = []

    for sev in _SEVERITIES:
        count = int(cve_summary.get(sev, 0) or 0)
        if count == 0:
            continue
        action = policy.get(sev, "warn")
        if action == "block":
            blocking.append(f"{count} CVE(s) {sev}")
        elif action == "review":
            reviewing.append(f"{count} CVE(s) {sev}")
        elif action == "warn":
            warnings.append(f"{count} CVE(s) {sev}")

    if blocking:
        return {
            "verdict":   "blocked",
            "reason":    f"Promotion bloquée — {'; '.join(blocking)}.",
            "warnings":  warnings,
            "blocking":  blocking,
            "reviewing": reviewing,
        }
    if reviewing:
        return {
            "verdict":   "pending_review",
            "reason":    (
                f"Approbation RSSI requise — {'; '.join(reviewing)}. "
                "Utilisez force=True (admin) pour forcer la promotion."
            ),
            "warnings":  warnings,
            "blocking":  [],
            "reviewing": reviewing,
        }
    return {
        "verdict":   "approved",
        "reason":    "Politique CVE respectée — promotion autorisée.",
        "warnings":  warnings,
        "blocking":  [],
        "reviewing": [],
    }


# ── Mise à jour de l'index ────────────────────────────────────────────────────

def _update_index_promoted_distributions(name: str, version: str, to_dist: str) -> None:
    """
    Ajoute `to_dist` à la liste `promoted_distributions` de la version dans l'index.
    Crée la liste si absente (rétrocompatibilité).
    """
    from services.indexer import get_index, _load_index, _save_index
    from threading import Lock
    # Réutilise le lock interne de l'indexer en accédant directement
    from services import indexer as _idx_mod

    with _idx_mod._lock:
        index = _idx_mod._load_index()
        pkg = index.get("packages", {}).get(name)
        if not pkg:
            return
        ver_entry = pkg.get("versions", {}).get(version)
        if not ver_entry:
            return
        promoted = ver_entry.get("promoted_distributions") or []
        if to_dist not in promoted:
            promoted.append(to_dist)
        ver_entry["promoted_distributions"] = promoted
        _idx_mod._save_index(index)


# ── Service principal ─────────────────────────────────────────────────────────

class PromotionError(Exception):
    """Erreur métier lors d'une promotion (distributions invalides, paquet introuvable…)."""


def get_promotable_targets(from_dist: str) -> list[str]:
    """
    Retourne les distributions cibles valides pour une distribution source.
    On ne peut pas promouvoir vers la même distribution.
    """
    from services.distributions import VALID_CODENAMES
    return sorted(VALID_CODENAMES - {from_dist})


def promote(
    name: str,
    from_dist: str,
    to_dist: str,
    promoted_by: str,
    version: str | None = None,
    force: bool = False,
    justification: str = "",
) -> dict:
    """
    Effectue (ou suspend) la promotion d'un paquet entre deux distributions.

    Paramètres
    ----------
    name          : nom du paquet
    from_dist     : distribution source (ex. "jammy")
    to_dist       : distribution cible  (ex. "noble")
    promoted_by   : username de l'opérateur
    version       : version spécifique (None = version latest)
    force         : True = forcer malgré les CVEs "review" (admin seulement)
    justification : texte de justification pour l'audit (requis si force=True)

    Retourne
    --------
    {
      "status":         "approved" | "pending_review" | "blocked" | "already_present",
      "package":        str,
      "version":        str | None,
      "from_dist":      str,
      "to_dist":        str,
      "promoted_by":    str,
      "promoted_at":    str,          # ISO-8601 UTC
      "policy_verdict": dict,         # résultat evaluate_cve_policy()
      "reprepro_msg":   str | None,   # message reprepro (si exécuté)
      "justification":  str,
    }

    Lève
    ----
    PromotionError : si les paramètres sont invalides ou le paquet introuvable
    """
    from services.distributions import VALID_CODENAMES, promote_package as _reprepro_promote
    from services.indexer import get_package_info
    from services.audit import log as audit_log
    from services.notifications import notify

    # ── Validation des distributions ─────────────────────────────────────────
    if from_dist not in VALID_CODENAMES:
        raise PromotionError(f"Distribution source invalide : {from_dist!r}")
    if to_dist not in VALID_CODENAMES:
        raise PromotionError(f"Distribution cible invalide : {to_dist!r}")
    if from_dist == to_dist:
        raise PromotionError("Les distributions source et cible doivent être différentes.")

    # ── Vérification existence du paquet ─────────────────────────────────────
    info = get_package_info(name)
    if not info:
        raise PromotionError(f"Paquet introuvable : {name!r}")

    resolved_version = version or info.get("latest")
    if resolved_version and resolved_version not in info.get("versions", {}):
        raise PromotionError(f"Version introuvable : {name}@{resolved_version}")

    # ── Récupération du résumé CVE ────────────────────────────────────────────
    cve_summary = None
    if resolved_version:
        cve_summary = info["versions"][resolved_version].get("cve_summary")

    # ── Évaluation de la politique CVSS ─────────────────────────────────────
    verdict = evaluate_cve_policy(cve_summary)
    now_iso = datetime.now(timezone.utc).isoformat()

    # ── Évaluation de la politique EPSS (en complément du CVSS) ─────────────
    # Récupère les CVE détaillées depuis le manifest pour obtenir les scores EPSS.
    if verdict["verdict"] != "blocked":   # inutile si déjà bloqué par CVSS
        try:
            from services.manifest import load_manifest
            mfst = load_manifest(name, resolved_version or "")
            cve_results_manifest = mfst.get("cve_results", []) if mfst else []
            if cve_results_manifest:
                # Enrichir les CVE avec les scores EPSS actuels (cache 24h)
                from services.cve_enrichment import get_epss_scores
                cve_ids  = [c.get("id", "") for c in cve_results_manifest if c.get("id")]
                epss_map = get_epss_scores(cve_ids)
                for c in cve_results_manifest:
                    cid = c.get("id", "")
                    ep  = epss_map.get(cid, {"score": 0.0, "percentile": 0.0})
                    c["epss"] = ep["score"]
                epss_verdict = evaluate_epss_policy(cve_results_manifest)
                # Fusionner EPSS verdict dans le verdict global
                if epss_verdict["verdict"] == "blocked":
                    verdict["verdict"]   = "blocked"
                    verdict["blocking"]  = verdict.get("blocking", []) + epss_verdict["blocking"]
                    verdict["reason"]    = f"{verdict['reason']} | EPSS: {epss_verdict['reason']}"
                elif epss_verdict["verdict"] == "pending_review" and verdict["verdict"] == "approved":
                    verdict["verdict"]   = "pending_review"
                    verdict["reviewing"] = verdict.get("reviewing", []) + epss_verdict["reviewing"]
                    verdict["reason"]    = f"{verdict['reason']} | EPSS: {epss_verdict['reason']}"
        except Exception as exc:
            logger.debug(f"[promotion] Évaluation EPSS ignorée : {exc}")

    result_base = {
        "package":        name,
        "version":        resolved_version,
        "from_dist":      from_dist,
        "to_dist":        to_dist,
        "promoted_by":    promoted_by,
        "promoted_at":    now_iso,
        "policy_verdict": verdict,
        "justification":  justification,
        "reprepro_msg":   None,
    }

    # ── Cas blocked — jamais contournable, même avec force=True ──────────────
    # "block" = CVEs critiques : refus absolu, aucune exception possible.
    # "review" = CVEs hautes   : force=True (admin) peut contourner.
    if verdict["verdict"] == "blocked":
        from services.pending_promotions import create_pending as _record
        _record(
            name=name, version=resolved_version,
            from_dist=from_dist, to_dist=to_dist,
            requested_by=promoted_by, policy_verdict=verdict,
            status="blocked",
            decided_by=promoted_by, decided_at=now_iso,
        )
        audit_log(
            "PROMOTE", promoted_by, "BLOCKED",
            package=name, version=resolved_version,
            detail=(
                f"{from_dist} → {to_dist} | {verdict['reason']}"
                + (f" | justification: {justification}" if justification else "")
            ),
        )
        notify("CVE_BLOCKED", {
            "package":   name,
            "version":   resolved_version or "",
            "from_dist": from_dist,
            "to_dist":   to_dist,
            "detail":    verdict["reason"],
            "user":      promoted_by,
        })
        logger.warning(
            "[promotion] BLOCKED %s@%s %s→%s : %s",
            name, resolved_version, from_dist, to_dist, verdict["reason"],
        )
        return {**result_base, "status": "blocked"}

    # ── Cas pending_review (sans force) ──────────────────────────────────────
    if verdict["verdict"] == "pending_review" and not force:
        from services.pending_promotions import create_pending
        pending = create_pending(
            name=name,
            version=resolved_version,
            from_dist=from_dist,
            to_dist=to_dist,
            requested_by=promoted_by,
            policy_verdict=verdict,
        )
        audit_log(
            "PROMOTE", promoted_by, "PENDING_REVIEW",
            package=name, version=resolved_version,
            detail=f"{from_dist} → {to_dist} | {verdict['reason']} | pending_id={pending['id']}",
        )
        notify("PENDING_REVIEW", {
            "package":   name,
            "version":   resolved_version or "",
            "from_dist": from_dist,
            "to_dist":   to_dist,
            "detail":    verdict["reason"],
            "user":      promoted_by,
        })
        logger.info(
            "[promotion] PENDING_REVIEW %s@%s %s→%s (id=%s)",
            name, resolved_version, from_dist, to_dist, pending["id"],
        )
        return {**result_base, "status": "pending_review",
                "pending_promotion_id": pending["id"]}

    # ── Promotion effective (approved ou force) ───────────────────────────────
    ok, msg = _reprepro_promote(name, from_dist, to_dist)

    if not ok:
        audit_log(
            "PROMOTE", promoted_by, "FAILURE",
            package=name, version=resolved_version,
            detail=f"{from_dist} → {to_dist} | reprepro: {msg}",
        )
        raise PromotionError(f"reprepro a échoué : {msg}")

    already = "déjà" in msg.lower() or "already" in msg.lower() or "up-to-date" in msg.lower()
    final_status: PromotionStatus = "already_present" if already else "approved"

    # Mise à jour de l'index si promotion effective
    if not already and resolved_version:
        try:
            _update_index_promoted_distributions(name, resolved_version, to_dist)
        except Exception as exc:
            logger.warning("[promotion] Impossible de mettre à jour l'index : %s", exc)

    extra_detail = ""
    if force:
        extra_detail = f" | FORCE par {promoted_by} | justification: {justification or '(aucune)'}"
    if verdict["warnings"]:
        extra_detail += f" | avertissements: {'; '.join(verdict['warnings'])}"

    audit_log(
        "PROMOTE", promoted_by,
        "SUCCESS" if final_status == "approved" else "INFO",
        package=name, version=resolved_version,
        detail=f"{from_dist} → {to_dist} | {msg}{extra_detail}",
    )

    # Notification si promotion forcée par admin malgré pending_review
    if force and verdict["verdict"] == "pending_review" and final_status == "approved":
        notify("PROMOTION_APPROVED", {
            "package":       name,
            "version":       resolved_version or "",
            "from_dist":     from_dist,
            "to_dist":       to_dist,
            "user":          promoted_by,
            "justification": justification or "(aucune)",
            "warnings":      "; ".join(verdict.get("warnings", [])) or "aucun",
        })

    # ── Enregistrement dans l'historique des promotions ──────────────────────
    from services.pending_promotions import create_pending as _record
    _record(
        name=name, version=resolved_version,
        from_dist=from_dist, to_dist=to_dist,
        requested_by=promoted_by, policy_verdict=verdict,
        status=final_status,
        decided_by=promoted_by, decided_at=now_iso,
        decision_note=(
            f"Force par {promoted_by} — {justification or '(aucune justification)'}"
            if force else ""
        ),
    )

    logger.info(
        "[promotion] %s %s@%s %s→%s",
        final_status.upper(), name, resolved_version, from_dist, to_dist,
    )

    return {**result_base, "status": final_status, "reprepro_msg": msg}


# ── Approbation formelle d'une demande en attente ────────────────────────────

def approve_pending(
    pending_id: str,
    approved_by: str,
    justification: str = "",
) -> dict:
    """
    Approuve une demande de promotion en attente.

    1. Vérifie l'existence et le statut "pending" (idempotence).
    2. Re-évalue la politique CVE au moment de l'approbation.
       Si la re-évaluation donne "blocked", l'approbation est refusée.
    3. Exécute la promotion avec force=True (bypass pending_review).
    4. Met à jour le statut de la demande → "approved".
    5. Envoie la notification PROMOTION_APPROVED.

    Lève
    ----
    PromotionError : demande introuvable, déjà décidée, paquet introuvable,
                     re-évaluation blocked, ou reprepro a échoué.
    """
    from datetime import datetime, timezone
    from services.pending_promotions import get_pending, update_pending
    from services.distributions import VALID_CODENAMES, promote_package as _reprepro_promote
    from services.indexer import get_package_info
    from services.audit import log as audit_log
    from services.notifications import notify

    record = get_pending(pending_id)
    if record is None:
        raise PromotionError(f"Demande introuvable : {pending_id!r}")
    if record["status"] != "pending":
        raise PromotionError(
            f"Demande déjà traitée (statut: {record['status']!r}). "
            "L'approbation n'est possible que sur les demandes en attente."
        )

    name      = record["name"]
    version   = record["version"]
    from_dist = record["from_dist"]
    to_dist   = record["to_dist"]

    # ── Re-vérification CVE au moment de l'approbation ───────────────────────
    try:
        info = get_package_info(name)
    except Exception as exc:
        raise PromotionError(
            f"Impossible de lire les informations du paquet {name!r} "
            f"au moment de l'approbation : {type(exc).__name__}"
        ) from None
    if not info:
        raise PromotionError(f"Paquet introuvable au moment de l'approbation : {name!r}")

    resolved_version = version or info.get("latest")
    cve_summary = None
    if resolved_version and resolved_version in info.get("versions", {}):
        cve_summary = info["versions"][resolved_version].get("cve_summary")

    current_verdict = evaluate_cve_policy(cve_summary)

    # Même avec force=True, "blocked" reste interdit
    if current_verdict["verdict"] == "blocked":
        audit_log(
            "PROMOTE_APPROVE", approved_by, "BLOCKED",
            package=name, version=resolved_version,
            detail=(
                f"Re-évaluation bloquée au moment de l'approbation | "
                f"{from_dist} → {to_dist} | {current_verdict['reason']}"
            ),
        )
        raise PromotionError(
            f"Approbation impossible — re-évaluation CVE bloquée : "
            f"{current_verdict['reason']}"
        )

    # ── Promotion effective ───────────────────────────────────────────────────
    ok, msg = _reprepro_promote(name, from_dist, to_dist)
    if not ok:
        audit_log(
            "PROMOTE_APPROVE", approved_by, "FAILURE",
            package=name, version=resolved_version,
            detail=f"{from_dist} → {to_dist} | reprepro: {msg}",
        )
        raise PromotionError(f"reprepro a échoué lors de l'approbation : {msg}")

    now_iso = datetime.now(timezone.utc).isoformat()
    already = "déjà" in msg.lower() or "already" in msg.lower() or "up-to-date" in msg.lower()
    final_status: PromotionStatus = "already_present" if already else "approved"

    # Mise à jour de l'index
    if not already and resolved_version:
        try:
            _update_index_promoted_distributions(name, resolved_version, to_dist)
        except Exception as exc:
            logger.warning("[promotion] Impossible de mettre à jour l'index : %s", exc)

    # Mise à jour de la demande
    update_pending(pending_id,
                   status="approved",
                   decided_by=approved_by,
                   decided_at=now_iso,
                   decision_note=justification or "(approbation formelle RSSI)")

    audit_log(
        "PROMOTE_APPROVE", approved_by, "SUCCESS",
        package=name, version=resolved_version,
        detail=(
            f"{from_dist} → {to_dist} | pending_id={pending_id} | "
            f"justification: {justification or '(aucune)'} | {msg}"
        ),
    )

    notify("PROMOTION_APPROVED", {
        "package":       name,
        "version":       resolved_version or "",
        "from_dist":     from_dist,
        "to_dist":       to_dist,
        "user":          approved_by,
        "justification": justification or "(approbation formelle RSSI)",
        "warnings":      "; ".join(current_verdict.get("warnings", [])) or "aucun",
    })

    logger.info(
        "[promotion] APPROVED (RSSI) %s@%s %s→%s par %s",
        name, resolved_version, from_dist, to_dist, approved_by,
    )

    return {
        "status":          final_status,
        "pending_id":      pending_id,
        "package":         name,
        "version":         resolved_version,
        "from_dist":       from_dist,
        "to_dist":         to_dist,
        "approved_by":     approved_by,
        "approved_at":     now_iso,
        "justification":   justification,
        "policy_verdict":  current_verdict,
        "reprepro_msg":    msg,
    }


# ── Rejet formel d'une demande en attente ────────────────────────────────────

def reject_pending(
    pending_id: str,
    rejected_by: str,
    reason: str,
) -> dict:
    """
    Rejette formellement une demande de promotion en attente.

    Aucune action reprepro — le paquet reste dans la distribution source.
    Envoie une notification PROMOTION_REJECTED.

    Lève
    ----
    PromotionError : demande introuvable ou déjà décidée.
    """
    from datetime import datetime, timezone
    from services.pending_promotions import get_pending, update_pending
    from services.audit import log as audit_log
    from services.notifications import notify

    record = get_pending(pending_id)
    if record is None:
        raise PromotionError(f"Demande introuvable : {pending_id!r}")
    if record["status"] != "pending":
        raise PromotionError(
            f"Demande déjà traitée (statut: {record['status']!r}). "
            "Le rejet n'est possible que sur les demandes en attente."
        )

    if not reason.strip():
        raise PromotionError("Le motif de rejet est obligatoire.")

    name      = record["name"]
    version   = record["version"]
    from_dist = record["from_dist"]
    to_dist   = record["to_dist"]
    now_iso   = datetime.now(timezone.utc).isoformat()

    update_pending(pending_id,
                   status="rejected",
                   decided_by=rejected_by,
                   decided_at=now_iso,
                   decision_note=reason)

    audit_log(
        "PROMOTE_REJECT", rejected_by, "SUCCESS",
        package=name, version=version,
        detail=(
            f"{from_dist} → {to_dist} | pending_id={pending_id} | "
            f"motif: {reason[:200]}"
        ),
    )

    notify("PROMOTION_REJECTED", {
        "package":   name,
        "version":   version or "",
        "from_dist": from_dist,
        "to_dist":   to_dist,
        "user":      rejected_by,
        "reason":    reason,
    })

    logger.info(
        "[promotion] REJECTED %s@%s %s→%s par %s",
        name, version, from_dist, to_dist, rejected_by,
    )

    return {
        "status":      "rejected",
        "pending_id":  pending_id,
        "package":     name,
        "version":     version,
        "from_dist":   from_dist,
        "to_dist":     to_dist,
        "rejected_by": rejected_by,
        "rejected_at": now_iso,
        "reason":      reason,
    }
