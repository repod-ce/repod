"""
Enrichissement des CVE avec des sources de threat intelligence :

  EPSS (Exploit Prediction Scoring System) — FIRST.org
    → Score 0-100% : probabilité qu'une CVE soit exploitée dans les 30 jours
    → API : https://api.first.org/data/1.0/epss

  KEV (Known Exploited Vulnerabilities) — CISA
    → Liste des CVE activement exploitées en ce moment
    → Feed : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Cache disque (TTL 24h) dans /repos/security/ pour fonctionner en air-gap après
la première récupération.
"""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger("cve_enrichment")

SECURITY_CACHE_DIR = Path(os.getenv("SECURITY_CACHE_DIR", "/repos/security"))
SECURITY_CACHE_DIR.mkdir(parents=True, exist_ok=True)

KEV_CACHE_PATH  = SECURITY_CACHE_DIR / "kev_cache.json"
EPSS_CACHE_PATH = SECURITY_CACHE_DIR / "epss_cache.json"

KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

CACHE_TTL_HOURS = 24
REQUEST_TIMEOUT = 10


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _cache_fresh(path: Path, ttl_hours: int = CACHE_TTL_HOURS) -> bool:
    if not path.exists():
        return False
    age = datetime.now(timezone.utc) - datetime.fromtimestamp(
        path.stat().st_mtime, tz=timezone.utc
    )
    return age < timedelta(hours=ttl_hours)


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout)),
)
def _get_with_retry(url: str, **kwargs) -> requests.Response:
    """GET avec retry/backoff exponentiel sur erreurs réseau transitoires (3 tentatives)."""
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    return requests.get(url, **kwargs)


def _save_json(path: Path, data: dict) -> None:
    """Écriture atomique via tempfile + os.replace — résistant aux permissions root sur le fichier."""
    import tempfile, os
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ─── KEV CISA ────────────────────────────────────────────────────────────────

def refresh_kev() -> bool:
    """Force le rechargement du KEV CISA. Retourne True si succès."""
    try:
        resp = _get_with_retry(KEV_URL)
        resp.raise_for_status()
        data = resp.json()
        cve_ids = [
            v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")
        ]
        _save_json(KEV_CACHE_PATH, {
            "cve_ids": cve_ids,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "total": len(cve_ids),
            "catalog_version": data.get("catalogVersion", ""),
        })
        logger.info(f"[KEV] Mis à jour — {len(cve_ids)} vulnérabilités actives exploitées")
        return True
    except Exception as e:
        logger.warning(f"[KEV] Impossible de mettre à jour : {e}")
        return False


def get_kev_set() -> set[str]:
    """
    Retourne l'ensemble des CVE IDs du CISA KEV.
    Utilise le cache si frais, sinon tente une mise à jour (graceful fallback).
    """
    if not _cache_fresh(KEV_CACHE_PATH):
        refresh_kev()

    cached = _load_json(KEV_CACHE_PATH)
    return set(cached.get("cve_ids", []))


def get_kev_meta() -> dict:
    """Retourne les métadonnées du cache KEV (date, total)."""
    cached = _load_json(KEV_CACHE_PATH)
    return {
        "total": cached.get("total", 0),
        "fetched_at": cached.get("fetched_at"),
        "catalog_version": cached.get("catalog_version", ""),
        "cache_fresh": _cache_fresh(KEV_CACHE_PATH),
    }


# ─── EPSS FIRST.org ──────────────────────────────────────────────────────────

def _load_epss_cache() -> dict[str, dict]:
    """Cache format : {cve_id: {"score": float, "percentile": float}}"""
    cached = _load_json(EPSS_CACHE_PATH)
    raw = cached.get("scores", {})
    # Rétro-compat : ancien format {cve_id: float}
    result = {}
    for cve_id, val in raw.items():
        if isinstance(val, dict):
            result[cve_id] = val
        else:
            result[cve_id] = {"score": float(val), "percentile": 0.0}
    return result


def _save_epss_cache(scores: dict[str, dict]) -> None:
    _save_json(EPSS_CACHE_PATH, {
        "scores": scores,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Retourne les données EPSS pour une liste de CVE IDs.

    Retourne : {cve_id: {"score": float, "percentile": float}}
      - score      : probabilité d'exploitation à 30 jours (0.0 – 1.0)
      - percentile : rang parmi toutes les CVE connues (0.0 – 1.0)
                     ex: 0.95 → dans le top 5 % des CVE les plus exploitées
    """
    if not cve_ids:
        return {}

    scores = _load_epss_cache() if _cache_fresh(EPSS_CACHE_PATH) else {}
    missing = [c for c in cve_ids if c not in scores]

    if missing:
        try:
            # Batch par 100 (limite API FIRST.org)
            for i in range(0, len(missing), 100):
                batch = missing[i : i + 100]
                resp = _get_with_retry(
                    EPSS_URL,
                    params={"cve": ",".join(batch), "limit": len(batch)},
                )
                resp.raise_for_status()
                for item in resp.json().get("data", []):
                    cve_id = item.get("cve", "")
                    if cve_id:
                        scores[cve_id] = {
                            "score":      round(float(item.get("epss", 0)), 6),
                            "percentile": round(float(item.get("percentile", 0)), 6),
                        }
            _save_epss_cache(scores)
            logger.info(f"[EPSS] {len(missing)} nouveaux scores récupérés")
        except Exception as e:
            logger.warning(f"[EPSS] Impossible de récupérer les scores : {e}")

    return {
        cve: scores.get(cve, {"score": 0.0, "percentile": 0.0})
        for cve in cve_ids
    }


# ─── Score TruRisk (inspiré Qualys) ──────────────────────────────────────────

_SEVERITY_CVSS_FALLBACK = {
    "Critical":   9.5,
    "High":       7.5,
    "Medium":     5.0,
    "Low":        2.5,
    "Negligible": 1.0,
    "Unknown":    4.0,
}


def compute_trurisk(
    cvss: float | None,
    epss: float,
    in_kev: bool,
    severity: str | None = None,
) -> float:
    """
    Score TruRisk composite sur 100 points, inspiré de Qualys TruRisk™.

    Pondération :
      CVSS  (0–10)  → 50 % du score  (base de sévérité)
      EPSS  (0–1)   → 30 % du score  (probabilité d'exploitation à 30 j)
      KEV           → +20 pts bonus  (exploitée activement — CISA)

    Si CVSS est absent, on utilise un score estimé depuis la sévérité Grype.

    Exemples :
      Log4Shell  CVSS 10.0 + EPSS 94 % + KEV  → 50 + 28.2 + 20 = 98.2
      CVE moyen  CVSS  7.5 + EPSS  5 % + pas KEV → 37.5 + 1.5 + 0 = 39.0
      CVE faible CVSS  4.0 + EPSS  0.1 % + pas KEV → 20 + 0.03 + 0 = 20.0
    """
    if cvss is None or cvss == 0:
        cvss = _SEVERITY_CVSS_FALLBACK.get(severity or "Unknown", 4.0)
    cvss_score = (float(cvss) / 10.0) * 50.0   # 0 – 50
    epss_score = float(epss or 0) * 30.0        # 0 – 30
    kev_bonus  = 20.0 if in_kev else 0.0        # 0 or 20
    return round(min(cvss_score + epss_score + kev_bonus, 100.0), 1)


def trurisk_label(score: float) -> str:
    """Étiquette qualitative associée au score TruRisk."""
    if score >= 75:
        return "Critique"
    if score >= 50:
        return "Élevé"
    if score >= 25:
        return "Modéré"
    return "Faible"


# ─── Enrichissement d'une liste de CVE ───────────────────────────────────────

def enrich_cve_list(cve_list: list[dict]) -> list[dict]:
    """
    Enrichit chaque CVE de la liste avec :
      - epss          : score brut (float 0.0–1.0)
      - epss_percent  : score en % (ex: 2.34)
      - epss_label    : "Critique" | "Élevé" | "Modéré" | "Faible"
      - in_kev        : bool — activement exploitée (CISA KEV)

    Modifie la liste en place et la retourne.
    """
    if not cve_list:
        return cve_list

    cve_ids = [c["id"] for c in cve_list if c.get("id")]

    try:
        kev_set    = get_kev_set()
        epss_map   = get_epss_scores(cve_ids)
    except Exception as e:
        logger.warning(f"[enrich] Enrichissement partiel ou ignoré : {e}")
        kev_set  = set()
        epss_map = {}

    for cve in cve_list:
        cid        = cve.get("id", "")
        epss_data  = epss_map.get(cid, {"score": 0.0, "percentile": 0.0})
        epss       = epss_data["score"]
        percentile = epss_data["percentile"]
        pct        = round(epss * 100, 2)       # ex: 47.3 (%)

        if pct >= 50:
            label = "Critique"
        elif pct >= 10:
            label = "Élevé"
        elif pct >= 1:
            label = "Modéré"
        else:
            label = "Faible"

        kev                    = cid in kev_set
        tr                     = compute_trurisk(cve.get("cvss"), epss, kev, cve.get("severity"))

        cve["epss"]            = epss
        cve["epss_percent"]    = pct
        cve["epss_percentile"] = round(percentile * 100, 1)   # ex: 95.3 (%)
        cve["epss_label"]      = label
        cve["in_kev"]          = kev
        cve["trurisk"]         = tr
        cve["trurisk_label"]   = trurisk_label(tr)

    return cve_list
