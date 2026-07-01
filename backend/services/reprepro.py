"""
services/reprepro.py — Opérations reprepro centralisées.

Ce module est le point d'entrée unique pour toutes les interactions avec reprepro
(ajout, suppression de paquets dans le dépôt APT).

Avant ce refactoring, la commande `docker exec depot-apt reprepro remove ...`
était dupliquée en 4 endroits distincts (artifacts.py × 2, security_router.py × 2).
Tout changement (nom du conteneur, chemin reprepro, liste des distributions)
doit maintenant se faire ici uniquement.

Variables d'environnement :
  REPREPRO_CONTAINER : nom du conteneur depot-apt (défaut : "depot-apt")
  REPREPRO_BASE      : chemin -b pour reprepro (défaut : "/repos")
  REPREPRO_DISTS     : distributions séparées par virgule
                       (défaut : "jammy,noble,focal,bookworm")
"""

import logging
import os
import subprocess
from typing import Sequence

logger = logging.getLogger("reprepro")

# ── Configuration centralisée ─────────────────────────────────────────────────

_CONTAINER = os.getenv("REPREPRO_CONTAINER", "depot-apt")
_BASE      = os.getenv("REPREPRO_BASE",      "/repos")
_WEB_BASE  = "/usr/share/nginx/html/repos"  # chemin dans le conteneur apt-repo

_DEFAULT_DISTS: list[str] = [
    d.strip()
    for d in os.getenv("REPREPRO_DISTS", "jammy,noble,focal,bookworm").split(",")
    if d.strip()
]


# ── Suppression ───────────────────────────────────────────────────────────────

def remove_package(
    name: str,
    distributions: Sequence[str] | None = None,
    via_docker: bool = True,
) -> dict:
    """
    Supprime un paquet de reprepro dans toutes les distributions spécifiées.

    Paramètres
    ----------
    name          : nom du paquet (sans version ni arch).
    distributions : liste de distributions cibles ; None = toutes les distributions
                    par défaut (REPREPRO_DISTS ou fallback hardcodé).
    via_docker    : si True, passe par `docker exec <container>` ;
                    si False, appelle reprepro directement (backend et depot-apt
                    partagent le même filesystem, ex: test ou mode standalone).

    Retourne un dict :
      {
        "package": str,
        "distributions": list[str],
        "results": { dist: {"returncode": int, "ok": bool, "output": str} },
        "all_ok": bool,
      }
    """
    dists = list(distributions) if distributions is not None else _DEFAULT_DISTS
    results: dict[str, dict] = {}

    for dist in dists:
        if via_docker:
            cmd = [
                "docker", "exec", _CONTAINER,
                "reprepro", "-b", _WEB_BASE, "remove", dist, name,
            ]
        else:
            cmd = ["reprepro", "-b", _BASE, "remove", dist, name]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            ok     = proc.returncode == 0
            output = (proc.stdout or proc.stderr or "").strip()
            results[dist] = {"returncode": proc.returncode, "ok": ok, "output": output}

            if not ok:
                logger.warning(
                    f"[reprepro] remove {name} de {dist} — code {proc.returncode} : {output[:120]}"
                )
        except subprocess.TimeoutExpired:
            results[dist] = {"returncode": -1, "ok": False, "output": "timeout (30s)"}
            logger.error(f"[reprepro] remove {name} de {dist} — timeout")
        except FileNotFoundError as exc:
            results[dist] = {"returncode": -1, "ok": False, "output": str(exc)}
            logger.error(f"[reprepro] commande introuvable : {exc}")

    all_ok = all(r["ok"] for r in results.values())
    if all_ok:
        logger.info(f"[reprepro] {name} retiré de : {', '.join(dists)}")

    return {
        "package":       name,
        "distributions": dists,
        "results":       results,
        "all_ok":        all_ok,
    }
