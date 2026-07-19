"""
services/reprepro.py — Opérations reprepro centralisées.

Ce module est le point d'entrée unique pour la suppression de paquets dans le
dépôt APT via reprepro (l'ajout est géré séparément par
`services/distributions_apt.py:_reprepro()`, en subprocess direct).

Avant ce refactoring, la commande `docker exec depot-apt reprepro remove ...`
était dupliquée en 4 endroits distincts (artifacts.py × 2, security_router.py × 2).
Tout changement (nom du conteneur, chemin reprepro, liste des distributions)
doit maintenant se faire ici uniquement.

`via_docker` vaut `False` par défaut : en production, `docker-compose.yaml` ne
monte PAS `/var/run/docker.sock` dans le conteneur backend (voir le
commentaire "SÉCURITÉ" à côté de `GNUPG_HOME` dans ce fichier) — reprepro est
appelé directement contre le volume `/repos` partagé avec `depot-apt`, comme
`_reprepro()` le fait déjà pour l'ajout. `via_docker=True` reste disponible
pour un usage explicite (ex. `docker-compose.dev.yml`, qui monte le socket),
mais n'est plus le comportement par défaut.

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
    via_docker: bool = False,
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
        # --delete est indispensable ici : sans lui, reprepro conserve le
        # fichier .deb dans le pool hiérarchique (pool/main/**/{name}_*.deb)
        # même une fois retiré de toutes les distributions qui le
        # référençaient (comportement par défaut de reprepro, documenté dans
        # son --help : "Delete included files if reasonable" n'est PAS
        # l'option par défaut). Sans ce flag, un paquet "supprimé" via l'UI
        # reste physiquement présent dans le pool hiérarchique — invisible
        # dans l'UI (manifest/index PostgreSQL bien retirés), mais toujours
        # détecté comme "déjà présent" par import_package_stream() (qui
        # vérifie précisément ce pool hiérarchique), bloquant silencieusement
        # toute réimportation ultérieure.
        if via_docker:
            cmd = [
                "docker", "exec", _CONTAINER,
                "reprepro", "-b", _WEB_BASE, "--delete", "remove", dist, name,
            ]
        else:
            cmd = ["reprepro", "-b", _BASE, "--delete", "remove", dist, name]

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

    # `--delete` sur `remove` ne suffit pas à lui seul : testé en direct,
    # reprepro laisse le fichier .deb orphelin dans le pool hiérographique
    # si, au moment du remove, il croit encore le fichier potentiellement
    # référencé ailleurs. `deleteunreferenced` est la commande dédiée qui
    # balaie et purge tout fichier réellement non référencé — appelée ici en
    # best-effort après CHAQUE suppression, elle nettoie aussi bien le
    # fichier qu'on vient de retirer que d'éventuels orphelins hérités de
    # suppressions précédentes (avant ce correctif, quand --delete était
    # totalement absent des commandes remove).
    try:
        cmd = (
            ["docker", "exec", _CONTAINER, "reprepro", "-b", _WEB_BASE, "--delete", "deleteunreferenced"]
            if via_docker
            else ["reprepro", "-b", _BASE, "--delete", "deleteunreferenced"]
        )
        subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:
        logger.warning(f"[reprepro] deleteunreferenced après suppression de {name} — échec (best-effort) : {exc}")

    return {
        "package":       name,
        "distributions": dists,
        "results":       results,
        "all_ok":        all_ok,
    }
