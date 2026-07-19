"""
Routes pour la gestion des distributions reprepro enterprise.
- GET  /distributions/          → liste + stats (nb paquets par distrib)
- GET  /distributions/{codename}/packages → paquets dans une distribution
- POST /distributions/promote   → promouvoir un paquet d'une distrib vers une autre
- POST /distributions/migrate   → migration en masse (ex: bookworm → jammy)
- POST /distributions/init      → initialise les dists/ reprepro pour les nouvelles distribs
"""
import json
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import (
    get_admin_user,
    get_current_user,
    get_maintainer_user,
    get_uploader_user,
)
from services.audit import log as audit_log
from services.distributions import (
    ENTERPRISE_DISTRIBUTIONS,
    VALID_CODENAMES,
    get_distribution_stats,
    list_packages_in_distrib,
    migrate_all,
    promote_package,
)
from services.format_router import REPO_FORMAT as _REPO_FORMAT
from services.format_router import is_apk as _is_apk
from services.format_router import is_apt as _is_apt
from services.format_router import is_rpm as _is_rpm

router = APIRouter(prefix="/distributions", tags=["Distributions"])

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))


# ─── Liste & stats ────────────────────────────────────────────────────────────

@router.get("/")
def list_distributions(current_user: str = Depends(get_current_user)):
    """Liste toutes les distributions avec leur nombre de paquets."""
    return {"distributions": get_distribution_stats()}


# ─── Paquets d'une distribution ───────────────────────────────────────────────

@router.get("/{codename}/packages")
def get_distrib_packages(
    codename: str,
    current_user: str = Depends(get_current_user),
):
    """Liste les paquets dans une distribution spécifique."""
    if codename not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail=f"Distribution inconnue : {codename}")
    packages = list_packages_in_distrib(codename)
    return {"codename": codename, "packages": packages, "total": len(packages)}


# ─── Promotion ────────────────────────────────────────────────────────────────

class PromoteRequest(BaseModel):
    package: str
    from_dist: str
    to_dist: str


@router.post("/promote")
def promote(
    req: PromoteRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Promeut un paquet d'une distribution vers une autre.
    Ex : jammy → noble pour déployer en production.
    """
    if req.from_dist not in VALID_CODENAMES or req.to_dist not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail="Distribution invalide")
    if req.from_dist == req.to_dist:
        raise HTTPException(status_code=400, detail="Source et destination identiques")

    ok, message = promote_package(req.package, req.from_dist, req.to_dist)
    if not ok:
        raise HTTPException(status_code=500, detail=message)

    audit_log("PROMOTE", current_user, "SUCCESS",
              package=req.package,
              detail=f"{req.from_dist} → {req.to_dist}")

    return {"status": "ok", "message": message,
            "package": req.package, "from": req.from_dist, "to": req.to_dist}


# ─── Migration en masse ───────────────────────────────────────────────────────

class MigrateRequest(BaseModel):
    from_dist: str
    to_dist: str


@router.post("/migrate")
def migrate(
    req: MigrateRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Copie TOUS les paquets de from_dist vers to_dist.
    Utilisé pour la migration initiale bookworm → jammy.
    Aussi met à jour les manifests locaux avec la nouvelle distribution.
    """
    if req.from_dist not in VALID_CODENAMES or req.to_dist not in VALID_CODENAMES:
        raise HTTPException(status_code=400, detail="Distribution invalide")
    if req.from_dist == req.to_dist:
        raise HTTPException(status_code=400, detail="Source et destination identiques")

    count, copied, errors = migrate_all(req.from_dist, req.to_dist)

    # Mettre à jour les manifests : changer distribution si c'est from_dist
    updated_manifests = 0
    if MANIFEST_DIR.exists():
        for mf_path in MANIFEST_DIR.glob("*.manifest.json"):
            try:
                with open(mf_path) as f:
                    mf = json.load(f)
                from services.format_router import DEFAULT_DISTRIBUTION as _DEF_DIST
                if mf.get("distribution", _DEF_DIST) == req.from_dist:
                    mf["distribution"] = req.to_dist
                    with open(mf_path, "w") as f:
                        json.dump(mf, f, indent=2, ensure_ascii=False)
                    updated_manifests += 1
            except Exception:
                continue

    # Reconstruire l'index depuis les manifests mis à jour
    if updated_manifests > 0:
        from services.indexer import sync_index_from_pool
        sync_index_from_pool()

    audit_log("MIGRATE", current_user, "SUCCESS",
              detail=f"{count} paquets migrés de {req.from_dist} vers {req.to_dist}")

    return {
        "status": "ok",
        "from": req.from_dist,
        "to": req.to_dist,
        "migrated": count,
        "packages": copied,
        "errors": errors,
        "manifests_updated": updated_manifests,
    }


# ─── Initialisation des distributions ─────────────────────────────────────────

_DIST_META = {
    # Debian / Ubuntu (reprepro APT)
    "jammy":    {"label": "Ubuntu 22.04 LTS"},
    "noble":    {"label": "Ubuntu 24.04 LTS"},
    "focal":    {"label": "Ubuntu 20.04 LTS"},
    "bookworm": {"label": "Debian 12"},
    # Alpine Linux (APK — inventaire et CVE uniquement, pas de dépôt reprepro)
    "alpine3.18": {"label": "Alpine Linux 3.18", "pkg_type": "apk"},
    "alpine3.19": {"label": "Alpine Linux 3.19", "pkg_type": "apk"},
    "alpine3.20": {"label": "Alpine Linux 3.20", "pkg_type": "apk"},
    "alpine3.21": {"label": "Alpine Linux 3.21", "pkg_type": "apk"},
}


def _get_gpg_key_id(gnupg_home: str) -> str | None:
    import subprocess
    env = {**os.environ, "GNUPGHOME": gnupg_home}
    result = subprocess.run(["gpg", "--list-keys", "--with-colons"],
                            capture_output=True, text=True, env=env)
    for line in result.stdout.splitlines():
        if line.startswith("pub:"):
            parts = line.split(":")
            if len(parts) > 4 and parts[4]:
                return parts[4]
    return None


# Architectures que reprepro doit accepter pour chaque distribution APT.
# "arm64" a été ajouté après le lancement initial (amd64 seul) — voir
# _distributions_conf_is_complete() pour comment un déploiement existant,
# déjà initialisé avec "Architectures: amd64" uniquement, se répare tout
# seul au prochain redémarrage plutôt que de rejeter silencieusement tout
# .deb arm64 pour toujours.
_REQUIRED_ARCHITECTURES = ["amd64", "arm64"]


def _write_distributions_conf(conf_dir: Path, gnupg_home: str, gpg_key_id: str | None):
    conf_dir.mkdir(parents=True, exist_ok=True)
    blocks = []
    for codename, meta in _DIST_META.items():
        # Les distributions APK (Alpine) ne sont pas gérées par reprepro
        if meta.get("pkg_type") == "apk":
            continue
        block = (
            f"Origin: Repod\n"
            f"Label: {meta['label']}\n"
            f"Codename: {codename}\n"
            f"Architectures: {' '.join(_REQUIRED_ARCHITECTURES)}\n"
            f"Components: main\n"
            f"Description: Repod Enterprise — {meta['label']}\n"
            f"Contents:\n"
        )
        if gpg_key_id:
            block += f"SignWith: {gpg_key_id}\n"
        blocks.append(block)
    (conf_dir / "distributions").write_text("\n".join(blocks))


def _distributions_conf_is_complete(conf_dir: Path) -> bool:
    """
    Vérifie que conf/distributions contient bien toutes les distributions
    requises, ET que chacune liste bien toutes les architectures requises
    (_REQUIRED_ARCHITECTURES). Retourne False si le fichier est absent, vide,
    s'il manque au moins une distribution, ou si une distribution présente
    ne liste pas encore toutes les architectures requises — ce second cas
    est ce qui permet à un déploiement existant (initialisé avant l'ajout du
    support arm64, avec "Architectures: amd64" seul) de se régénérer
    automatiquement au prochain redémarrage plutôt que de rester bloqué en
    amd64-only indéfiniment (auto_init_distributions() ne vérifiait jusqu'ici
    que la présence du codename, jamais le contenu de sa ligne Architectures).
    """
    conf_file = conf_dir / "distributions"
    if not conf_file.exists():
        return False
    try:
        content = conf_file.read_text()
        # Seulement les distributions APT (pas les Alpine qui ne passent pas par reprepro)
        required = {k for k, v in _DIST_META.items() if v.get("pkg_type") != "apk"}

        architectures_by_codename: dict[str, set[str]] = {}
        current_codename = None
        for line in content.splitlines():
            if line.lower().startswith("codename:"):
                current_codename = line.split(":", 1)[1].strip()
            elif line.lower().startswith("architectures:") and current_codename:
                architectures_by_codename[current_codename] = set(line.split(":", 1)[1].split())

        present = set(architectures_by_codename.keys())
        missing = required - present
        if missing:
            import logging
            logging.getLogger("distributions.auto_init").warning(
                f"[auto-init] conf/distributions incomplet — distributions manquantes : {missing}"
            )
            return False

        required_arch_set = set(_REQUIRED_ARCHITECTURES)
        incomplete_arch = {
            cn for cn in present
            if cn in required and not required_arch_set.issubset(architectures_by_codename[cn])
        }
        if incomplete_arch:
            import logging
            logging.getLogger("distributions.auto_init").warning(
                f"[auto-init] conf/distributions incomplet — architectures manquantes sur : {incomplete_arch}"
            )
            return False

        return True
    except Exception:
        return False


def auto_init_distributions() -> bool:
    """
    Vérifie et initialise les distributions au démarrage.

    Mode APT  : vérifie/répare conf/distributions (reprepro) — toutes les
                distributions requises (jammy, noble, focal, bookworm) doivent
                être présentes.
    Mode RPM  : initialise les répertoires createrepo_c pour chaque distribution
                si les métadonnées repomd.xml n'existent pas encore.
    Mode APK  : initialise les répertoires Alpine + APKINDEX.tar.gz vides.
    Mode ALL  : initialise les trois.

    Retourne True si une action corrective a été effectuée, False si tout était OK.
    """
    import logging
    log = logging.getLogger("distributions.auto_init")

    if _REPO_FORMAT == "all":
        apt_done = _auto_init_apt(log)
        rpm_done = _auto_init_rpm(log)
        apk_done = _auto_init_apk(log)
        return apt_done or rpm_done or apk_done
    if _REPO_FORMAT == "both":
        apt_done = _auto_init_apt(log)
        rpm_done = _auto_init_rpm(log)
        return apt_done or rpm_done
    if _is_rpm():
        return _auto_init_rpm(log)
    if _is_apk():
        return _auto_init_apk(log)
    return _auto_init_apt(log)


def _auto_init_apt(log) -> bool:
    """Initialisation reprepro (mode APT)."""
    import subprocess
    reprepro_base = Path(os.getenv("REPREPRO_BASE", "/repos"))
    conf_dir      = Path(os.getenv("CONF_DIR",      "/repos/conf"))
    gnupg_home    = os.getenv("GNUPG_HOME",          "/repos/gnupg")

    if _distributions_conf_is_complete(conf_dir):
        log.info("[auto-init APT] conf/distributions complet — aucune action requise")
        return False

    log.info("[auto-init APT] conf/distributions absent ou incomplet — réparation en cours…")
    try:
        gpg_key_id = _get_gpg_key_id(gnupg_home)
        _write_distributions_conf(conf_dir, gnupg_home, gpg_key_id)
        for d in ("dists", "db", "pool"):
            (reprepro_base / d).mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "GNUPGHOME": gnupg_home}
        # Supprimer les entrées orphelines avant d'exporter
        subprocess.run(
            ["reprepro", "-b", str(reprepro_base), "clearvanished"],
            capture_output=True, text=True, env=env,
        )
        # N'initialiser que les distributions APT (pas les RPM ni APK)
        apt_dists = [d for d in ENTERPRISE_DISTRIBUTIONS if d.get("format", "deb") == "deb"]
        ok_count = 0
        for dist in apt_dists:
            proc = subprocess.run(
                ["reprepro", "-b", str(reprepro_base), "export", dist["codename"]],
                capture_output=True, text=True, env=env,
            )
            if proc.returncode == 0:
                ok_count += 1
                log.info(f"[auto-init APT] ✓ {dist['codename']} initialisée")
            else:
                log.warning(
                    f"[auto-init APT] ✗ {dist['codename']} : "
                    f"{(proc.stdout + proc.stderr).strip()[:200]}"
                )
        log.info(
            f"[auto-init APT] Terminé — {ok_count}/{len(apt_dists)} distributions APT OK"
        )
        return True
    except Exception as exc:
        log.warning(f"[auto-init APT] Échec réparation distributions : {exc}")
        return False


def _auto_init_rpm(log) -> bool:
    """Initialisation createrepo_c (mode RPM)."""
    from services.distributions_rpm import RPM_DISTRIBUTIONS, init_distribution
    repaired = 0
    for dist in RPM_DISTRIBUTIONS:
        codename = dist["codename"]
        try:
            ok, msg = init_distribution(codename)
            if ok:
                log.info(f"[auto-init RPM] ✓ {codename} initialisée")
                repaired += 1
            else:
                log.warning(f"[auto-init RPM] ✗ {codename} : {msg}")
        except Exception as exc:
            log.warning(f"[auto-init RPM] Exception pour {codename} : {exc}")
    return repaired > 0


def _auto_init_apk(log) -> bool:
    """Initialisation APKINDEX (mode APK Alpine)."""
    from services.distributions_apk import APK_DISTRIBUTIONS, init_distribution
    repaired = 0
    for dist in APK_DISTRIBUTIONS:
        codename = dist["codename"]
        try:
            ok, msg = init_distribution(codename)
            if ok:
                log.info(f"[auto-init APK] ✓ {codename} initialisée")
                repaired += 1
            else:
                log.warning(f"[auto-init APK] ✗ {codename} : {msg}")
        except Exception as exc:
            log.warning(f"[auto-init APK] Exception pour {codename} : {exc}")
    return repaired > 0


@router.post("/init")
def init_distributions(current_user: str = Depends(get_maintainer_user)):
    """
    Initialise les dépôts pour toutes les distributions configurées.
    - Mode APT : reprepro export (conf/distributions)
    - Mode RPM : createrepo_c --update sur chaque répertoire distribution/arch
    - Mode APK : création des répertoires + APKINDEX.tar.gz vides
    - Mode ALL : les trois
    """
    if _REPO_FORMAT == "all":
        apt_r = _init_apt(current_user)
        rpm_r = _init_rpm(current_user)
        apk_r = _init_apk(current_user)
        return {
            "repo_format": "all",
            "apt": apt_r,
            "rpm": rpm_r,
            "apk": apk_r,
        }
    if _REPO_FORMAT == "both":
        apt_r = _init_apt(current_user)
        rpm_r = _init_rpm(current_user)
        return {"repo_format": "both", "apt": apt_r, "rpm": rpm_r}
    if _is_rpm():
        return _init_rpm(current_user)
    if _is_apk():
        return _init_apk(current_user)
    return _init_apt(current_user)


def _init_apt(current_user: str) -> dict:
    """Initialisation reprepro (mode APT)."""
    import subprocess

    from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _APT_ONLY_DISTS

    reprepro_base = Path(os.getenv("REPREPRO_BASE", "/repos"))
    conf_dir      = Path(os.getenv("CONF_DIR",      "/repos/conf"))
    gnupg_home    = os.getenv("GNUPG_HOME",          "/repos/gnupg")

    gpg_key_id = _get_gpg_key_id(gnupg_home)
    try:
        _write_distributions_conf(conf_dir, gnupg_home, gpg_key_id)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Impossible d'écrire conf/distributions : {exc}"
        )

    for d in ("dists", "db", "pool"):
        (reprepro_base / d).mkdir(parents=True, exist_ok=True)

    env = {**os.environ, "GNUPGHOME": gnupg_home}

    # Supprimer les entrées orphelines avant d'exporter (évite "unused database" errors)
    subprocess.run(
        ["reprepro", "-b", str(reprepro_base), "clearvanished"],
        capture_output=True, text=True, env=env,
    )

    results = []
    # N'initialiser que les distributions APT (pas RPM ni APK qui ne passent pas par reprepro)
    for dist in _APT_ONLY_DISTS:
        proc = subprocess.run(
            ["reprepro", "-b", str(reprepro_base), "export", dist["codename"]],
            capture_output=True, text=True, env=env,
        )
        ok = proc.returncode == 0
        results.append({
            "codename": dist["codename"],
            "ok":       ok,
            "output":   (proc.stdout + proc.stderr).strip()[:300] or
                        (f"Distribution '{dist['codename']}' initialisée" if ok else "Erreur reprepro"),
        })

    n_ok = sum(r["ok"] for r in results)
    audit_log("INIT_DISTS", current_user,
              "SUCCESS" if n_ok == len(results) else "PARTIAL",
              detail=f"Init reprepro : {n_ok}/{len(results)} distributions APT OK")
    return {"repo_format": "apt", "results": results}


def _init_rpm(current_user: str) -> dict:
    """Initialisation createrepo_c (mode RPM)."""
    from services.distributions_rpm import RPM_DISTRIBUTIONS, init_distribution
    results = []
    for dist in RPM_DISTRIBUTIONS:
        ok, msg = init_distribution(dist["codename"])
        results.append({
            "codename": dist["codename"],
            "ok":       ok,
            "output":   msg[:300],
        })
    n_ok = sum(r["ok"] for r in results)
    audit_log("INIT_DISTS", current_user,
              "SUCCESS" if n_ok == len(results) else "PARTIAL",
              detail=f"Init createrepo_c : {n_ok}/{len(results)} distributions OK")
    return {"repo_format": "rpm", "results": results}


def _init_apk(current_user: str) -> dict:
    """Initialisation APKINDEX Alpine (mode APK)."""
    from services.distributions_apk import APK_DISTRIBUTIONS, init_distribution
    results = []
    for dist in APK_DISTRIBUTIONS:
        ok, msg = init_distribution(dist["codename"])
        results.append({
            "codename": dist["codename"],
            "ok":       ok,
            "output":   msg[:300],
        })
    n_ok = sum(r["ok"] for r in results)
    audit_log("INIT_DISTS", current_user,
              "SUCCESS" if n_ok == len(results) else "PARTIAL",
              detail=f"Init APKINDEX Alpine : {n_ok}/{len(results)} distributions OK")
    return {"repo_format": "apk", "results": results}
