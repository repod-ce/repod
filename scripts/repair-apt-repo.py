#!/usr/bin/env python3
"""
Script de réparation du dépôt APT.
Resynchronise tous les .deb du pool plat vers le pool hiérarchique reprepro.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPOS_BASE   = Path("/repos")
POOL_FLAT    = REPOS_BASE / "pool"
POOL_HIER    = REPOS_BASE / "pool" / "main"
MANIFESTS_DIR = REPOS_BASE / "manifests"
GNUPG_HOME   = REPOS_BASE / "gnupg"
INDEX_PATH   = REPOS_BASE / "manifests" / "index.json"

def reprepro(*args):
    env = os.environ.copy()
    env["GNUPGHOME"] = str(GNUPG_HOME)
    result = subprocess.run(
        ["reprepro", "-b", str(REPOS_BASE)] + list(args),
        capture_output=True, text=True, env=env
    )
    return result.returncode, result.stdout + result.stderr

def pkg_in_hier(filename):
    """Vérifie si le fichier est dans le pool hiérarchique reprepro."""
    matches = list(POOL_HIER.rglob(filename))
    return bool(matches)

def get_distribution_from_manifest(filename):
    """Cherche la distribution dans les manifests."""
    if MANIFESTS_DIR.exists():
        for mf in MANIFESTS_DIR.glob("*.json"):
            if mf.name == "index.json":
                continue
            try:
                data = json.loads(mf.read_text())
                if data.get("filename") == filename:
                    return data.get("distribution", "jammy")
            except Exception:
                pass
    return "jammy"  # fallback

def get_pkg_name(deb_path):
    result = subprocess.run(
        ["dpkg-deb", "-f", str(deb_path), "Package"],
        capture_output=True, text=True
    )
    return result.stdout.strip()

# Inventaire
flat_debs  = sorted(POOL_FLAT.glob("*.deb"))
missing    = [f for f in flat_debs if not pkg_in_hier(f.name)]

print(f"Pool plat     : {len(flat_debs)} paquets")
print(f"Pool APT hier.: {sum(1 for _ in POOL_HIER.rglob('*.deb')) if POOL_HIER.exists() else 0} paquets")
print(f"Manquants     : {len(missing)} à réparer")
print()

if not missing:
    print("✅  Rien à réparer — tous les paquets sont dans le pool APT.")
    sys.exit(0)

ok = 0
errors = []

for deb_path in missing:
    fn  = deb_path.name
    distrib = get_distribution_from_manifest(fn)
    pkg_name = get_pkg_name(deb_path)

    print(f"  ▸ {fn}  [{distrib}]")

    # Retirer de la DB reprepro si présent (évite le "Skipping")
    if pkg_name:
        rc, out = reprepro("listfilter", distrib, f"Package (== {pkg_name})")
        if out.strip():
            print(f"      → en DB ({pkg_name}), suppression avant ré-insertion...")
            reprepro("remove", distrib, pkg_name)

    # Insérer depuis le pool plat
    rc, out = reprepro("includedeb", distrib, str(deb_path))
    if rc == 0:
        if pkg_in_hier(fn):
            print(f"      ✅ OK")
            ok += 1
        else:
            msg = f"reprepro rc=0 mais fichier absent du pool hiérarchique: {fn}"
            print(f"      ⚠  {msg}")
            errors.append(msg)
    else:
        if "already" in out.lower() or "skipping" in out.lower():
            # Re-vérifier
            if pkg_in_hier(fn):
                print(f"      ✅ Déjà présent (confirmé)")
                ok += 1
            else:
                msg = f"'already' mais absent hiérarchique: {fn}"
                print(f"      ❌ {msg}")
                errors.append(msg)
        else:
            msg = f"Erreur reprepro (rc={rc}): {fn} — {out[:200]}"
            print(f"      ❌ {msg}")
            errors.append(msg)

print()
print(f"═══════════════════════════════════")
print(f"Réparé : {ok}/{len(missing)}")
if errors:
    print(f"Erreurs : {len(errors)}")
    for e in errors:
        print(f"  ✗ {e}")
else:
    print("✅  Tous les paquets réparés avec succès !")
