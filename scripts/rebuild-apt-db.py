#!/usr/bin/env python3
"""
Reconstruction complète de la base de données reprepro depuis le pool plat.
- Sauvegarde la DB actuelle
- Efface la DB corrompue
- Réinsère tous les paquets validés via la structure hiérarchique correcte
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOS_BASE    = Path("/repos")
POOL_FLAT     = REPOS_BASE / "pool"
POOL_HIER     = POOL_FLAT / "main"
MANIFESTS_DIR = REPOS_BASE / "manifests"
GNUPG_HOME    = REPOS_BASE / "gnupg"
DB_DIR        = REPOS_BASE / "db"
DB_BACKUP     = REPOS_BASE / "db_backup"

def reprepro(*args):
    env = os.environ.copy()
    env["GNUPGHOME"] = str(GNUPG_HOME)
    r = subprocess.run(
        ["reprepro", "-b", str(REPOS_BASE)] + list(args),
        capture_output=True, text=True, env=env
    )
    return r.returncode, r.stdout + r.stderr

# ─── 1. Lire les manifests (filename → distribution, status)
print("1. Lecture des manifests...")
pkg_distrib = {}  # filename → distribution
pkg_status  = {}  # filename → status
for mf in MANIFESTS_DIR.glob("*.json"):
    if mf.name in ("index.json",):
        continue
    try:
        data = json.loads(mf.read_text())
        fn   = data.get("filename")
        dist = data.get("distribution", "jammy")
        stat = data.get("status", "validated")
        if fn:
            # En cas de conflit (même fichier, manifests multiples), garder validated
            if fn not in pkg_distrib or stat == "validated":
                pkg_distrib[fn] = dist
                pkg_status[fn]  = stat
    except Exception as e:
        print(f"  ⚠ Erreur {mf.name}: {e}")

# Paquets dans le pool plat sans manifest → ajouter avec distrib par défaut
for flat in POOL_FLAT.glob("*.deb"):
    if flat.name not in pkg_distrib:
        # Deviner la distrib depuis dpkg-deb
        pkg_distrib[flat.name] = "jammy"
        pkg_status[flat.name]  = "validated"

all_flat = sorted(POOL_FLAT.glob("*.deb"))
print(f"   {len(pkg_distrib)} entrées manifest, {len(all_flat)} fichiers pool")

# ─── 2. Sauvegarde DB
print("\n2. Sauvegarde de la DB reprepro...")
if DB_BACKUP.exists():
    shutil.rmtree(DB_BACKUP)
shutil.copytree(DB_DIR, DB_BACKUP)
print(f"   DB sauvegardée → {DB_BACKUP}")

# ─── 3. Suppression DB
print("\n3. Suppression de la DB corrompue...")
for db_file in DB_DIR.iterdir():
    if db_file.is_file():
        db_file.unlink()
print("   DB effacée.")

# ─── 4. Réinsertion depuis pool plat
print("\n4. Réinsertion des paquets via pool hiérarchique...")
ok       = 0
skipped  = 0
warnings = []
errors   = []

for flat_path in all_flat:
    fn       = flat_path.name
    distrib  = pkg_distrib.get(fn, "jammy")
    status   = pkg_status.get(fn, "validated")

    if status == "pending_review":
        print(f"  ⏳ {fn} — pending_review (non publié dans APT)")
        skipped += 1
        continue

    # Temp dir HORS REPREPRO_BASE pour forcer la copie hiérarchique
    with tempfile.TemporaryDirectory(prefix="/tmp/repod-rebuild-") as tmpdir:
        tmp_path = Path(tmpdir) / fn
        shutil.copy2(flat_path, tmp_path)

        rc, out = reprepro("includedeb", distrib, str(tmp_path))

        if rc == 0:
            # Vérifier présence physique dans le pool hiérarchique
            hier_files = list(POOL_HIER.rglob(fn)) if POOL_HIER.exists() else []
            if hier_files:
                print(f"  ✅ {fn}  [{distrib}]")
                ok += 1
            else:
                msg = f"rc=0 mais absent hiérarchique: {fn}"
                print(f"  ⚠  {msg}")
                warnings.append(msg)
                ok += 1  # reprepro dit OK, on continue
        else:
            if "already" in out.lower() or "skipping" in out.lower():
                # version plus récente déjà présente — non bloquant
                print(f"  ℹ  {fn} [{distrib}] — version déjà enregistrée")
                ok += 1
            else:
                msg = f"ERREUR (rc={rc}) {fn}: {out[:250]}"
                print(f"  ❌ {msg}")
                errors.append(msg)

# ─── 5. Résumé
print(f"""
═══════════════════════════════════════════
Reconstruction terminée :
  ✅ OK       : {ok}
  ⏳ Ignorés  : {skipped}
  ⚠  Warnings : {len(warnings)}
  ❌ Erreurs  : {len(errors)}
""")

if warnings:
    print("Warnings:")
    for w in warnings[:10]:
        print(f"  ⚠  {w}")

if errors:
    print("Erreurs:")
    for e in errors[:10]:
        print(f"  ✗ {e}")
    print("\nLa sauvegarde DB est dans /repos/db_backup — restaurer avec:")
    print("  rm -rf /repos/db && cp -r /repos/db_backup /repos/db")
    sys.exit(1)
else:
    # Vérification finale
    hier_count = sum(1 for _ in POOL_HIER.rglob("*.deb")) if POOL_HIER.exists() else 0
    flat_count = len(all_flat)
    print(f"Vérification finale:")
    print(f"  Pool plat     : {flat_count} fichiers")
    print(f"  Pool APT hier : {hier_count} fichiers")
    print(f"\n✅ Reconstruction réussie !")
