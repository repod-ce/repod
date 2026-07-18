"""
services/audit_export.py — Export du journal d'audit en CSV ou JSON.

Fonctionnalités :
  • export_audit_logs(format, start, end, …)
      → bytes bruts (CSV ou JSON, optionnellement compressé gzip)
  • sign_export(data_bytes)
      → signature GPG détachée (armored ASCII), ou None si GPG indisponible
  • get_export_filename(format, compress)
      → nom de fichier suggéré pour le Content-Disposition
  • build_audit_archive()
      → ZIP en mémoire de tous les fichiers JSONL du répertoire d'audit
  • export_user_data(username)
      → JSON RGPD des entrées d'audit concernant un utilisateur
  • check_audit_integrity()
      → liste des {file, sha256, size, lines} pour chaque JSONL d'audit

Filtres supportés :
  start / end    : borne temporelle ISO-8601 (incluses)
  package        : filtrer par nom de paquet exact
  action         : filtrer par type d'action (UPLOAD, DELETE…)
  result         : filtrer par résultat (SUCCESS, FAILURE…)
  user           : filtrer par nom d'utilisateur

Format CSV :
  Colonnes fixes : timestamp, action, user, result, package, version, detail
  Les champs supplémentaires (extra) ne sont pas inclus dans le CSV.

Format JSON :
  Liste JSON des entrées correspondant aux filtres, triée par timestamp.

Compression :
  compress=True → gzip les données produites (Content-Encoding: gzip).

Signature GPG :
  sign=True → produit une signature détachée via `gpg --detach-sign --armor`.
  Si gpg est absent ou échoue, retourne None pour la signature (pas d'erreur bloquante).
"""

import csv
import gzip
import hashlib
import io
import json
import logging
import subprocess
import zipfile
from datetime import datetime, timezone
from typing import Literal

logger = logging.getLogger("audit_export")

# Colonnes fixes exportées dans le CSV (ordre stable)
CSV_COLUMNS = ("timestamp", "action", "user", "result", "package", "version", "detail")

ExportFormat = Literal["csv", "json"]


# ── Filtrage des entrées ──────────────────────────────────────────────────────

def _parse_dt(raw: str | None) -> datetime | None:
    """Parse une chaîne ISO-8601 en datetime UTC. Retourne None si invalide."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _entry_dt(entry: dict) -> datetime | None:
    return _parse_dt(entry.get("timestamp"))


def _filter_entries(
    entries: list[dict],
    start: str | None = None,
    end: str | None = None,
    package: str | None = None,
    action: str | None = None,
    result: str | None = None,
    user: str | None = None,
) -> list[dict]:
    """Applique les filtres sur la liste d'entrées."""
    dt_start = _parse_dt(start)
    dt_end   = _parse_dt(end)

    out = []
    for entry in entries:
        dt = _entry_dt(entry)

        if dt_start and dt and dt < dt_start:
            continue
        if dt_end and dt and dt > dt_end:
            continue
        if package and entry.get("package") != package:
            continue
        if action and entry.get("action", "").upper() != action.upper():
            continue
        if result and entry.get("result", "").upper() != result.upper():
            continue
        if user and entry.get("user") != user:
            continue

        out.append(entry)

    return out


# ── Sérialisation ─────────────────────────────────────────────────────────────

def _to_csv(entries: list[dict]) -> bytes:
    """Sérialise les entrées en CSV UTF-8 avec BOM (compatible Excel)."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=list(CSV_COLUMNS),
        extrasaction="ignore",
        lineterminator="\r\n",
    )
    writer.writeheader()
    for entry in entries:
        row = {col: entry.get(col, "") or "" for col in CSV_COLUMNS}
        writer.writerow(row)
    return ("﻿" + buf.getvalue()).encode("utf-8")


def _to_json(entries: list[dict]) -> bytes:
    """Sérialise les entrées en JSON indenté (UTF-8)."""
    return json.dumps(entries, ensure_ascii=False, indent=2).encode("utf-8")


# ── Compression ───────────────────────────────────────────────────────────────

def _gzip_compress(data: bytes) -> bytes:
    """Compresse les données en gzip."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


# ── Signature GPG ─────────────────────────────────────────────────────────────

def sign_export(data: bytes) -> str | None:
    """
    Produit une signature GPG détachée armored pour les données fournies.
    Retourne la signature ASCII ou None si gpg est absent / échoue.

    La clé utilisée est la clé par défaut du trousseau de l'utilisateur courant.
    """
    try:
        proc = subprocess.run(
            ["gpg", "--batch", "--yes", "--detach-sign", "--armor"],
            input=data,
            capture_output=True,
            timeout=15,
        )
        if proc.returncode != 0:
            logger.warning(
                "[audit_export] gpg a retourné %d : %s",
                proc.returncode,
                proc.stderr.decode(errors="replace"),
            )
            return None
        return proc.stdout.decode(errors="replace")
    except FileNotFoundError:
        logger.warning("[audit_export] gpg introuvable — signature ignorée")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("[audit_export] gpg timeout — signature ignorée")
        return None
    except Exception as exc:
        logger.warning("[audit_export] gpg erreur inattendue : %s", exc)
        return None


# ── Export principal ──────────────────────────────────────────────────────────

def export_audit_logs(
    fmt: ExportFormat = "json",
    start: str | None = None,
    end: str | None = None,
    package: str | None = None,
    action: str | None = None,
    result: str | None = None,
    user: str | None = None,
    compress: bool = False,
    sign: bool = False,
) -> dict:
    """
    Exporte les entrées d'audit selon les filtres fournis.

    Retourne
    --------
    {
      "data":      bytes,           # contenu (csv/json, éventuellement gzippé)
      "signature": str | None,      # signature GPG armored, ou None
      "count":     int,             # nombre d'entrées exportées
      "format":    str,             # "csv" | "json"
      "compressed": bool,
    }
    """
    from services.audit import get_recent_logs

    all_entries = get_recent_logs(limit=100_000)
    filtered    = _filter_entries(all_entries, start=start, end=end,
                                  package=package, action=action,
                                  result=result, user=user)

    # Tri chronologique ascendant
    filtered.sort(key=lambda e: (e.get("timestamp") or ""))

    # Sérialisation
    if fmt == "csv":
        raw = _to_csv(filtered)
    else:
        raw = _to_json(filtered)

    # Compression optionnelle
    data      = _gzip_compress(raw) if compress else raw
    signature = sign_export(data) if sign else None

    return {
        "data":       data,
        "signature":  signature,
        "count":      len(filtered),
        "format":     fmt,
        "compressed": compress,
    }


# ── Utilitaires pour le router ────────────────────────────────────────────────

def get_export_filename(fmt: ExportFormat, compress: bool) -> str:
    """Génère un nom de fichier pour le Content-Disposition."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    ext   = "csv" if fmt == "csv" else "json"
    name  = f"audit_export_{today}.{ext}"
    if compress:
        name += ".gz"
    return name


# ── Archive ZIP ───────────────────────────────────────────────────────────────

def build_audit_archive() -> bytes:
    """
    Crée un fichier ZIP en mémoire contenant tous les fichiers JSONL
    présents dans le répertoire d'audit.

    Chaque fichier est stocké avec son nom d'origine (ex. 2026-06-03.jsonl).
    Retourne les octets du ZIP (vide si aucun fichier JSONL n'existe).
    """
    from services import audit as _audit_mod
    audit_dir = _audit_mod.AUDIT_DIR

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
            try:
                zf.write(jsonl_file, arcname=jsonl_file.name)
            except Exception as exc:
                logger.warning("[audit_export] impossible d'archiver %s : %s",
                               jsonl_file.name, exc)
    return buf.getvalue()


# ── Export RGPD utilisateur ───────────────────────────────────────────────────

def export_user_data(username: str) -> bytes:
    """
    Exporte toutes les entrées d'audit concernant l'utilisateur `username`.

    Conforme RGPD — retourne un JSON structuré :
    {
      "username":    str,
      "exported_at": str (ISO-8601),
      "count":       int,
      "entries":     list[dict]   # triée par timestamp ascendant
    }
    """
    from services import audit as _audit_mod
    audit_dir = _audit_mod.AUDIT_DIR

    entries: list[dict] = []
    for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
        try:
            with open(jsonl_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("user") == username:
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue

    entries.sort(key=lambda e: e.get("timestamp") or "")

    payload = {
        "username":    username,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "count":       len(entries),
        "entries":     entries,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


# ── Vérification d'intégrité ──────────────────────────────────────────────────

def check_audit_integrity() -> list[dict]:
    """
    Calcule le condensat SHA-256 de chaque fichier JSONL d'audit.

    Retourne une liste triée par nom de fichier :
    [
      {"file": "2026-06-03.jsonl", "sha256": "…", "size": 4096, "lines": 42},
      …
    ]
    En cas d'erreur de lecture d'un fichier, l'entrée contiendra "error".
    """
    from services import audit as _audit_mod
    audit_dir = _audit_mod.AUDIT_DIR

    results: list[dict] = []
    for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
        try:
            data   = jsonl_file.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            # Compter les lignes non vides (= entrées valides potentielles)
            lines  = sum(1 for l in data.split(b"\n") if l.strip())
            results.append({
                "file":   jsonl_file.name,
                "sha256": sha256,
                "size":   len(data),
                "lines":  lines,
            })
        except Exception as exc:
            results.append({
                "file":  jsonl_file.name,
                "error": str(exc),
            })
    return results
