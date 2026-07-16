"""
Système d'audit immuable (append-only).
Chaque action critique est enregistrée en JSONL avec timestamp.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

AUDIT_DIR = Path(os.getenv("AUDIT_DIR", "/repos/audit"))
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

_lock = Lock()


def _audit_file() -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return AUDIT_DIR / f"{today}.jsonl"


def log(
    action: str,
    user: str,
    result: str,
    package: str = None,
    version: str = None,
    detail: str = None,
    extra: dict = None,
):
    """
    Enregistre une entrée d'audit.

    action  : UPLOAD | VALIDATE | INSTALL | DELETE | ROLLBACK | LOGIN | SYNC
    result  : SUCCESS | FAILURE | WARNING
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "user": user,
        "result": result,
    }
    if package:
        entry["package"] = package
    if version:
        entry["version"] = version
    if detail:
        entry["detail"] = detail
    if extra:
        entry.update(extra)

    with _lock:
        with open(_audit_file(), "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Diffusion temps réel via SSE (non-bloquant, failure ignorée)
    try:
        from services.sse_bus import publish_event as _sse_publish
        _sse_publish("audit_log", {
            "action":    action,
            "user":      user,
            "result":    result,
            "package":   package,
            "timestamp": entry["timestamp"],
        })
    except Exception:
        pass


def get_recent_logs(limit: int = 100) -> list[dict]:
    """Retourne les N dernières entrées d'audit (tous les fichiers confondus)."""
    entries = []
    log_files = sorted(AUDIT_DIR.glob("*.jsonl"), reverse=True)

    for log_file in log_files:
        try:
            with open(log_file) as f:
                lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                if len(entries) >= limit:
                    break
        except Exception:
            continue
        if len(entries) >= limit:
            break

    return entries[:limit]


def get_package_history(package_name: str) -> list[dict]:
    """Retourne tout l'historique d'un paquet spécifique."""
    entries = []
    for log_file in sorted(AUDIT_DIR.glob("*.jsonl")):
        try:
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            if entry.get("package") == package_name:
                                entries.append(entry)
                        except json.JSONDecodeError:
                            continue
        except Exception:
            continue
    return entries
