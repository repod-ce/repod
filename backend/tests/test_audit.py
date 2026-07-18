"""
Module : test_audit.py
Rôle   : P1-B — Tests du journal d'audit immuable (append-only JSONL)
         Vérifie log(), get_recent_logs(), get_package_history()
         et la robustesse face aux fichiers corrompus.

Dépend : pytest
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_audit_test_")
os.environ["AUDIT_DIR"] = _TMP         # override absolu
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread

import pytest

import services.audit as audit_mod
# Rediriger le module vers notre répertoire temp
audit_mod.AUDIT_DIR = Path(_TMP)

from services.audit import log, get_recent_logs, get_package_history


# ── Fixture : nettoyage avant chaque test ────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_audit_dir():
    for f in Path(_TMP).glob("*.jsonl"):
        f.unlink(missing_ok=True)
    yield
    for f in Path(_TMP).glob("*.jsonl"):
        f.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# log() — écriture JSONL
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditLog:

    def test_log_creates_file(self):
        """log() crée un fichier YYYY-MM-DD.jsonl dans AUDIT_DIR."""
        log("UPLOAD", "alice", "SUCCESS")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert (Path(_TMP) / f"{today}.jsonl").exists()

    def test_log_entry_is_valid_json(self):
        """Chaque ligne écrite est du JSON valide."""
        log("UPLOAD", "alice", "SUCCESS", package="nginx")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = (Path(_TMP) / f"{today}.jsonl").read_text().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert isinstance(entry, dict)

    def test_log_contains_required_fields(self):
        """L'entrée contient timestamp, action, user, result."""
        log("VALIDATE", "bob", "FAILURE", package="curl", version="7.88.0")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = json.loads((Path(_TMP) / f"{today}.jsonl").read_text().splitlines()[0])
        assert entry["action"] == "VALIDATE"
        assert entry["user"] == "bob"
        assert entry["result"] == "FAILURE"
        assert entry["package"] == "curl"
        assert entry["version"] == "7.88.0"
        assert "timestamp" in entry

    def test_log_optional_fields_omitted_when_none(self):
        """Les champs optionnels absents ne figurent pas dans l'entrée."""
        log("LOGIN", "carol", "SUCCESS")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = json.loads((Path(_TMP) / f"{today}.jsonl").read_text().splitlines()[0])
        assert "package" not in entry
        assert "version" not in entry
        assert "detail" not in entry

    def test_log_extra_fields_merged(self):
        """Les champs extra sont fusionnés dans l'entrée."""
        log("UPLOAD", "alice", "SUCCESS", extra={"distribution": "jammy", "size": 1024})
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = json.loads((Path(_TMP) / f"{today}.jsonl").read_text().splitlines()[0])
        assert entry["distribution"] == "jammy"
        assert entry["size"] == 1024

    def test_log_appends_multiple_entries(self):
        """N appels successifs → N lignes dans le même fichier."""
        for i in range(5):
            log("UPLOAD", f"user{i}", "SUCCESS", package=f"pkg{i}")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = (Path(_TMP) / f"{today}.jsonl").read_text().splitlines()
        assert len(lines) == 5

    def test_log_timestamp_is_iso_utc(self):
        """Le timestamp est une ISO 8601 UTC valide."""
        log("DELETE", "admin", "SUCCESS")
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = json.loads((Path(_TMP) / f"{today}.jsonl").read_text().splitlines()[0])
        ts = entry["timestamp"]
        # Doit être parsable
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None

    def test_log_thread_safe(self):
        """50 threads écrivant simultanément → 50 lignes valides."""
        errors: list = []

        def write():
            try:
                log("UPLOAD", "user", "SUCCESS", package="pkg")
            except Exception as e:
                errors.append(e)

        threads = [Thread(target=write) for _ in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Erreurs en écriture concurrente : {errors}"
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        lines = (Path(_TMP) / f"{today}.jsonl").read_text().splitlines()
        assert len(lines) == 50
        for line in lines:
            json.loads(line)  # chaque ligne valide


# ═══════════════════════════════════════════════════════════════════════════════
# get_recent_logs() — lecture inverse
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetRecentLogs:

    def test_returns_empty_list_when_no_logs(self):
        """Répertoire vide → liste vide."""
        assert get_recent_logs() == []

    def test_returns_entries_most_recent_first(self):
        """Les entrées sont retournées de la plus récente à la plus ancienne."""
        log("UPLOAD", "alice", "SUCCESS", package="pkg_a")
        log("UPLOAD", "bob",   "SUCCESS", package="pkg_b")
        log("UPLOAD", "carol", "SUCCESS", package="pkg_c")
        entries = get_recent_logs()
        assert len(entries) == 3
        # La plus récente est en premier
        assert entries[0]["package"] == "pkg_c"
        assert entries[2]["package"] == "pkg_a"

    def test_limit_is_respected(self):
        """limit=2 → au plus 2 entrées retournées."""
        for i in range(10):
            log("UPLOAD", "user", "SUCCESS", package=f"pkg{i}")
        entries = get_recent_logs(limit=2)
        assert len(entries) == 2

    def test_corrupted_line_is_skipped(self):
        """Une ligne JSON malformée est ignorée — les autres sont retournées."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        audit_file = Path(_TMP) / f"{today}.jsonl"
        # Bonne entrée, ligne corrompue, bonne entrée
        audit_file.write_text(
            '{"action":"UPLOAD","user":"alice","result":"SUCCESS","timestamp":"2025-01-01T00:00:00+00:00"}\n'
            'THIS IS NOT JSON\n'
            '{"action":"DELETE","user":"bob","result":"SUCCESS","timestamp":"2025-01-01T00:00:01+00:00"}\n'
        )
        entries = get_recent_logs()
        assert len(entries) == 2
        actions = {e["action"] for e in entries}
        assert "UPLOAD" in actions
        assert "DELETE" in actions


# ═══════════════════════════════════════════════════════════════════════════════
# get_package_history() — filtrage par paquet
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetPackageHistory:

    def test_returns_only_entries_for_package(self):
        """Seules les entrées du paquet demandé sont retournées."""
        log("UPLOAD",   "alice", "SUCCESS", package="nginx")
        log("VALIDATE", "alice", "SUCCESS", package="nginx")
        log("UPLOAD",   "bob",   "SUCCESS", package="curl")

        history = get_package_history("nginx")
        assert len(history) == 2
        assert all(e["package"] == "nginx" for e in history)

    def test_returns_empty_for_unknown_package(self):
        """Paquet inconnu → liste vide."""
        log("UPLOAD", "alice", "SUCCESS", package="nginx")
        assert get_package_history("unknown_pkg") == []

    def test_history_ordered_chronologically(self):
        """L'historique est dans l'ordre chronologique (fichier lu de haut en bas)."""
        log("UPLOAD",   "alice", "SUCCESS", package="vim")
        log("VALIDATE", "alice", "SUCCESS", package="vim")
        log("DELETE",   "alice", "SUCCESS", package="vim")

        history = get_package_history("vim")
        assert len(history) == 3
        actions = [e["action"] for e in history]
        assert actions == ["UPLOAD", "VALIDATE", "DELETE"]
