"""
Module : conftest.py
Rôle   : Fixtures pytest partagées — email/SMTP mocks + DB test engine.
Expose : email_settings, email_settings_ssl, email_settings_disabled,
         mock_smtp, mock_smtp_ssl, db_test_engine
Dépend : pytest, unittest.mock, sqlalchemy
"""
import pytest
from unittest.mock import patch, MagicMock


# ── Données de test ───────────────────────────────────────────────────────────

_EMAIL_CFG_BASE = {
    "enabled":       True,
    "smtp_host":     "smtp.test.local",
    "smtp_port":     587,
    "smtp_user":     "repod@test.local",
    "smtp_password": "s3cr3t",
    "from_address":  "repod@test.local",
    "to_addresses":  "admin@test.local",
    "use_tls":       True,
}


@pytest.fixture
def email_settings():
    """Settings complets avec email activé — port 587 (STARTTLS)."""
    return {
        "email":         _EMAIL_CFG_BASE.copy(),
        "notifications": {"webhook_enabled": False, "webhook_url": ""},
        "app_url":       "http://localhost:3003",
    }


@pytest.fixture
def email_settings_ssl():
    """Settings email avec port 465 — SMTP_SSL direct."""
    cfg = {**_EMAIL_CFG_BASE, "smtp_port": 465}
    return {
        "email":         cfg,
        "notifications": {"webhook_enabled": False, "webhook_url": ""},
        "app_url":       "http://localhost:3003",
    }


@pytest.fixture
def email_settings_disabled():
    """Settings avec email désactivé."""
    return {"email": {"enabled": False}}


# ── Mocks SMTP ────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_smtp():
    """
    Mock smtplib.SMTP pour port 587 (STARTTLS).
    Yields (mock_class, mock_server) :
      - mock_class  : le constructeur SMTP() remplacé
      - mock_server : l'objet session actif dans le bloc `with ... as server`
    """
    with patch("smtplib.SMTP") as mock_class:
        mock_server = mock_class.return_value.__enter__.return_value
        yield mock_class, mock_server


@pytest.fixture
def mock_smtp_ssl():
    """Mock smtplib.SMTP_SSL pour port 465."""
    with patch("smtplib.SMTP_SSL") as mock_class:
        mock_server = mock_class.return_value.__enter__.return_value
        yield mock_class, mock_server


# ── DB test engine (SQLite in-memory) ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def db_test_engine():
    """
    Moteur SQLite in-memory pour les tests unitaires.
    Remplace db.engine._engine afin que tous les services utilisent SQLite
    sans nécessiter un serveur PostgreSQL.

    Tables créées : users, api_tokens, revoked_tokens, manifests, ssh_known_hosts,
                    inventory_clients, inventory_packages, packages, sync_status, sync_log,
                    import_groups, import_group_files,
                    apk_packages, apk_sync_status.
    """
    from sqlalchemy import create_engine, text as _t
    from sqlalchemy.pool import StaticPool
    import db.engine as _engine_mod

    # StaticPool + check_same_thread=False : une connexion unique partagée
    # entre threads. Nécessaire car decode_token() (auth/jwt.py) interroge
    # désormais revoked_tokens à chaque requête, et FastAPI TestClient exécute
    # les requêtes dans un thread différent du thread de test (SQLite
    # in-memory + SingletonThreadPool lèverait sqlite3.ProgrammingError).
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    with engine.begin() as c:
        c.execute(_t("""
            CREATE TABLE users (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                username            TEXT UNIQUE NOT NULL,
                hashed_password     TEXT NOT NULL DEFAULT '',
                role                TEXT NOT NULL DEFAULT 'reader',
                full_name           TEXT NOT NULL DEFAULT '',
                email               TEXT NOT NULL DEFAULT '',
                active              INTEGER NOT NULL DEFAULT 1,
                created_at          TEXT NOT NULL DEFAULT '',
                last_login          TEXT,
                auth_source         TEXT NOT NULL DEFAULT 'local',
                mfa_enabled         INTEGER NOT NULL DEFAULT 0,
                totp_secret         TEXT,
                totp_pending_secret TEXT,
                failed_login_count  INTEGER NOT NULL DEFAULT 0,
                locked_until        TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE api_tokens (
                id          TEXT PRIMARY KEY,
                hash        TEXT UNIQUE NOT NULL,
                name        TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'reader',
                created_by  TEXT NOT NULL DEFAULT '',
                created_at  TEXT NOT NULL,
                expires_at  TEXT,
                last_used   TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE revoked_tokens (
                jti         TEXT PRIMARY KEY,
                username    TEXT NOT NULL,
                revoked_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            )
        """))
        c.execute(_t("""
            CREATE TABLE manifests (
                name              TEXT NOT NULL,
                version           TEXT NOT NULL,
                arch              TEXT NOT NULL DEFAULT 'amd64',
                distribution      TEXT NOT NULL DEFAULT 'unknown',
                pkg_type          TEXT NOT NULL DEFAULT 'unknown',
                section           TEXT DEFAULT '',
                description       TEXT DEFAULT '',
                maintainer        TEXT DEFAULT '',
                installed_size_kb INTEGER DEFAULT 0,
                file_size_bytes   INTEGER DEFAULT 0,
                filename          TEXT DEFAULT '',
                status            TEXT DEFAULT 'validated',
                imported_by       TEXT DEFAULT 'system',
                imported_at       TEXT DEFAULT '',
                import_method     TEXT DEFAULT 'upload',
                import_group      TEXT,
                sha256            TEXT DEFAULT '',
                sha512            TEXT DEFAULT '',
                gpg_signed        INTEGER DEFAULT 0,
                tags              TEXT DEFAULT '[]',
                dependencies      TEXT DEFAULT '[]',
                validation_steps  TEXT DEFAULT '[]',
                cve_results       TEXT DEFAULT '[]',
                updated_at        TEXT,
                PRIMARY KEY (name, version, arch)
            )
        """))
        c.execute(_t("""
            CREATE TABLE ssh_known_hosts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id   TEXT NOT NULL,
                hostname    TEXT NOT NULL,
                key_type    TEXT,
                fingerprint TEXT,
                trusted_at  TEXT,
                UNIQUE (client_id, hostname)
            )
        """))
        c.execute(_t("""
            CREATE TABLE inventory_clients (
                id              TEXT PRIMARY KEY,
                hostname        TEXT,
                port            INTEGER DEFAULT 22,
                username        TEXT,
                auth_method     TEXT DEFAULT 'key',
                sudo_password   TEXT,
                last_seen       TEXT,
                enabled         INTEGER DEFAULT 1,
                connection_type TEXT DEFAULT 'ssh',
                scan_status     TEXT DEFAULT 'idle',
                last_scan_at    TEXT,
                packages_count  INTEGER DEFAULT 0,
                cve_count       INTEGER DEFAULT 0,
                distro          TEXT,
                agent_token     TEXT,
                notes           TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE inventory_packages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id   TEXT NOT NULL,
                name        TEXT NOT NULL,
                version     TEXT NOT NULL,
                arch        TEXT,
                scanned_at  TEXT NOT NULL
            )
        """))
        c.execute(_t("""
            CREATE TABLE packages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id      TEXT NOT NULL,
                name           TEXT NOT NULL,
                version        TEXT NOT NULL,
                arch           TEXT,
                section        TEXT,
                description    TEXT,
                depends        TEXT,
                provides       TEXT,
                filename       TEXT,
                size           INTEGER,
                sha256         TEXT,
                installed_size INTEGER,
                maintainer     TEXT,
                distro         TEXT,
                security       INTEGER DEFAULT 0,
                summary        TEXT,
                group_name     TEXT,
                license        TEXT,
                url            TEXT,
                rpm_url        TEXT,
                requires       TEXT,
                synced_at      TEXT,
                UNIQUE (source_id, name, version, arch)
            )
        """))
        c.execute(_t("""
            CREATE TABLE sync_status (
                source_id  TEXT PRIMARY KEY,
                label      TEXT,
                last_sync  TEXT,
                pkg_count  INTEGER DEFAULT 0,
                status     TEXT DEFAULT 'never',
                error      TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE sync_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL,
                status    TEXT NOT NULL,
                pkg_count INTEGER DEFAULT 0,
                error     TEXT,
                synced_at TEXT NOT NULL
            )
        """))
        c.execute(_t("""
            CREATE TABLE import_groups (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                name             TEXT UNIQUE NOT NULL,
                package_count    INTEGER DEFAULT 0,
                total_size_bytes INTEGER DEFAULT 0,
                distribution     TEXT,
                imported_by      TEXT,
                imported_at      TEXT NOT NULL
            )
        """))
        c.execute(_t("""
            CREATE TABLE import_group_files (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                group_name TEXT NOT NULL,
                filename   TEXT NOT NULL,
                size_bytes INTEGER DEFAULT 0
            )
        """))
        c.execute(_t("""
            CREATE TABLE apk_packages (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id      TEXT NOT NULL,
                name           TEXT NOT NULL,
                version        TEXT NOT NULL,
                arch           TEXT,
                description    TEXT,
                depends        TEXT,
                provides       TEXT,
                size           INTEGER,
                installed_size INTEGER,
                url            TEXT,
                license        TEXT,
                origin         TEXT,
                distro         TEXT,
                synced_at      TEXT NOT NULL
            )
        """))
        c.execute(_t("""
            CREATE TABLE apk_sync_status (
                source_id  TEXT PRIMARY KEY,
                label      TEXT,
                last_sync  TEXT,
                pkg_count  INTEGER DEFAULT 0,
                status     TEXT DEFAULT 'never',
                error      TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE decision_records (
                id                       TEXT PRIMARY KEY,
                package                  TEXT NOT NULL,
                version                  TEXT NOT NULL,
                arch                     TEXT NOT NULL DEFAULT 'amd64',
                action                   TEXT NOT NULL,
                status                   TEXT NOT NULL,
                justification            TEXT NOT NULL DEFAULT '',
                decided_by               TEXT NOT NULL,
                decided_at               TEXT NOT NULL,
                expires_at               TEXT,
                expires_in_days          INTEGER,
                target_version           TEXT,
                cve_ids                  TEXT NOT NULL DEFAULT '[]',
                assigned_to              TEXT,
                assigned_to_type         TEXT,
                assigned_at              TEXT,
                patch_available_notified INTEGER NOT NULL DEFAULT 0,
                resolved_at              TEXT,
                resolved_by              TEXT,
                resolution_note          TEXT,
                UNIQUE (package, version, arch)
            )
        """))
        c.execute(_t("""
            CREATE TABLE client_decision_records (
                id               TEXT PRIMARY KEY,
                source           TEXT NOT NULL DEFAULT 'compliance',
                package          TEXT NOT NULL,
                version          TEXT NOT NULL,
                arch             TEXT NOT NULL DEFAULT 'x86_64',
                distro_family    TEXT NOT NULL DEFAULT '',
                action           TEXT NOT NULL,
                justification    TEXT NOT NULL DEFAULT '',
                decided_by       TEXT NOT NULL,
                decided_at       TEXT NOT NULL,
                expires_at       TEXT,
                expires_in_days  INTEGER,
                target_version   TEXT,
                cve_ids          TEXT NOT NULL DEFAULT '[]',
                client_ids       TEXT NOT NULL DEFAULT '[]',
                hostnames        TEXT NOT NULL DEFAULT '[]',
                assigned_to      TEXT,
                assigned_to_type TEXT,
                assigned_at      TEXT,
                resolved_at      TEXT,
                resolved_by      TEXT,
                resolve_note     TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE groups (
                id           TEXT PRIMARY KEY,
                name         TEXT UNIQUE NOT NULL,
                description  TEXT NOT NULL DEFAULT '',
                color        TEXT NOT NULL DEFAULT 'blue',
                created_at   TEXT NOT NULL,
                created_by   TEXT NOT NULL,
                default_role TEXT
            )
        """))
        c.execute(_t("""
            CREATE TABLE group_members (
                group_id  TEXT NOT NULL,
                username  TEXT NOT NULL,
                added_at  TEXT NOT NULL,
                added_by  TEXT NOT NULL,
                PRIMARY KEY (group_id, username)
            )
        """))
        c.execute(_t("""
            CREATE TABLE custom_roles (
                id          TEXT PRIMARY KEY,
                name        TEXT UNIQUE NOT NULL,
                label       TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                color       TEXT NOT NULL DEFAULT 'gray',
                is_builtin  INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                created_by  TEXT NOT NULL DEFAULT 'system'
            )
        """))
        c.execute(_t("""
            CREATE TABLE role_permissions (
                role_id    TEXT NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (role_id, permission)
            )
        """))

    old = _engine_mod._engine
    _engine_mod._engine = engine
    yield engine
    _engine_mod._engine = old
    engine.dispose()
