# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_arch_disambiguation.py
Rôle   : après l'ajout des sources arm64 (APT)/aarch64 (RPM/APK) — mêmes
         `distro` que leurs équivalents amd64/x86_64, cohérent avec le modèle
         réel où une distribution contient plusieurs architectures — un même
         (name, distro) peut désormais correspondre à plusieurs lignes dans
         `packages`/`apk_packages`. Ces tests couvrent la désambiguïsation
         ajoutée dans package_index_apt.py/package_index_rpm.py/
         package_index_apk.py : préférence amd64/x86_64 par défaut (ORDER BY,
         zéro changement de comportement pour les appelants existants), et
         filtre explicite par `arch` quand fourni.

Dépend : pytest, db_test_engine (fixture autouse, SQLite in-memory —
         tests/conftest.py).
"""
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn


def _insert_apt_package(name, distro, arch, source_id, depends=None):
    with db_conn() as conn:
        conn.execute(text("""
            INSERT INTO packages (source_id, name, version, arch, distro, depends, synced_at)
            VALUES (:source_id, :name, '1.0', :arch, :distro, :depends, :now)
        """), {
            "source_id": source_id, "name": name, "arch": arch, "distro": distro,
            "depends": depends, "now": datetime.now(timezone.utc).isoformat(),
        })


def _insert_rpm_package(name, distro, arch, source_id):
    with db_conn() as conn:
        conn.execute(text("""
            INSERT INTO packages (source_id, name, version, arch, distro, synced_at)
            VALUES (:source_id, :name, '1.0', :arch, :distro, :now)
        """), {
            "source_id": source_id, "name": name, "arch": arch, "distro": distro,
            "now": datetime.now(timezone.utc).isoformat(),
        })


def _insert_apk_package(name, distro, arch, source_id):
    with db_conn() as conn:
        conn.execute(text("""
            INSERT INTO apk_packages (source_id, name, version, arch, distro, synced_at)
            VALUES (:source_id, :name, '1.0', :arch, :distro, :now)
        """), {
            "source_id": source_id, "name": name, "arch": arch, "distro": distro,
            "now": datetime.now(timezone.utc).isoformat(),
        })


class TestAptArchDisambiguation:
    def test_no_arch_filter_prefers_amd64(self, db_test_engine):
        from services.package_index_apt import get_package_info_for_distro

        _insert_apt_package("nginx", "jammy", "arm64", "ubuntu-jammy-arm64")
        _insert_apt_package("nginx", "jammy", "amd64", "ubuntu-jammy")

        row = get_package_info_for_distro("nginx", "jammy")
        assert row["arch"] == "amd64"

    def test_explicit_arm64_filter_returns_arm64_row(self, db_test_engine):
        from services.package_index_apt import get_package_info_for_distro

        _insert_apt_package("nginx", "jammy", "arm64", "ubuntu-jammy-arm64")
        _insert_apt_package("nginx", "jammy", "amd64", "ubuntu-jammy")

        row = get_package_info_for_distro("nginx", "jammy", arch="arm64")
        assert row["arch"] == "arm64"
        assert row["source_id"] == "ubuntu-jammy-arm64"

    def test_get_package_info_arch_filter(self, db_test_engine):
        from services.package_index_apt import get_package_info

        _insert_apt_package("curl", "jammy", "arm64", "ubuntu-jammy-arm64")
        _insert_apt_package("curl", "jammy", "amd64", "ubuntu-jammy")

        assert get_package_info("curl")["arch"] == "amd64"
        assert get_package_info("curl", arch="arm64")["arch"] == "arm64"

    def test_search_packages_arch_filter(self, db_test_engine):
        from services.package_index_apt import search_packages

        _insert_apt_package("libssl-dev", "jammy", "arm64", "ubuntu-jammy-arm64")
        _insert_apt_package("libssl-dev", "jammy", "amd64", "ubuntu-jammy")

        results = search_packages("libssl-dev", arch="arm64")
        assert all(r["arch"] == "arm64" for r in results)
        assert len(results) == 1


class TestRpmArchDisambiguation:
    def test_no_arch_filter_prefers_x86_64(self, db_test_engine):
        from services.package_index_rpm import get_package_info

        _insert_rpm_package("httpd", "almalinux9", "aarch64", "almalinux9-baseos-aarch64")
        _insert_rpm_package("httpd", "almalinux9", "x86_64", "almalinux9-baseos")

        row = get_package_info("httpd", source_prefix="almalinux9")
        assert row["arch"] == "x86_64"

    def test_explicit_aarch64_filter(self, db_test_engine):
        from services.package_index_rpm import get_package_info

        _insert_rpm_package("httpd", "almalinux9", "aarch64", "almalinux9-baseos-aarch64")
        _insert_rpm_package("httpd", "almalinux9", "x86_64", "almalinux9-baseos")

        row = get_package_info("httpd", source_prefix="almalinux9", arch="aarch64")
        assert row["arch"] == "aarch64"
        assert row["source_id"] == "almalinux9-baseos-aarch64"

    def test_search_packages_arch_filter(self, db_test_engine):
        from services.package_index_rpm import search_packages

        _insert_rpm_package("vim", "almalinux9", "aarch64", "almalinux9-baseos-aarch64")
        _insert_rpm_package("vim", "almalinux9", "x86_64", "almalinux9-baseos")

        results = search_packages("vim", arch="aarch64")
        assert all(r["arch"] == "aarch64" for r in results)
        assert len(results) == 1


class TestApkArchDisambiguation:
    def test_no_arch_filter_prefers_x86_64(self, db_test_engine):
        from services.package_index_apk import get_package_info

        _insert_apk_package("busybox", "alpine3.21", "aarch64", "alpine3.21-main-aarch64")
        _insert_apk_package("busybox", "alpine3.21", "x86_64", "alpine3.21-main")

        row = get_package_info("busybox")
        assert row["arch"] == "x86_64"

    def test_explicit_aarch64_filter(self, db_test_engine):
        from services.package_index_apk import get_package_info

        _insert_apk_package("busybox", "alpine3.21", "aarch64", "alpine3.21-main-aarch64")
        _insert_apk_package("busybox", "alpine3.21", "x86_64", "alpine3.21-main")

        row = get_package_info("busybox", arch="aarch64")
        assert row["arch"] == "aarch64"
        assert row["source_id"] == "alpine3.21-main-aarch64"

    def test_search_packages_arch_filter(self, db_test_engine):
        from services.package_index_apk import search_packages

        _insert_apk_package("openssl", "alpine3.21", "aarch64", "alpine3.21-main-aarch64")
        _insert_apk_package("openssl", "alpine3.21", "x86_64", "alpine3.21-main")

        results = search_packages("openssl", arch="aarch64")
        assert all(r["arch"] == "aarch64" for r in results)
        assert len(results) == 1


class TestApkAddPackageArchDerivation:
    """distributions_apk.py:add_package() — bug réel trouvé en ajoutant le
    support arm64 : ni upload.py ni importer_apk.py ne passaient jamais
    `arch`, qui retombait toujours sur x86_64 par défaut. Corrigé pour
    dériver l'arch depuis les métadonnées PKGINFO du fichier lui-même
    quand l'appelant ne la précise pas explicitement."""

    def test_arch_derived_from_pkginfo_when_not_specified(self, tmp_path, monkeypatch):
        import services.distributions_apk as dapk

        monkeypatch.setattr(dapk, "APK_REPO_BASE", tmp_path)
        monkeypatch.setattr(dapk, "parse_apk_metadata", lambda p: {"pkgname": "foo", "pkgver": "1.0", "arch": "aarch64"})
        monkeypatch.setattr(dapk, "build_apkindex", lambda d: 1)

        fake_apk = tmp_path / "foo-1.0.apk"
        fake_apk.write_bytes(b"fake")

        ok, msg = dapk.add_package(fake_apk, "alpine3.21")
        assert ok is True
        assert (tmp_path / "alpine3.21" / "main" / "aarch64" / "foo-1.0.apk").exists()
        assert not (tmp_path / "alpine3.21" / "main" / "x86_64" / "foo-1.0.apk").exists()

    def test_explicit_arch_overrides_metadata(self, tmp_path, monkeypatch):
        import services.distributions_apk as dapk

        monkeypatch.setattr(dapk, "APK_REPO_BASE", tmp_path)
        monkeypatch.setattr(dapk, "parse_apk_metadata", lambda p: {"pkgname": "foo", "pkgver": "1.0", "arch": "aarch64"})
        monkeypatch.setattr(dapk, "build_apkindex", lambda d: 1)

        fake_apk = tmp_path / "foo-1.0.apk"
        fake_apk.write_bytes(b"fake")

        ok, msg = dapk.add_package(fake_apk, "alpine3.21", arch="x86_64")
        assert ok is True
        assert (tmp_path / "alpine3.21" / "main" / "x86_64" / "foo-1.0.apk").exists()


class TestDistributionsConfSelfHeal:
    """routers/distributions_router.py:_distributions_conf_is_complete() —
    doit détecter qu'une distribution déjà présente mais n'ayant pas encore
    "arm64" dans sa ligne Architectures est incomplète, pour qu'un
    déploiement existant (initialisé avant l'ajout du support arm64) se
    répare tout seul au prochain redémarrage plutôt que de rester bloqué en
    amd64-only indéfiniment."""

    def test_amd64_only_conf_is_incomplete(self, tmp_path):
        from routers.distributions_router import _distributions_conf_is_complete

        conf_dir = tmp_path
        (conf_dir / "distributions").write_text(
            "Origin: Repod\nLabel: Ubuntu 22.04 LTS\nCodename: jammy\n"
            "Architectures: amd64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Ubuntu 24.04 LTS\nCodename: noble\n"
            "Architectures: amd64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Ubuntu 20.04 LTS\nCodename: focal\n"
            "Architectures: amd64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Debian 12\nCodename: bookworm\n"
            "Architectures: amd64\nComponents: main\n"
        )
        assert _distributions_conf_is_complete(conf_dir) is False

    def test_amd64_and_arm64_conf_is_complete(self, tmp_path):
        from routers.distributions_router import _distributions_conf_is_complete

        conf_dir = tmp_path
        (conf_dir / "distributions").write_text(
            "Origin: Repod\nLabel: Ubuntu 22.04 LTS\nCodename: jammy\n"
            "Architectures: amd64 arm64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Ubuntu 24.04 LTS\nCodename: noble\n"
            "Architectures: amd64 arm64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Ubuntu 20.04 LTS\nCodename: focal\n"
            "Architectures: amd64 arm64\nComponents: main\n\n"
            "Origin: Repod\nLabel: Debian 12\nCodename: bookworm\n"
            "Architectures: amd64 arm64\nComponents: main\n"
        )
        assert _distributions_conf_is_complete(conf_dir) is True

    def test_missing_file_is_incomplete(self, tmp_path):
        from routers.distributions_router import _distributions_conf_is_complete
        assert _distributions_conf_is_complete(tmp_path) is False
