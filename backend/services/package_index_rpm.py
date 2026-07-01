"""
Index local de métadonnées RPM.

Architecture RPM vs Debian :
  - Debian : Packages.gz par dist/component/arch
  - RPM    : repomd.xml → primary.xml.gz + updateinfo.xml.gz par dépôt

Chaque dépôt RPM est un « repo » indépendant (BaseOS, AppStream, EPEL…).
On télécharge primary.xml.gz pour indexer les paquets disponibles.
On télécharge updateinfo.xml.gz pour indexer les avis de sécurité (CVE/ALSA/RHSA).

Interface compatible avec package_index_apt.py :
  - DEFAULT_SOURCES, sync_source, sync_all, get_sync_status, is_indexed,
    search_packages, get_package_info, init_db
  - Fonctions RPM-uniquement : record_import_group, get_import_groups,
    delete_import_group, resolve_provide_to_package, get_sync_stats
"""
import gzip
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn

# ─── Sources RPM publiques ────────────────────────────────────────────────────
#
# Chaque entrée représente un dépôt RPM indépendant.
# La clé "component" décrit le rôle (baseos, appstream, extras, updates…).
# La clé "security" = True si le repo contient updateinfo.xml.gz avec des CVE.
#
# URLs validées le 2026-05-17.
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SOURCES = [
    # ── AlmaLinux 8 ────────────────────────────────────────────────────────────
    {
        "id": "almalinux8-baseos",
        "label": "AlmaLinux 8 — BaseOS",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "almalinux8-appstream",
        "label": "AlmaLinux 8 — AppStream",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "almalinux8-extras",
        "label": "AlmaLinux 8 — Extras",
        "repomd_url": "https://repo.almalinux.org/almalinux/8/extras/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "extras",
        "security": False,
        "format": "rpm",
    },
    # ── AlmaLinux 9 ────────────────────────────────────────────────────────────
    {
        "id": "almalinux9-baseos",
        "label": "AlmaLinux 9 — BaseOS",
        "repomd_url": "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux9",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "almalinux9-appstream",
        "label": "AlmaLinux 9 — AppStream",
        "repomd_url": "https://repo.almalinux.org/almalinux/9/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux9",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "almalinux9-extras",
        "label": "AlmaLinux 9 — Extras",
        "repomd_url": "https://repo.almalinux.org/almalinux/9/extras/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux9",
        "arch": "x86_64",
        "component": "extras",
        "security": False,
        "format": "rpm",
    },
    # ── AlmaLinux 10 ───────────────────────────────────────────────────────────
    {
        "id": "almalinux10-baseos",
        "label": "AlmaLinux 10 — BaseOS",
        "repomd_url": "https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux10",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "almalinux10-appstream",
        "label": "AlmaLinux 10 — AppStream",
        "repomd_url": "https://repo.almalinux.org/almalinux/10/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "almalinux10",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    # ── Rocky Linux 8 ──────────────────────────────────────────────────────────
    {
        "id": "rocky8-baseos",
        "label": "Rocky Linux 8 — BaseOS",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "rocky8-appstream",
        "label": "Rocky Linux 8 — AppStream",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "rocky8-extras",
        "label": "Rocky Linux 8 — Extras",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/8/extras/x86_64/os/repodata/repomd.xml",
        "distro": "rocky8",
        "arch": "x86_64",
        "component": "extras",
        "security": False,
        "format": "rpm",
    },
    # ── Rocky Linux 9 ──────────────────────────────────────────────────────────
    {
        "id": "rocky9-baseos",
        "label": "Rocky Linux 9 — BaseOS",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "rocky9",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "rocky9-appstream",
        "label": "Rocky Linux 9 — AppStream",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "rocky9",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "rocky9-extras",
        "label": "Rocky Linux 9 — Extras",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/9/extras/x86_64/os/repodata/repomd.xml",
        "distro": "rocky9",
        "arch": "x86_64",
        "component": "extras",
        "security": False,
        "format": "rpm",
    },
    # ── Rocky Linux 10 ─────────────────────────────────────────────────────────
    {
        "id": "rocky10-baseos",
        "label": "Rocky Linux 10 — BaseOS",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "rocky10",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "rocky10-appstream",
        "label": "Rocky Linux 10 — AppStream",
        "repomd_url": "https://dl.rockylinux.org/pub/rocky/10/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "rocky10",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    # ── CentOS Stream 9 ────────────────────────────────────────────────────────
    # CentOS Stream n'a PAS de updateinfo.xml.gz car c'est un rolling release.
    {
        "id": "centos-stream9-baseos",
        "label": "CentOS Stream 9 — BaseOS",
        "repomd_url": "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/repodata/repomd.xml",
        "distro": "centos-stream9",
        "arch": "x86_64",
        "component": "baseos",
        "security": False,
        "format": "rpm",
    },
    {
        "id": "centos-stream9-appstream",
        "label": "CentOS Stream 9 — AppStream",
        "repomd_url": "https://mirror.stream.centos.org/9-stream/AppStream/x86_64/os/repodata/repomd.xml",
        "distro": "centos-stream9",
        "arch": "x86_64",
        "component": "appstream",
        "security": False,
        "format": "rpm",
    },
    # ── Oracle Linux 8 ─────────────────────────────────────────────────────────
    {
        "id": "oraclelinux8-baseos",
        "label": "Oracle Linux 8 — BaseOS",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux8",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "oraclelinux8-appstream",
        "label": "Oracle Linux 8 — AppStream",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL8/appstream/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux8",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    # ── Oracle Linux 9 ─────────────────────────────────────────────────────────
    {
        "id": "oraclelinux9-baseos",
        "label": "Oracle Linux 9 — BaseOS",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux9",
        "arch": "x86_64",
        "component": "baseos",
        "security": True,
        "format": "rpm",
    },
    {
        "id": "oraclelinux9-appstream",
        "label": "Oracle Linux 9 — AppStream",
        "repomd_url": "https://yum.oracle.com/repo/OracleLinux/OL9/appstream/x86_64/repodata/repomd.xml",
        "distro": "oraclelinux9",
        "arch": "x86_64",
        "component": "appstream",
        "security": True,
        "format": "rpm",
    },
    # ── Fedora 42 ──────────────────────────────────────────────────────────────
    {
        "id": "fedora42",
        "label": "Fedora 42 — Everything",
        "repomd_url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/42/Everything/x86_64/os/repodata/repomd.xml",
        "distro": "fedora",
        "arch": "x86_64",
        "component": "everything",
        "security": False,
        "format": "rpm",
    },
    {
        "id": "fedora42-updates",
        "label": "Fedora 42 — Updates",
        "repomd_url": "https://dl.fedoraproject.org/pub/fedora/linux/updates/42/Everything/x86_64/repodata/repomd.xml",
        "distro": "fedora",
        "arch": "x86_64",
        "component": "updates",
        "security": True,
        "format": "rpm",
    },
    # ── EPEL (Extra Packages for Enterprise Linux) ─────────────────────────────
    {
        "id": "epel8",
        "label": "EPEL 8 — Extra Packages",
        "repomd_url": "https://dl.fedoraproject.org/pub/epel/8/Everything/x86_64/repodata/repomd.xml",
        "distro": "almalinux8",
        "arch": "x86_64",
        "component": "epel",
        "security": False,
        "format": "rpm",
    },
    {
        "id": "epel9",
        "label": "EPEL 9 — Extra Packages",
        "repomd_url": "https://dl.fedoraproject.org/pub/epel/9/Everything/x86_64/repodata/repomd.xml",
        "distro": "rocky9",
        "arch": "x86_64",
        "component": "epel",
        "security": False,
        "format": "rpm",
    },
    # ── openSUSE Leap 15.6 ─────────────────────────────────────────────────────
    {
        "id": "opensuse-leap-15.6-oss",
        "label": "openSUSE Leap 15.6 — OSS",
        "repomd_url": "https://download.opensuse.org/distribution/leap/15.6/repo/oss/repodata/repomd.xml",
        "distro": "opensuse-leap-15.6",
        "arch": "x86_64",
        "component": "oss",
        "security": False,
        "format": "rpm",
    },
    {
        "id": "opensuse-leap-15.6-updates",
        "label": "openSUSE Leap 15.6 — Updates",
        "repomd_url": "https://download.opensuse.org/update/leap/15.6/oss/repodata/repomd.xml",
        "distro": "opensuse-leap-15.6",
        "arch": "x86_64",
        "component": "updates",
        "security": True,
        "format": "rpm",
    },
    # ── openSUSE Tumbleweed ─────────────────────────────────────────────────────
    {
        "id": "opensuse-tumbleweed-oss",
        "label": "openSUSE Tumbleweed — OSS",
        "repomd_url": "https://download.opensuse.org/tumbleweed/repo/oss/repodata/repomd.xml",
        "distro": "opensuse-tumbleweed",
        "arch": "x86_64",
        "component": "oss",
        "security": True,
        "format": "rpm",
    },
]


def init_db():
    """No-op — le schéma est géré par Alembic (db/tables.py)."""
    pass


# ─── Parsing repomd.xml ───────────────────────────────────────────────────────

def _fetch_metadata_url(repomd_url: str, metadata_type: str = "primary") -> str | None:
    """
    Télécharge repomd.xml et extrait l'URL d'un fichier de métadonnées.
    """
    try:
        req = urllib.request.Request(repomd_url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            repomd_data = resp.read()
    except Exception:
        return None

    try:
        tree = ET.fromstring(repomd_data)
        ns = {"r": "http://linux.duke.edu/metadata/repo"}
        for data in tree.findall("r:data", ns):
            if data.get("type") == metadata_type:
                loc = data.find("r:location", ns)
                if loc is not None:
                    href = loc.get("href", "").lstrip("/")
                    base = repomd_url.rsplit("/repodata/", 1)[0]
                    return f"{base}/{href}"
    except Exception:
        pass
    return None


def _fetch_primary_xml_url(repomd_url: str) -> str | None:
    return _fetch_metadata_url(repomd_url, "primary")


def _fetch_updateinfo_xml_url(repomd_url: str) -> str | None:
    return _fetch_metadata_url(repomd_url, "updateinfo")


# ─── Parsing primary.xml.gz ───────────────────────────────────────────────────

def _parse_package_elem(pkg, ns_common: str, ns_rpm: str) -> dict | None:
    """Extrait les métadonnées d'un élément <package> primary.xml."""
    ns = {"p": ns_common, "rpm": ns_rpm}
    name_el    = pkg.find("p:name", ns)
    version_el = pkg.find("p:version", ns)
    if name_el is None or version_el is None:
        return None

    arch_el     = pkg.find("p:arch", ns)
    summary_el  = pkg.find("p:summary", ns)
    desc_el     = pkg.find("p:description", ns)
    url_el      = pkg.find("p:url", ns)
    location_el = pkg.find("p:location", ns)
    size_el     = pkg.find("p:size", ns)
    checksum_el = pkg.find("p:checksum", ns)
    group_el    = pkg.find("p:format/p:group", ns)

    ver   = version_el.get("ver", "")
    rel   = version_el.get("rel", "")
    epoch = version_el.get("epoch", "0")
    version = f"{ver}-{rel}" if rel else ver
    if epoch and epoch != "0":
        version = f"{epoch}:{version}"

    rpm_url = location_el.get("href", "") if location_el is not None else ""

    sha256 = ""
    if checksum_el is not None and checksum_el.get("type", "") in ("sha256", "sha"):
        sha256 = checksum_el.text or ""

    installed_size = 0
    if size_el is not None:
        try:
            installed_size = int(size_el.get("installed", 0))
        except (ValueError, TypeError):
            pass

    requires_els = pkg.findall("p:format/rpm:requires/rpm:entry", ns)
    requires = ",".join(
        el.get("name", "")
        for el in requires_els
        if el.get("name")
        and not el.get("name", "").startswith("rpmlib(")
    )

    provides_els = pkg.findall("p:format/rpm:provides/rpm:entry", ns)
    provides = ",".join(
        el.get("name", "")
        for el in provides_els
        if el.get("name")
    )

    return {
        "name":        name_el.text or "",
        "version":     version,
        "arch":        arch_el.text if arch_el is not None else "x86_64",
        "summary":     summary_el.text if summary_el is not None else "",
        "description": desc_el.text if desc_el is not None else "",
        "group_name":  group_el.text if group_el is not None else "",
        "size":        installed_size,
        "url":         url_el.text if url_el is not None else "",
        "rpm_url":     rpm_url,
        "sha256":      sha256,
        "requires":    requires,
        "provides":    provides,
    }


def _open_streaming_decompressor(response, url: str):
    """
    Retourne un objet fichier décompressant à la volée depuis une réponse HTTP.
    Formats supportés : .gz, .xz, .bz2, .zst
    """
    if url.endswith(".gz"):
        import gzip as _gzip
        return _gzip.GzipFile(fileobj=response)
    if url.endswith(".xz"):
        import lzma as _lzma
        class _LzmaStream:
            def __init__(self, src):
                self._dec = _lzma.LZMADecompressor()
                self._src = src
                self._buf = b""
            def read(self, n=-1):
                while len(self._buf) < (n if n > 0 else 1):
                    chunk = self._src.read(65536)
                    if not chunk:
                        break
                    self._buf += self._dec.decompress(chunk)
                if n < 0:
                    out, self._buf = self._buf, b""
                else:
                    out, self._buf = self._buf[:n], self._buf[n:]
                return out
        return _LzmaStream(response)
    if url.endswith(".bz2"):
        import bz2 as _bz2
        class _Bz2Stream:
            def __init__(self, src):
                self._dec = _bz2.BZ2Decompressor()
                self._src = src
                self._buf = b""
            def read(self, n=-1):
                while len(self._buf) < (n if n > 0 else 1):
                    chunk = self._src.read(65536)
                    if not chunk:
                        break
                    self._buf += self._dec.decompress(chunk)
                if n < 0:
                    out, self._buf = self._buf, b""
                else:
                    out, self._buf = self._buf[:n], self._buf[n:]
                return out
        return _Bz2Stream(response)
    if url.endswith(".zst"):
        try:
            import zstandard as _zstd
            dctx = _zstd.ZstdDecompressor()
            return dctx.stream_reader(response)
        except ImportError:
            pass
    return response


def _stream_download_and_parse(url: str, source_id: str, distro: str = "",
                               batch_size: int = 500, timeout: int = 300,
                               stop_event=None) -> int:
    """
    Pipeline streaming : télécharge, décompresse et parse primary.xml.

    IMPORTANT : le verrou SQLite (_lock) n'est PAS tenu pendant le téléchargement.
    Il est acquis brièvement (< 100 ms) pour chaque flush de 500 paquets seulement.
    Cela évite de bloquer les syncs APT/APK simultanées.

    stop_event : threading.Event optionnel — si set(), l'opération est annulée
    proprement (retourne -2 au lieu de -1).

    Retourne le nombre de paquets insérés, -1 en cas d'erreur, -2 si annulé.
    Supporte les très grands primary.xml (Oracle Linux 8 ≈ 600 MB XML décompressé).
    """
    ns_common = "http://linux.duke.edu/metadata/common"
    ns_rpm    = "http://linux.duke.edu/metadata/rpm"
    pkg_tag   = f"{{{ns_common}}}package"
    now       = datetime.now(timezone.utc).isoformat()
    total     = 0
    batch: list[dict] = []
    first_batch = True

    def _flush_to_db(pkgs: list, clear_table: bool) -> None:
        nonlocal total
        with db_conn() as conn:
            if clear_table:
                conn.execute(text("DELETE FROM packages WHERE source_id = :source_id"), {"source_id": source_id})
            if pkgs:
                conn.execute(text("""
                    INSERT INTO packages
                    (source_id, name, version, arch, summary, description, group_name,
                     size, url, rpm_url, sha256, requires, provides, distro, synced_at)
                    VALUES
                    (:source_id, :name, :version, :arch, :summary, :description, :group_name,
                     :size, :url, :rpm_url, :sha256, :requires, :provides, :distro, :synced_at)
                    ON CONFLICT (source_id, name, version, arch) DO UPDATE SET
                        summary = EXCLUDED.summary,
                        description = EXCLUDED.description,
                        group_name = EXCLUDED.group_name,
                        size = EXCLUDED.size,
                        url = EXCLUDED.url,
                        rpm_url = EXCLUDED.rpm_url,
                        sha256 = EXCLUDED.sha256,
                        requires = EXCLUDED.requires,
                        provides = EXCLUDED.provides,
                        distro = EXCLUDED.distro,
                        synced_at = EXCLUDED.synced_at
                """), pkgs)
            total += len(pkgs)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "RPM-Repo-Manager/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as raw_resp:
            xml_stream = _open_streaming_decompressor(raw_resp, url)
            context = ET.iterparse(xml_stream, events=("start", "end"))
            root = None
            for event, elem in context:
                if stop_event is not None and stop_event.is_set():
                    return -2

                if event == "start" and root is None:
                    root = elem
                    continue
                if event != "end" or elem.tag != pkg_tag:
                    continue
                try:
                    pkg = _parse_package_elem(elem, ns_common, ns_rpm)
                    if pkg:
                        batch.append({
                            "source_id": source_id, "name": pkg["name"],
                            "version": pkg["version"], "arch": pkg["arch"],
                            "summary": pkg["summary"], "description": pkg["description"],
                            "group_name": pkg["group_name"], "size": pkg["size"],
                            "url": pkg["url"], "rpm_url": pkg["rpm_url"],
                            "sha256": pkg["sha256"], "requires": pkg["requires"],
                            "provides": pkg.get("provides", ""), "distro": distro,
                            "synced_at": now,
                        })
                except Exception:
                    pass

                if root is not None:
                    root.clear()

                if len(batch) >= batch_size:
                    _flush_to_db(batch, clear_table=first_batch)
                    batch = []
                    first_batch = False

            if batch or first_batch:
                _flush_to_db(batch, clear_table=first_batch)

    except Exception as exc:
        import logging as _log
        _log.getLogger("package_index").error(
            f"[_stream_download_and_parse] {source_id}: {type(exc).__name__}: {exc}"
        )
        return -1

    return total


# ─── Synchronisation d'une source ────────────────────────────────────────────

def sync_source(source: dict, stop_event=None) -> dict:
    """
    Synchronise une source RPM dans l'index PostgreSQL.

    stop_event : threading.Event optionnel — si set(), annule l'opération en cours.

    Processus :
      1. Télécharger repomd.xml → URL de primary.xml
      2. Télécharger en streaming + décompresser à la volée
      3. Parser avec iterparse ; commits rapides par batch
    """
    source_id  = source["id"]
    repomd_url = source.get("repomd_url", "")

    if stop_event is not None and stop_event.is_set():
        return {"source_id": source_id, "status": "cancelled", "error": "Annulé"}

    primary_url = _fetch_primary_xml_url(repomd_url)
    if not primary_url:
        err = f"Impossible de localiser primary.xml dans repomd.xml ({repomd_url})"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    pkg_count = _stream_download_and_parse(primary_url, source_id, distro=source.get("distro", ""), stop_event=stop_event)

    if pkg_count == -2:
        return {"source_id": source_id, "status": "cancelled", "error": "Annulé"}

    if pkg_count < 0:
        err = f"Téléchargement ou parsing de primary.xml échoué ({primary_url})"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    if pkg_count == 0:
        err = "Aucun paquet parsé depuis primary.xml"
        _log_sync(source_id, "error", 0, err)
        return {"source_id": source_id, "status": "error", "error": err}

    _log_sync(source_id, "ok", pkg_count, None)

    return {
        "source_id": source_id,
        "status":    "ok",
        "pkg_count": pkg_count,
        "label":     source.get("label", source_id),
    }


def sync_all() -> list[dict]:
    """Synchronise toutes les sources RPM configurées."""
    results = []
    for source in DEFAULT_SOURCES:
        results.append(sync_source(source))
    return results


def _log_sync(source_id: str, status: str, pkg_count: int, error: str | None,
              conn=None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    params = {"source_id": source_id, "status": status, "pkg_count": pkg_count, "error": error, "synced_at": now}
    if conn:
        conn.execute(text(
            "INSERT INTO sync_log (source_id, status, pkg_count, error, synced_at) VALUES (:source_id, :status, :pkg_count, :error, :synced_at)"
        ), params)
    else:
        with db_conn() as c:
            c.execute(text(
                "INSERT INTO sync_log (source_id, status, pkg_count, error, synced_at) VALUES (:source_id, :status, :pkg_count, :error, :synced_at)"
            ), params)


# ─── Recherche dans l'index ───────────────────────────────────────────────────

def get_package_info(name: str, source_id: str = None, source_prefix: str = None) -> dict | None:
    """Cherche un paquet par nom exact dans l'index local.

    source_prefix : si fourni, filtre les sources dont l'ID commence par ce préfixe
    (ex. "almalinux9" → cherche dans almalinux9-baseos, almalinux9-appstream, etc.).
    Utile pour cibler la bonne distribution sans connaître le nom complet de la source.
    """
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT * FROM packages
            WHERE name = :name
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:source_prefix IS NULL OR source_id LIKE :source_prefix_like)
            ORDER BY CASE WHEN arch = 'x86_64' THEN 0 ELSE 1 END, synced_at DESC
            LIMIT 1
        """), {
            "name": name,
            "source_id": source_id,
            "source_prefix": source_prefix,
            "source_prefix_like": f"{source_prefix}%" if source_prefix else None,
        }).mappings().fetchone()
    return {**dict(row), "format": "rpm"} if row else None


def resolve_provide_to_package(provide: str) -> dict | None:
    """
    Résout une capability RPM (provide) vers le paquet qui la fournit.
    Ex: 'libc.so.6(GLIBC_2.34)(64bit)' → {name: 'glibc', ...}
    """
    pkg = get_package_info(provide)
    if pkg:
        return pkg
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT * FROM packages
            WHERE LOWER(provides) LIKE LOWER(:pat)
            ORDER BY CASE WHEN arch = 'x86_64' THEN 0 ELSE 1 END, synced_at DESC
            LIMIT 1
        """), {"pat": f"%{provide}%"}).mappings().fetchone()
    return dict(row) if row else None


def list_packages_by_source(source_id: str, limit: int = 1000, offset: int = 0) -> list[dict]:
    """
    Retourne tous les paquets indexés pour une source donnée, paginés.
    Utilisé par le mirroir planifié pour itérer sur l'ensemble du dépôt upstream.
    """
    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT * FROM packages
            WHERE source_id = :source_id
            ORDER BY name ASC
            LIMIT :limit OFFSET :offset
        """), {"source_id": source_id, "limit": limit, "offset": offset}).mappings().fetchall()
    return [{**dict(r), "format": "rpm"} for r in rows]


def search_packages(query: str, limit: int = 50, source_id: str | None = None, distro: str | None = None) -> list[dict]:
    """Recherche des paquets par nom ou résumé dans l'index local."""
    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT * FROM packages
            WHERE (LOWER(name) LIKE LOWER(:q) OR LOWER(summary) LIKE LOWER(:q))
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:distro IS NULL OR distro LIKE :distro_pattern)
            ORDER BY name LIMIT :limit
        """), {
            "q": f"%{query}%",
            "source_id": source_id,
            "limit": limit,
            "distro": distro,
            "distro_pattern": f"{distro}%" if distro else None,
        }).mappings().fetchall()
    return [{**dict(r), "format": "rpm"} for r in rows]


# ─── Statistiques de synchronisation ─────────────────────────────────────────

def get_sync_stats() -> list[dict]:
    """
    Retourne l'état de synchronisation de chaque source.
    Format enrichi avec id, distro, arch, component.
    """
    result = []
    with db_conn() as conn:
        for source in DEFAULT_SOURCES:
            sid = source["id"]
            row = conn.execute(text("""
                SELECT pkg_count, synced_at, status, error
                FROM sync_log WHERE source_id = :source_id
                ORDER BY id DESC LIMIT 1
            """), {"source_id": sid}).mappings().fetchone()
            result.append({
                "id":        sid,
                "source_id": sid,
                "label":     source.get("label", sid),
                "distro":    source.get("distro", ""),
                "arch":      source.get("arch", "x86_64"),
                "component": source.get("component", ""),
                "security":  source.get("security", False),
                "pkg_count": row["pkg_count"] if row else 0,
                "last_sync": row["synced_at"] if row else None,
                "status":    row["status"] if row else "never",
                "error":     row["error"] if row else None,
            })
    return result


def get_sync_status() -> list[dict]:
    """Alias de get_sync_stats() — interface compatible avec package_index_apt."""
    return get_sync_stats()


def is_indexed() -> bool:
    """Retourne True si l'index contient au moins un paquet RPM."""
    try:
        with db_conn() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM packages WHERE source_id IS NOT NULL")).scalar()
        return (count or 0) > 0
    except Exception:
        return False


# ─── Groupes d'import ────────────────────────────────────────────────────────

def record_import_group(
    name: str,
    files: list[dict],
    distribution: str,
    imported_by: str,
) -> None:
    """
    Enregistre un groupe d'import (ensemble de .rpm téléchargés ensemble).
    files = [{"filename": "nginx-1.24.rpm", "size_bytes": 1234567}, …]
    """
    total_size = sum(f.get("size_bytes", 0) for f in files)
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(text("""
            INSERT INTO import_groups
            (name, package_count, total_size_bytes, distribution, imported_by, imported_at)
            VALUES (:name, :package_count, :total_size_bytes, :distribution, :imported_by, :imported_at)
            ON CONFLICT (name) DO UPDATE SET
                package_count = EXCLUDED.package_count,
                total_size_bytes = EXCLUDED.total_size_bytes,
                distribution = EXCLUDED.distribution,
                imported_by = EXCLUDED.imported_by,
                imported_at = EXCLUDED.imported_at
        """), {
            "name": name, "package_count": len(files), "total_size_bytes": total_size,
            "distribution": distribution, "imported_by": imported_by, "imported_at": now,
        })
        conn.execute(text("DELETE FROM import_group_files WHERE group_name = :name"), {"name": name})
        if files:
            conn.execute(text(
                "INSERT INTO import_group_files (group_name, filename, size_bytes) VALUES (:group_name, :filename, :size_bytes)"
            ), [{"group_name": name, "filename": f["filename"], "size_bytes": f.get("size_bytes", 0)} for f in files])


def get_import_groups() -> list[dict]:
    """Retourne tous les groupes d'import avec leurs fichiers."""
    with db_conn() as conn:
        groups = conn.execute(text("SELECT * FROM import_groups ORDER BY imported_at DESC")).mappings().fetchall()
        result = []
        for g in groups:
            files = conn.execute(text(
                "SELECT filename, size_bytes FROM import_group_files WHERE group_name = :name"
            ), {"name": g["name"]}).mappings().fetchall()
            result.append({
                **dict(g),
                "packages": [dict(f) for f in files],
            })
    return result


def delete_import_group(name: str) -> bool:
    """Supprime un groupe d'import (cascade sur les fichiers)."""
    with db_conn() as conn:
        conn.execute(text("DELETE FROM import_group_files WHERE group_name = :name"), {"name": name})
        conn.execute(text("DELETE FROM import_groups WHERE name = :name"), {"name": name})
    return True
