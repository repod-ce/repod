"""
Module : test_webhook.py
Rôle   : P3-C — Webhooks entrants (GitHub Security Advisory + CISA KEV)

Vérifie :
  • Vérification HMAC-SHA256 de la signature entrante
  • Parsing des payloads GitHub Advisory et CISA KEV
  • Mise à jour de in_kev sur les manifests affectés
  • Endpoint router (source inspection)
  • Intégration main.py

Sécurité : signature HMAC-SHA256 (convention GitHub X-Hub-Signature-256).
  Si WEBHOOK_SECRET est vide → les webhooks sont acceptés sans vérification
  (pratique en développement, à documenter).
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_webhook_test_")
os.environ["MANIFEST_DIR"] = _TMP
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("WEBHOOK_SECRET", "test-secret-42")

# ── Imports normaux ────────────────────────────────────────────────────────────
import hashlib
import hmac
import json
from pathlib import Path

import pytest

import services.manifest as _manifest_mod
_manifest_mod.MANIFEST_DIR = Path(_TMP)


# ── Helpers de test ────────────────────────────────────────────────────────────

def _make_signature(body: bytes, secret: str = "test-secret-42") -> str:
    """Génère une signature HMAC-SHA256 au format GitHub (sha256=...)."""
    sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _github_advisory_payload(
    cve_id="CVE-2024-1234",
    severity="high",
    action="published",
    use_identifiers=False,
) -> dict:
    """Payload GitHub security_advisory webhook."""
    advisory: dict = {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Buffer overflow in libssl",
        "severity": severity,
    }
    if use_identifiers:
        advisory["identifiers"] = [{"type": "CVE", "value": cve_id}]
    else:
        advisory["cve_id"] = cve_id
    return {
        "action": action,
        "security_advisory": advisory,
    }


def _kev_payload(
    cve_id="CVE-2024-9999",
    product="nginx",
    vendor="F5",
    date_added="2024-06-01",
) -> dict:
    """Payload CISA KEV (format catalog.json)."""
    return {
        "cveID": cve_id,
        "vendorProject": vendor,
        "product": product,
        "vulnerabilityName": f"vuln in {product}",
        "dateAdded": date_added,
        "shortDescription": "Remote code execution vulnerability",
        "requiredAction": "Apply updates per vendor instructions.",
        "dueDate": "2024-06-21",
    }


def _make_manifest(name="nginx", version="1.24.0", cve_id=None, in_kev=False):
    """Manifest de test avec ou sans CVE."""
    cve_results = []
    if cve_id:
        cve_results = [{
            "id": cve_id,
            "severity": "High",
            "cvss": 7.5,
            "description": "Test",
            "fix_state": "fixed",
            "fix_versions": ["1.24.1"],
            "in_kev": in_kev,
            "urls": [],
        }]
    return {
        "name": name, "version": version, "arch": "amd64",
        "distribution": "jammy",
        "filename": f"{name}_{version}_amd64.deb",
        "description": f"Package {name}",
        "section": "web", "status": "validated",
        "integrity": {"sha256": "abc123", "sha512": "def456"},
        "source": {"imported_at": "2025-01-01T00:00:00+00:00", "import_method": "upload"},
        "cve_results": cve_results,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Module services/webhook.py — existence et imports
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookServiceExists:
    """
    ❌ ROUGE avant fix : services/webhook.py n'existe pas
    ✅ VERT après fix  : module présent avec toutes les fonctions
    """

    def test_webhook_module_exists(self):
        """services/webhook.py doit exister."""
        p = Path(__file__).parent.parent / "services" / "webhook.py"
        assert p.exists(), "services/webhook.py doit être créé (P3-C)"

    def test_verify_signature_importable(self):
        """verify_github_signature() doit être importable."""
        from services.webhook import verify_github_signature
        assert callable(verify_github_signature)

    def test_parse_github_advisory_importable(self):
        """parse_github_advisory() doit être importable."""
        from services.webhook import parse_github_advisory
        assert callable(parse_github_advisory)

    def test_parse_kev_entry_importable(self):
        """parse_kev_entry() doit être importable."""
        from services.webhook import parse_kev_entry
        assert callable(parse_kev_entry)

    def test_update_kev_flag_importable(self):
        """update_kev_flag() doit être importable."""
        from services.webhook import update_kev_flag
        assert callable(update_kev_flag)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Vérification HMAC-SHA256 (verify_github_signature)
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyGithubSignature:
    """Rôle DevOps/Security : vérification rigoureuse de la signature."""

    def test_valid_signature_returns_true(self):
        """Signature HMAC-SHA256 correcte → True."""
        from services.webhook import verify_github_signature
        body = b'{"action": "published"}'
        sig = _make_signature(body, "my-secret")
        assert verify_github_signature(body, sig, "my-secret") is True

    def test_wrong_secret_returns_false(self):
        """Mauvais secret → False (signature invalide)."""
        from services.webhook import verify_github_signature
        body = b'{"action": "published"}'
        sig = _make_signature(body, "correct-secret")
        assert verify_github_signature(body, sig, "wrong-secret") is False

    def test_corrupted_signature_returns_false(self):
        """Signature tronquée/corrompue → False."""
        from services.webhook import verify_github_signature
        body = b'{"action": "published"}'
        assert verify_github_signature(body, "sha256=deadbeef", "my-secret") is False

    def test_missing_sha256_prefix_returns_false(self):
        """Header sans préfixe 'sha256=' → False."""
        from services.webhook import verify_github_signature
        body = b'{"action": "published"}'
        raw_hmac = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        assert verify_github_signature(body, raw_hmac, "secret") is False

    def test_empty_signature_header_returns_false(self):
        """Header vide → False."""
        from services.webhook import verify_github_signature
        assert verify_github_signature(b"body", "", "secret") is False

    def test_uses_timing_safe_comparison(self):
        """
        La vérification doit utiliser hmac.compare_digest (timing-safe)
        pour résister aux attaques par mesure de temps.
        """
        src = (Path(__file__).parent.parent / "services" / "webhook.py").read_text()
        assert "compare_digest" in src, (
            "verify_github_signature doit utiliser hmac.compare_digest (timing-safe)"
        )

    def test_different_body_returns_false(self):
        """Corps modifié (replay attack partiel) → False."""
        from services.webhook import verify_github_signature
        original = b'{"action": "published"}'
        tampered = b'{"action": "deleted"}'
        sig = _make_signature(original, "secret")
        assert verify_github_signature(tampered, sig, "secret") is False

    def test_bytes_body_supported(self):
        """Le corps en bytes bruts (non décodé) doit être supporté."""
        from services.webhook import verify_github_signature
        body = json.dumps({"test": "données spéciales éàü"}).encode("utf-8")
        sig = _make_signature(body, "sec")
        assert verify_github_signature(body, sig, "sec") is True


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Parsing GitHub Advisory (parse_github_advisory)
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseGithubAdvisory:
    """Rôle Developer : vérifie l'extraction des champs CVE depuis GitHub."""

    def test_valid_advisory_returns_dict(self):
        """Payload valide → dict non None."""
        from services.webhook import parse_github_advisory
        result = parse_github_advisory(_github_advisory_payload())
        assert result is not None
        assert isinstance(result, dict)

    def test_cve_id_extracted(self):
        """L'ID CVE doit être dans le résultat."""
        from services.webhook import parse_github_advisory
        result = parse_github_advisory(_github_advisory_payload(cve_id="CVE-2024-5678"))
        assert result["cve_id"] == "CVE-2024-5678"

    def test_cve_id_from_identifiers(self):
        """CVE dans identifiers[] (pas dans cve_id direct) → extrait quand même."""
        from services.webhook import parse_github_advisory
        payload = _github_advisory_payload(cve_id="CVE-2024-IDENT", use_identifiers=True)
        result = parse_github_advisory(payload)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-IDENT"

    def test_missing_cve_returns_none(self):
        """Advisory sans CVE → None (on ne traite pas les GHSA purs)."""
        from services.webhook import parse_github_advisory
        payload = {"action": "published", "security_advisory": {"ghsa_id": "GHSA-xxxx"}}
        assert parse_github_advisory(payload) is None

    def test_severity_preserved(self):
        """La sévérité est préservée dans le résultat."""
        from services.webhook import parse_github_advisory
        result = parse_github_advisory(_github_advisory_payload(severity="critical"))
        assert result["severity"] == "critical"

    def test_action_preserved(self):
        """L'action (published, updated…) est préservée."""
        from services.webhook import parse_github_advisory
        result = parse_github_advisory(_github_advisory_payload(action="updated"))
        assert result["action"] == "updated"

    def test_source_field_is_github(self):
        """Le champ source identifie l'origine GitHub."""
        from services.webhook import parse_github_advisory
        result = parse_github_advisory(_github_advisory_payload())
        assert "github" in result.get("source", "").lower()

    def test_empty_payload_returns_none(self):
        """Payload vide → None."""
        from services.webhook import parse_github_advisory
        assert parse_github_advisory({}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Parsing CISA KEV (parse_kev_entry)
# ═══════════════════════════════════════════════════════════════════════════════

class TestParseKevEntry:
    """Rôle Developer : vérifie l'extraction d'une entrée CISA KEV."""

    def test_valid_kev_returns_dict(self):
        """Entrée KEV valide → dict."""
        from services.webhook import parse_kev_entry
        result = parse_kev_entry(_kev_payload())
        assert result is not None

    def test_cve_id_extracted(self):
        """cveID → cve_id dans le résultat."""
        from services.webhook import parse_kev_entry
        result = parse_kev_entry(_kev_payload(cve_id="CVE-2024-KEV"))
        assert result["cve_id"] == "CVE-2024-KEV"

    def test_missing_cve_id_returns_none(self):
        """Entrée sans cveID → None."""
        from services.webhook import parse_kev_entry
        assert parse_kev_entry({"product": "nginx"}) is None

    def test_vendor_and_product_present(self):
        """vendor et product sont présents dans le résultat."""
        from services.webhook import parse_kev_entry
        result = parse_kev_entry(_kev_payload(vendor="Apache", product="log4j"))
        assert result["vendor"] == "Apache"
        assert result["product"] == "log4j"

    def test_date_added_present(self):
        """dateAdded est mappé vers date_added."""
        from services.webhook import parse_kev_entry
        result = parse_kev_entry(_kev_payload(date_added="2024-12-01"))
        assert result["date_added"] == "2024-12-01"

    def test_source_field_is_cisa_kev(self):
        """Le champ source identifie la CISA KEV."""
        from services.webhook import parse_kev_entry
        result = parse_kev_entry(_kev_payload())
        assert "kev" in result.get("source", "").lower()

    def test_empty_payload_returns_none(self):
        """Payload vide → None."""
        from services.webhook import parse_kev_entry
        assert parse_kev_entry({}) is None


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Mise à jour du flag in_kev sur les manifests (update_kev_flag)
# ═══════════════════════════════════════════════════════════════════════════════

class TestUpdateKevFlag:
    """Rôle Developer : vérifie la propagation du flag KEV sur les manifests."""

    @pytest.fixture(autouse=True)
    def clean_manifests(self):
        """Nettoie les manifests de test avant et après chaque test."""
        from services.manifest import invalidate_manifest_cache
        _manifest_mod.MANIFEST_DIR = Path(_TMP)
        for f in Path(_TMP).glob("*.manifest.json"):
            f.unlink(missing_ok=True)
        invalidate_manifest_cache()
        yield
        for f in Path(_TMP).glob("*.manifest.json"):
            f.unlink(missing_ok=True)
        invalidate_manifest_cache()

    def _save(self, manifest: dict):
        from services.manifest import save_manifest
        save_manifest(manifest)

    def test_matching_cve_sets_in_kev_true(self):
        """
        Paquet avec CVE-2024-KEV → update_kev_flag('CVE-2024-KEV') → in_kev=True.
        """
        from services.webhook import update_kev_flag
        from services.manifest import load_manifest, invalidate_manifest_cache
        m = _make_manifest("nginx", "1.24.0", cve_id="CVE-2024-KEV", in_kev=False)
        self._save(m)
        invalidate_manifest_cache()

        updated = update_kev_flag("CVE-2024-KEV")
        assert updated == 1

        saved = load_manifest("nginx", "1.24.0")
        assert saved is not None
        cve = saved["cve_results"][0]
        assert cve["in_kev"] is True

    def test_non_matching_cve_not_updated(self):
        """Paquet avec CVE-2024-OTHER → update_kev_flag('CVE-2024-KEV') → 0."""
        from services.webhook import update_kev_flag
        from services.manifest import invalidate_manifest_cache
        m = _make_manifest("curl", "7.88.0", cve_id="CVE-2024-OTHER")
        self._save(m)
        invalidate_manifest_cache()

        updated = update_kev_flag("CVE-2024-KEV")
        assert updated == 0

    def test_already_kev_not_double_counted(self):
        """Paquet déjà in_kev=True → update ne le compte pas comme nouveau."""
        from services.webhook import update_kev_flag
        from services.manifest import invalidate_manifest_cache
        m = _make_manifest("openssl", "3.0.0", cve_id="CVE-2024-KNOWN", in_kev=True)
        self._save(m)
        invalidate_manifest_cache()

        updated = update_kev_flag("CVE-2024-KNOWN")
        # Déjà marqué → pas de mise à jour (0 manifests changés)
        assert updated == 0

    def test_multiple_packages_same_cve(self):
        """2 paquets avec la même CVE → 2 manifests mis à jour."""
        from services.webhook import update_kev_flag
        from services.manifest import invalidate_manifest_cache
        m1 = _make_manifest("nginx",  "1.24.0", cve_id="CVE-2024-MULTI")
        m2 = _make_manifest("apache", "2.4.57", cve_id="CVE-2024-MULTI")
        self._save(m1)
        self._save(m2)
        invalidate_manifest_cache()

        updated = update_kev_flag("CVE-2024-MULTI")
        assert updated == 2

    def test_no_manifests_returns_zero(self):
        """Aucun manifest → 0."""
        from services.webhook import update_kev_flag
        assert update_kev_flag("CVE-2024-GHOST") == 0

    def test_returns_int(self):
        """update_kev_flag retourne un entier."""
        from services.webhook import update_kev_flag
        result = update_kev_flag("CVE-2024-NOOP")
        assert isinstance(result, int)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Router — source inspection
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebhookRouterSource:
    """
    ❌ ROUGE avant fix : routers/webhook_router.py n'existe pas
    ✅ VERT après fix  : router présent avec les deux endpoints
    """

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "webhook_router.py"
        return p.read_text()

    def test_webhook_router_file_exists(self):
        """routers/webhook_router.py doit exister."""
        p = Path(__file__).parent.parent / "routers" / "webhook_router.py"
        assert p.exists(), "routers/webhook_router.py doit être créé (P3-C)"

    def test_github_endpoint_present(self):
        """POST /webhooks/github doit être défini."""
        src = self._src()
        assert "/github" in src

    def test_kev_endpoint_present(self):
        """POST /webhooks/kev doit être défini."""
        src = self._src()
        assert "/kev" in src

    def test_signature_verification_used(self):
        """Le router doit appeler verify_github_signature."""
        src = self._src()
        assert "verify_github_signature" in src, (
            "Le router doit vérifier les signatures HMAC (verify_github_signature)"
        )

    def test_no_get_current_user(self):
        """
        Les webhooks s'authentifient par signature HMAC, pas par JWT.
        get_current_user ne doit PAS être importé dans ce router.
        """
        src = self._src()
        assert "get_current_user" not in src, (
            "Les webhooks utilisent la signature HMAC, pas get_current_user"
        )

    def test_update_kev_flag_used_in_kev_endpoint(self):
        """L'endpoint /kev doit appeler update_kev_flag pour propager le flag."""
        src = self._src()
        assert "update_kev_flag" in src, (
            "L'endpoint /kev doit propager le flag KEV sur les manifests"
        )

    def test_audit_log_called(self):
        """Les événements webhook doivent être audités."""
        src = self._src()
        assert "audit" in src.lower() or "log" in src.lower()

    def test_401_on_invalid_signature(self):
        """Le router doit retourner 401 si la signature est invalide."""
        src = self._src()
        assert "401" in src or "Unauthorized" in src or "Invalid" in src


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Intégration main.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestMainWebhookIntegration:
    """webhook_router doit être intégré dans main.py."""

    def test_webhook_router_in_main(self):
        """
        ❌ ROUGE avant fix : webhook_router absent de main.py
        ✅ VERT après fix  : importé et inclus
        """
        src = (Path(__file__).parent.parent / "main.py").read_text()
        assert "webhook_router" in src or "webhook" in src, (
            "main.py doit importer et inclure webhook_router"
        )

    def test_webhook_not_under_api_v1(self):
        """
        Les webhooks ne sont PAS sous /api/v1 (pas un endpoint utilisateur).
        Ils sont directement sur /webhooks/... (accessibles de l'extérieur).
        """
        src = (Path(__file__).parent.parent / "main.py").read_text()
        lines = src.splitlines()
        for line in lines:
            if "webhook_router" in line and "API_V1" in line and "prefix" in line:
                pytest.fail(
                    f"webhook_router ne doit pas utiliser le préfixe API_V1 :\n{line}"
                )
