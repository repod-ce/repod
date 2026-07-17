# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_cve_scan_conclusive_status.py
Rôle   : Bug réel observé en production (VM .20, import manuel de
         libf2c2-dev) — la modale CVE de SecurityPage.js affichait
         "Ce paquet a été importé avant la collecte structurée des CVE"
         pour un paquet qui venait tout juste d'être scanné par Grype et
         confirmé sain (0 CVE). Cause : GET /security/packages/{name}/
         {version}/cve calculait has_structured_data = len(cve_results) > 0
         — or un paquet réellement scanné et sain a cve_results == []
         (résultat légitime), rendant "jamais scanné" et "scanné, confirmé
         propre" indiscernables.

         Correctif : services/routers/security_common.py:
         has_conclusive_cve_scan() regarde aussi le message de l'étape de
         validation "cve" — un scan Grype qui a réellement tourné laisse
         toujours une étape "cve" avec un message exploitable ("Grype —
         aucune CVE connue" pour un résultat propre, un résumé de
         sévérités sinon) ; seuls les messages d'échec/skip réels
         (binaire absent, timeout, JSON illisible, code retour inattendu)
         doivent encore déclencher l'invite à ré-importer.

Dépend : pytest uniquement — has_conclusive_cve_scan()/
         _cve_message_is_inconclusive() sont des fonctions pures, pas
         d'accès DB/réseau nécessaire.
"""
from routers.security_common import (
    _cve_message_is_inconclusive,
    has_conclusive_cve_scan,
)


class TestCveMessageIsInconclusive:
    def test_empty_message_is_inconclusive(self):
        assert _cve_message_is_inconclusive("") is True
        assert _cve_message_is_inconclusive(None) is True

    def test_clean_scan_message_is_conclusive(self):
        assert _cve_message_is_inconclusive("Grype — aucune CVE connue") is False

    def test_real_findings_message_is_conclusive(self):
        assert _cve_message_is_inconclusive("Grype — 3 High | 18 Medium | 34 Low | 1 Negligible") is False

    def test_review_required_message_is_conclusive(self):
        assert _cve_message_is_inconclusive(
            "Grype — 2 High · Révision RSSI requise"
        ) is False

    def test_grype_unavailable_is_inconclusive(self):
        assert _cve_message_is_inconclusive("Grype non disponible — scan CVE ignoré") is True

    def test_timeout_is_inconclusive(self):
        assert _cve_message_is_inconclusive("Grype — timeout (> 5 min), scan CVE ignoré") is True

    def test_unreadable_json_is_inconclusive(self):
        assert _cve_message_is_inconclusive("Grype — réponse illisible (avertissement)") is True

    def test_incomplete_scan_is_inconclusive(self):
        assert _cve_message_is_inconclusive("Grype — scan incomplet (avertissement non bloquant)") is True

    def test_unexpected_error_is_inconclusive(self):
        assert _cve_message_is_inconclusive("Grype — erreur inattendue (ignorée)") is True


class TestHasConclusiveCveScan:
    def test_real_cve_results_is_conclusive(self):
        manifest = {"cve_results": [{"id": "CVE-2024-1234", "severity": "High"}], "validation_steps": []}
        assert has_conclusive_cve_scan(manifest) is True

    def test_clean_scan_with_empty_cve_results_is_conclusive(self):
        """Le cas exact du bug : cve_results vide MAIS un vrai scan a tourné."""
        manifest = {
            "cve_results": [],
            "validation_steps": [
                {"name": "checksum", "passed": True, "message": "OK"},
                {"name": "cve", "passed": True, "message": "Grype — aucune CVE connue"},
            ],
        }
        assert has_conclusive_cve_scan(manifest) is True

    def test_never_scanned_package_is_not_conclusive(self):
        """Paquet importé avant l'existence de l'étape 'cve' — aucune
        entrée validation_steps du tout."""
        manifest = {"cve_results": [], "validation_steps": [{"name": "checksum", "passed": True, "message": "OK"}]}
        assert has_conclusive_cve_scan(manifest) is False

    def test_failed_scan_is_not_conclusive(self):
        manifest = {
            "cve_results": [],
            "validation_steps": [
                {"name": "cve", "passed": True, "message": "Grype — timeout (> 5 min), scan CVE ignoré"},
            ],
        }
        assert has_conclusive_cve_scan(manifest) is False

    def test_missing_validation_steps_key_is_not_conclusive(self):
        assert has_conclusive_cve_scan({"cve_results": []}) is False
        assert has_conclusive_cve_scan({}) is False
