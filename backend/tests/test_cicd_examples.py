"""
Module : test_cicd_examples.py
Rôle   : P3-D — Exemples CI/CD (GitHub Actions + GitLab CI + script bash)

Vérifie :
  • Les fichiers d'exemple existent dans examples/ci/
  • Les endpoints API repod sont correctement référencés
  • L'authentification passe par des variables d'environnement (pas de secrets en dur)
  • La structure YAML de base est présente (jobs:, steps:, script:…)
  • Le script bash est exécutable et contient les commandes essentielles

Structure testée :
  examples/ci/
    github-upload.yml          → GitHub Actions : upload .deb après build
    github-security-gate.yml   → GitHub Actions : bloquer PR si CVE critique
    gitlab-repod.yml           → GitLab CI : upload + scan
    repod-cli.sh               → Script bash portable (tout CI/CD)
"""

import os
from pathlib import Path

import pytest

# Racine des exemples CI/CD
_EXAMPLES = Path(__file__).parent.parent / "examples" / "ci"


def _read(filename: str) -> str:
    """Lit un fichier exemple (échoue avec AssertionError si absent)."""
    p = _EXAMPLES / filename
    assert p.exists(), f"Fichier manquant : examples/ci/{filename}"
    return p.read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Existence des fichiers
# ═══════════════════════════════════════════════════════════════════════════════

class TestCicdFilesExist:
    """
    ❌ ROUGE avant fix : le dossier examples/ci/ n'existe pas
    ✅ VERT après fix  : tous les fichiers présents
    """

    def test_examples_ci_directory_exists(self):
        """Le dossier examples/ci/ doit exister."""
        assert _EXAMPLES.is_dir(), (
            "Le dossier examples/ci/ doit être créé (P3-D)"
        )

    def test_github_upload_workflow_exists(self):
        """examples/ci/github-upload.yml doit exister."""
        assert (_EXAMPLES / "github-upload.yml").exists()

    def test_github_security_gate_workflow_exists(self):
        """examples/ci/github-security-gate.yml doit exister."""
        assert (_EXAMPLES / "github-security-gate.yml").exists()

    def test_gitlab_template_exists(self):
        """examples/ci/gitlab-repod.yml doit exister."""
        assert (_EXAMPLES / "gitlab-repod.yml").exists()

    def test_cli_script_exists(self):
        """examples/ci/repod-cli.sh doit exister."""
        assert (_EXAMPLES / "repod-cli.sh").exists()


# ═══════════════════════════════════════════════════════════════════════════════
# 2. GitHub Actions : upload workflow
# ═══════════════════════════════════════════════════════════════════════════════

class TestGithubUploadWorkflow:
    """Vérifie le workflow GitHub Actions d'upload de paquets."""

    def test_references_upload_endpoint(self):
        """Le workflow doit appeler POST /api/v1/upload."""
        src = _read("github-upload.yml")
        assert "/api/v1/upload" in src, (
            "github-upload.yml doit référencer l'endpoint POST /api/v1/upload"
        )

    def test_uses_authorization_header(self):
        """L'appel API doit utiliser le header Authorization."""
        src = _read("github-upload.yml")
        assert "Authorization" in src

    def test_no_hardcoded_credentials(self):
        """Aucun mot de passe en clair — seulement des références à des secrets CI."""
        src = _read("github-upload.yml")
        # Ne doit pas avoir de mot de passe en dur
        assert "password:" not in src.lower() or "secrets." in src or "${{" in src

    def test_uses_github_secrets(self):
        """Les secrets sont passés via secrets.* (convention GitHub)."""
        src = _read("github-upload.yml")
        assert "secrets." in src, (
            "Le workflow doit utiliser ${{ secrets.REPOD_* }} pour les credentials"
        )

    def test_github_actions_structure(self):
        """Le fichier a la structure de base GitHub Actions (on: + jobs:)."""
        src = _read("github-upload.yml")
        assert "on:" in src or "on :" in src
        assert "jobs:" in src

    def test_steps_present(self):
        """Le workflow a des étapes (steps:)."""
        src = _read("github-upload.yml")
        assert "steps:" in src

    def test_auth_token_endpoint(self):
        """Le workflow récupère un token JWT via /api/v1/auth/token."""
        src = _read("github-upload.yml")
        assert "/api/v1/auth/token" in src, (
            "Le workflow doit s'authentifier via POST /api/v1/auth/token"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. GitHub Actions : security gate
# ═══════════════════════════════════════════════════════════════════════════════

class TestGithubSecurityGateWorkflow:
    """Vérifie le workflow de blocage sur CVE critique."""

    def test_references_vulnerabilities_endpoint(self):
        """Le workflow doit interroger GET /api/v1/security/vulnerabilities."""
        src = _read("github-security-gate.yml")
        assert "/api/v1/security/vulnerabilities" in src

    def test_has_exit_on_critical(self):
        """Le workflow doit échouer (exit 1) en cas de vulnérabilité critique."""
        src = _read("github-security-gate.yml")
        assert "exit 1" in src or "fail" in src.lower(), (
            "Le security gate doit stopper le pipeline sur CVE critique"
        )

    def test_checks_critical_severity(self):
        """Le workflow inspecte spécifiquement les sévérités Critical."""
        src = _read("github-security-gate.yml")
        assert "Critical" in src or "critical" in src

    def test_uses_authorization_header(self):
        """L'appel API doit être authentifié."""
        src = _read("github-security-gate.yml")
        assert "Authorization" in src

    def test_triggers_on_pr_or_schedule(self):
        """Le gate doit s'exécuter sur PR ou planification."""
        src = _read("github-security-gate.yml")
        assert "pull_request" in src or "schedule" in src

    def test_github_actions_structure(self):
        """Structure GitHub Actions valide."""
        src = _read("github-security-gate.yml")
        assert "on:" in src or "on :" in src
        assert "jobs:" in src


# ═══════════════════════════════════════════════════════════════════════════════
# 5. GitLab CI template
# ═══════════════════════════════════════════════════════════════════════════════

class TestGitlabTemplate:
    """Vérifie le template GitLab CI."""

    def test_references_upload_endpoint(self):
        """Le template doit référencer POST /api/v1/upload."""
        src = _read("gitlab-repod.yml")
        assert "/api/v1/upload" in src

    def test_references_vulnerabilities_endpoint(self):
        """Le template doit interroger GET /api/v1/security/vulnerabilities."""
        src = _read("gitlab-repod.yml")
        assert "/api/v1/security/vulnerabilities" in src

    def test_uses_gitlab_variables(self):
        """Les credentials passent par des variables GitLab CI ($REPOD_*)."""
        src = _read("gitlab-repod.yml")
        assert "$REPOD_" in src or "REPOD_URL" in src

    def test_no_hardcoded_secrets(self):
        """Pas de secret en dur dans le template."""
        src = _read("gitlab-repod.yml")
        # Vérifie qu'il n'y a pas de token ou password littéraux
        import re
        suspicious = re.findall(
            r'(?i)(password|token|secret)\s*[:=]\s*["\'][^$][^"\']{8,}["\']', src
        )
        assert not suspicious, f"Secrets potentiellement en dur : {suspicious}"

    def test_has_script_blocks(self):
        """Le template contient des blocs script:."""
        src = _read("gitlab-repod.yml")
        assert "script:" in src

    def test_has_authentication_step(self):
        """Le template s'authentifie via /api/v1/auth/token."""
        src = _read("gitlab-repod.yml")
        assert "/api/v1/auth/token" in src

    def test_exit_on_critical_vuln(self):
        """Le security gate GitLab échoue sur CVE critique."""
        src = _read("gitlab-repod.yml")
        assert "exit 1" in src or "Critical" in src


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Script CLI bash
# ═══════════════════════════════════════════════════════════════════════════════

class TestCliScript:
    """Vérifie le script bash repod-cli.sh."""

    def test_has_shebang(self):
        """Le script commence par #!/usr/bin/env bash ou #!/bin/bash."""
        src = _read("repod-cli.sh")
        assert src.startswith("#!/"), "repod-cli.sh doit commencer par un shebang"
        assert "bash" in src.splitlines()[0]

    def test_uses_set_euo_pipefail(self):
        """Le script utilise set -euo pipefail pour la sécurité bash."""
        src = _read("repod-cli.sh")
        assert "set -euo pipefail" in src or "set -e" in src

    def test_has_upload_command(self):
        """Le script expose une commande upload."""
        src = _read("repod-cli.sh")
        assert "upload" in src

    def test_has_vulnerabilities_command(self):
        """Le script expose une commande vulnerabilities ou security."""
        src = _read("repod-cli.sh")
        assert "vulnerab" in src.lower() or "security" in src.lower()

    def test_references_api_v1_upload(self):
        """Le script appelle POST /api/v1/upload."""
        src = _read("repod-cli.sh")
        assert "/api/v1/upload" in src

    def test_references_auth_token(self):
        """Le script récupère un JWT via /api/v1/auth/token."""
        src = _read("repod-cli.sh")
        assert "/api/v1/auth/token" in src

    def test_uses_repod_url_variable(self):
        """Le script utilise REPOD_URL comme variable d'environnement."""
        src = _read("repod-cli.sh")
        assert "REPOD_URL" in src

    def test_uses_curl(self):
        """Le script utilise curl pour les appels API."""
        src = _read("repod-cli.sh")
        assert "curl" in src

    def test_has_usage_help(self):
        """Le script affiche une aide (usage ou help)."""
        src = _read("repod-cli.sh")
        assert "usage" in src.lower() or "Usage" in src or "help" in src.lower()
