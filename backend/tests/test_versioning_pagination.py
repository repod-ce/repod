"""
Module : test_versioning_pagination.py
Rôle   : P2-1 — Versioning /api/v1/ + Pagination
         Vérifie que tous les routers métier sont enregistrés sous /api/v1,
         que health_router reste sans préfixe, et que les endpoints prioritaires
         retournent le format de pagination standard.

Format attendu :
    {"items": [...], "total": N, "page": 1, "per_page": 50, "pages": P}

Dépend : pytest, services/pagination.py (nouveau)
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_apiv1_test_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")

# ── Imports normaux ────────────────────────────────────────────────────────────
import math
from pathlib import Path

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Source inspection — versioning dans main.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestApiV1PrefixInMain:

    @staticmethod
    def _main_src() -> str:
        p = Path(__file__).parent.parent / "main.py"
        assert p.exists()
        return p.read_text()

    def test_api_v1_prefix_constant_defined(self):
        """
        ❌ ROUGE avant fix : aucune constante /api/v1 dans main.py
        ✅ VERT après fix  : API_V1 = "/api/v1" ou équivalent
        """
        src = self._main_src()
        assert "/api/v1" in src, (
            "main.py doit définir le préfixe /api/v1 pour les routers versionnés"
        )

    def test_packages_router_registered_with_api_v1(self):
        """packages_router inclus avec prefix /api/v1."""
        src = self._main_src()
        # On cherche include_router(packages_router suivi de /api/v1 quelque part
        assert "packages_router" in src
        # Vérifie que la ligne d'inclusion utilise le préfixe
        lines = src.splitlines()
        pkg_lines = [l for l in lines if "packages_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in pkg_lines), (
            f"packages_router doit être inclus avec le préfixe /api/v1, "
            f"trouvé : {pkg_lines}"
        )

    def test_security_router_registered_with_api_v1(self):
        """security_router inclus avec prefix /api/v1."""
        src = self._main_src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "security_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"security_router doit être inclus avec /api/v1 : {lines_}"
        )

    def test_auth_router_registered_with_api_v1(self):
        """auth_router inclus avec prefix /api/v1."""
        src = self._main_src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "auth_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"auth_router doit être inclus avec /api/v1 : {lines_}"
        )

    def test_health_router_not_versioned(self):
        """
        health_router doit rester sans préfixe /api/v1 — c'est un endpoint infra
        consulté par Docker healthcheck, load balancers, etc.
        """
        src = self._main_src()
        lines = src.splitlines()
        health_lines = [l for l in lines if "health_router" in l and "include_router" in l]
        assert health_lines, "health_router doit être enregistré dans main.py"
        # Aucune de ces lignes ne doit mentionner api/v1 ou API_V1
        versioned = [l for l in health_lines if "api/v1" in l or "API_V1" in l]
        assert not versioned, (
            f"health_router ne doit PAS être versionné : {versioned}"
        )

    def test_dashboard_router_registered_with_api_v1(self):
        """dashboard_router inclus avec prefix /api/v1."""
        src = self._main_src()
        lines = src.splitlines()
        lines_ = [l for l in lines if "dashboard_router" in l and "include_router" in l]
        assert any("api/v1" in l or "API_V1" in l for l in lines_), (
            f"dashboard_router doit être inclus avec /api/v1 : {lines_}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# services/pagination.py — utilitaire de pagination
# ═══════════════════════════════════════════════════════════════════════════════

class TestPaginationModule:

    def test_module_exists(self):
        """
        ❌ ROUGE avant fix : services/pagination.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "services" / "pagination.py"
        assert p.exists(), "services/pagination.py doit être créé (P2-1)"

    def test_paginate_importable(self):
        """paginate() doit être importable depuis services.pagination."""
        from services.pagination import paginate
        assert callable(paginate)

    def test_paginate_full_page(self):
        """10 items, page=1, per_page=5 → items[0:5], total=10, pages=2."""
        from services.pagination import paginate
        items = list(range(10))
        result = paginate(items, page=1, per_page=5)
        assert result["items"] == [0, 1, 2, 3, 4]
        assert result["total"] == 10
        assert result["page"] == 1
        assert result["per_page"] == 5
        assert result["pages"] == 2

    def test_paginate_second_page(self):
        """page=2 → items[5:10]."""
        from services.pagination import paginate
        items = list(range(10))
        result = paginate(items, page=2, per_page=5)
        assert result["items"] == [5, 6, 7, 8, 9]
        assert result["page"] == 2

    def test_paginate_last_page_partial(self):
        """7 items, per_page=5, page=2 → 2 items, pages=2."""
        from services.pagination import paginate
        items = list(range(7))
        result = paginate(items, page=2, per_page=5)
        assert result["items"] == [5, 6]
        assert result["total"] == 7
        assert result["pages"] == 2

    def test_paginate_empty_list(self):
        """Liste vide → items=[], total=0, pages=0."""
        from services.pagination import paginate
        result = paginate([], page=1, per_page=50)
        assert result["items"] == []
        assert result["total"] == 0
        assert result["pages"] == 0

    def test_paginate_page_beyond_range(self):
        """Page au-delà du total → items=[], page reflète la demande."""
        from services.pagination import paginate
        items = list(range(3))
        result = paginate(items, page=99, per_page=10)
        assert result["items"] == []
        assert result["total"] == 3
        assert result["page"] == 99

    def test_paginate_default_values(self):
        """Sans page/per_page → page=1, per_page=50 par défaut."""
        from services.pagination import paginate
        items = list(range(5))
        result = paginate(items)
        assert result["page"] == 1
        assert result["per_page"] == 50
        assert result["items"] == items

    def test_paginate_output_keys(self):
        """Les 5 clés obligatoires sont présentes."""
        from services.pagination import paginate
        result = paginate([1, 2, 3], page=1, per_page=10)
        for key in ("items", "total", "page", "per_page", "pages"):
            assert key in result, f"Clé manquante : {key!r}"

    def test_paginate_pages_ceil(self):
        """11 items, per_page=5 → pages=3 (ceil)."""
        from services.pagination import paginate
        result = paginate(list(range(11)), page=1, per_page=5)
        assert result["pages"] == 3


# ═══════════════════════════════════════════════════════════════════════════════
# GET /packages/ — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestPackagesEndpointPaginated:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "packages.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_packages_route(self):
        """
        ❌ ROUGE avant fix : GET /packages/ n'a pas de param page/per_page
        ✅ VERT après fix  : Query param page et per_page présents
        """
        src = self._src()
        assert "page" in src, (
            "routers/packages.py doit accepter un paramètre 'page' (pagination P2-1)"
        )

    def test_per_page_param_in_packages_route(self):
        """per_page Query param présent dans packages.py."""
        src = self._src()
        assert "per_page" in src, (
            "routers/packages.py doit accepter un paramètre 'per_page'"
        )

    def test_paginate_called_in_packages_route(self):
        """paginate() est appelé dans la route GET /packages/."""
        src = self._src()
        assert "paginate" in src, (
            "routers/packages.py doit appeler paginate() depuis services.pagination"
        )

    def test_packages_route_returns_paginated_format(self):
        """
        Vérifie par inspection source que get_packages() appelle paginate()
        et retourne ses résultats directement (format garanti par paginate()).
        """
        src = self._src()
        # paginate() est appelé dans la route
        assert "paginate" in src
        # le retour est le résultat de paginate()
        assert "return paginate(" in src


# ═══════════════════════════════════════════════════════════════════════════════
# GET /security/vulnerabilities — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestVulnerabilitiesEndpointPaginated:

    @staticmethod
    def _src() -> str:
        # get_vulnerabilities vit dans cve_router.py depuis le découpage
        # de security_router.py en sous-routers.
        p = Path(__file__).parent.parent / "routers" / "cve_router.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_vulnerabilities_route(self):
        """GET /security/vulnerabilities doit accepter page et per_page."""
        src = self._src()
        # Cherche dans le voisinage de la fonction get_vulnerabilities
        idx = src.find("def get_vulnerabilities")
        assert idx >= 0
        snippet = src[idx:idx + 400]
        assert "page" in snippet, (
            "get_vulnerabilities doit avoir un paramètre 'page'"
        )

    def test_vulnerabilities_returns_paginated_vulnerabilities(self):
        """
        Vérifie par inspection source que get_vulnerabilities() appelle
        paginate() sur la liste des CVE.
        """
        src = self._src()
        idx = src.find("def get_vulnerabilities")
        # Chercher paginate() dans le corps de la fonction (avant la prochaine def)
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "get_vulnerabilities doit appeler paginate() sur la liste des CVE"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# GET /security/review-queue — format paginé
# ═══════════════════════════════════════════════════════════════════════════════

class TestReviewQueueEndpointPaginated:

    @staticmethod
    def _src() -> str:
        # get_review_queue vit dans cve_router.py depuis le découpage
        # de security_router.py en sous-routers.
        p = Path(__file__).parent.parent / "routers" / "cve_router.py"
        assert p.exists()
        return p.read_text()

    def test_page_param_in_review_queue_route(self):
        """GET /security/review-queue doit accepter page et per_page."""
        src = self._src()
        idx = src.find("def get_review_queue")
        assert idx >= 0
        snippet = src[idx:idx + 400]
        assert "page" in snippet, (
            "get_review_queue doit avoir un paramètre 'page'"
        )

    def test_review_queue_returns_paginated_packages(self):
        """
        Vérifie par inspection source que get_review_queue() appelle
        paginate() sur la file d'attente.
        """
        src = self._src()
        idx = src.find("def get_review_queue")
        next_def = src.find("\ndef ", idx + 1)
        body = src[idx:next_def] if next_def > 0 else src[idx:]
        assert "paginate(" in body, (
            "get_review_queue doit appeler paginate() sur la liste packages"
        )
