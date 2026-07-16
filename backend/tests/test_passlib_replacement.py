"""
Module : test_passlib_replacement.py
Rôle   : P1-E — Migration passlib → bcrypt direct
         Vérifie que hash_password / verify_password fonctionnent sans passlib,
         que les anciens hashes ($2b$) restent vérifiables, et que la
         dépendance passlib a été retirée du code source.

Dépend : pytest, bcrypt
"""

# ── Env avant tout import d'auth (AUTH_DB_PATH ne doit pas pointer vers /repos) ─
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_auth_test_")
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")
os.environ.setdefault("MANIFEST_DIR",  _TMP)
os.environ.setdefault("POOL_DIR",       _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
from pathlib import Path

import bcrypt
import pytest

from auth.users import hash_password, verify_password


# ═══════════════════════════════════════════════════════════════════════════════
# Source inspection — passlib retiré
# ═══════════════════════════════════════════════════════════════════════════════

class TestPasslibRemoved:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "auth" / "users.py"
        assert p.exists(), "auth/users.py introuvable"
        return p.read_text()

    def test_passlib_not_imported_in_users(self):
        """
        ❌ ROUGE avant fix : from passlib.context import CryptContext présent
        ✅ VERT après fix  : passlib absent du source
        """
        assert "passlib" not in self._src(), (
            "auth/users.py ne doit plus importer passlib — "
            "migrer vers bcrypt direct (P1-E)"
        )

    def test_bcrypt_imported_directly(self):
        """auth/users.py doit importer bcrypt directement."""
        assert "import bcrypt" in self._src(), (
            "auth/users.py doit utiliser 'import bcrypt' directement"
        )

    def test_crypt_context_removed(self):
        """CryptContext ne doit plus apparaître dans le source."""
        assert "CryptContext" not in self._src(), (
            "CryptContext (passlib) ne doit plus être utilisé"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# hash_password — format et unicité
# ═══════════════════════════════════════════════════════════════════════════════

class TestHashPassword:

    def test_returns_bcrypt_hash_prefix(self):
        """
        ❌ ROUGE avant fix : passlib génère $2b$ mais via CryptContext — après
           remplacement on doit toujours obtenir $2b$ (bcrypt native).
        ✅ VERT après fix  : bcrypt.hashpw génère bien $2b$…
        """
        h = hash_password("secret")
        assert h.startswith("$2b$"), (
            f"Le hash doit commencer par '$2b$' (bcrypt), obtenu : {h[:10]!r}"
        )

    def test_returns_string_not_bytes(self):
        """hash_password doit retourner str, pas bytes."""
        h = hash_password("secret")
        assert isinstance(h, str), f"Attendu str, obtenu {type(h)}"

    def test_two_hashes_of_same_password_differ(self):
        """Chaque appel génère un sel distinct → hashes différents."""
        h1 = hash_password("secret")
        h2 = hash_password("secret")
        assert h1 != h2, "Les hashes d'un même mot de passe doivent différer (sel aléatoire)"

    def test_empty_password_hashes_without_error(self):
        """Un mot de passe vide est accepté (bcrypt le supporte jusqu'à 72 chars)."""
        h = hash_password("")
        assert h.startswith("$2b$")

    def test_unicode_password_hashes_without_error(self):
        """Mots de passe unicode (accents, emojis) hashés sans exception."""
        h = hash_password("pässwörD!🔑")
        assert h.startswith("$2b$")


# ═══════════════════════════════════════════════════════════════════════════════
# verify_password — correct / incorrect / backward-compat
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyPassword:

    def test_correct_password_returns_true(self):
        """verify_password(plain, hash_password(plain)) → True."""
        h = hash_password("correct_password")
        assert verify_password("correct_password", h) is True

    def test_wrong_password_returns_false(self):
        """Mauvais mot de passe → False, pas d'exception."""
        h = hash_password("correct_password")
        assert verify_password("wrong_password", h) is False

    def test_returns_bool_not_truthy(self):
        """Le retour doit être un bool strict, pas juste truthy."""
        h = hash_password("pw")
        result = verify_password("pw", h)
        assert result is True
        bad = verify_password("x", h)
        assert bad is False

    def test_backward_compat_with_native_bcrypt_hash(self):
        """
        Hash produit par bcrypt natif ($2b$) doit être vérifiable.
        Simule les hashes existants créés avant la migration.
        """
        # Créer un hash avec bcrypt natif directement (comme passlib le ferait)
        native_hash = bcrypt.hashpw(b"legacy_password", bcrypt.gensalt()).decode()
        assert native_hash.startswith("$2b$")
        assert verify_password("legacy_password", native_hash) is True
        assert verify_password("wrong",           native_hash) is False

    def test_invalid_hash_returns_false_not_exception(self):
        """Un hash malformé ne lève pas d'exception — retourne False."""
        result = verify_password("password", "not_a_valid_bcrypt_hash")
        assert result is False

    def test_unicode_password_verifies_correctly(self):
        """Mot de passe unicode hashé puis vérifié correctement."""
        pw = "pässwörD!🔑"
        h = hash_password(pw)
        assert verify_password(pw, h) is True
        assert verify_password("wrong", h) is False
