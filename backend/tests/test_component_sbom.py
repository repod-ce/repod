"""
Module : test_component_sbom.py
Rôle   : services/component_sbom.py — stockage du SBOM CycloneDX capturé
         lors du scan Grype (chemin déterministe, aucune colonne
         PostgreSQL). Couvre le roundtrip save/load, le no-op sur None, et
         le garde-fou de type (un objet inattendu — ex. un MagicMock dans un
         test qui ne configure pas explicitement .sbom — ne doit jamais
         faire planter l'appelant).

Dépend : pytest (pas de DB — ce module ne touche que le filesystem)
"""
from services.component_sbom import (
    load_component_sbom,
    save_component_sbom,
    sbom_path_for,
)


class TestSaveLoadRoundtrip:
    def test_save_then_load_returns_same_content(self, tmp_path, monkeypatch):
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)

        sbom = {"components": [{"name": "curltest", "version": "1.0-1"}]}
        save_component_sbom("curltest", "1.0-1", "amd64", sbom)

        loaded = load_component_sbom("curltest", "1.0-1", "amd64")
        assert loaded == sbom

    def test_path_is_deterministic_from_name_version_arch(self, tmp_path, monkeypatch):
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)
        path1 = sbom_path_for("curltest", "1.0-1", "amd64")
        path2 = sbom_path_for("curltest", "1.0-1", "amd64")
        assert path1 == path2
        assert path1.name.endswith(".cdx.json")


class TestSaveNoOpGuards:
    def test_none_sbom_is_noop(self, tmp_path, monkeypatch):
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)
        save_component_sbom("curltest", "1.0-1", "amd64", None)
        assert load_component_sbom("curltest", "1.0-1", "amd64") is None

    def test_empty_dict_is_noop(self, tmp_path, monkeypatch):
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)
        save_component_sbom("curltest", "1.0-1", "amd64", {})
        assert load_component_sbom("curltest", "1.0-1", "amd64") is None

    def test_non_dict_object_is_ignored_not_raised(self, tmp_path, monkeypatch):
        """Régression réelle (déjà rencontrée côté SaaS) : un MagicMock()
        non configuré (test existant qui ne mocke pas result.sbom) est
        truthy mais n'est pas un dict — json.dumps() sur un tel objet
        lèverait TypeError si on ne vérifie pas le type avant d'écrire."""
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)

        class NotASbom:
            def __bool__(self):
                return True

        save_component_sbom("curltest", "1.0-1", "amd64", NotASbom())
        assert load_component_sbom("curltest", "1.0-1", "amd64") is None


class TestLoadMissing:
    def test_missing_file_returns_none(self, tmp_path, monkeypatch):
        import services.component_sbom as mod
        monkeypatch.setattr(mod, "SBOM_DIR", tmp_path)
        assert load_component_sbom("neverimported", "1.0", "amd64") is None
