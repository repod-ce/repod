"""
Façade format-agnostique pour le pipeline de validation des artefacts.

Dispatche vers validator_apt (.deb), validator_rpm (.rpm) ou validator_apk (.apk)
selon REPO_FORMAT et l'extension du fichier. Tous les imports existants restent
valides sans modification :

    from services.validator import run_validation_pipeline, ValidationResult

Voir :
    services/validator_apt.py — pipeline .deb (format APT)
    services/validator_rpm.py — pipeline .rpm (format RPM)
    services/validator_apk.py — pipeline .apk (format Alpine APK)
"""
from services.format_router import is_rpm as _is_rpm, is_apk as _is_apk, REPO_FORMAT as _REPO_FORMAT

def _is_apk_path(path: str) -> bool:
    return str(path).endswith(".apk")


if _REPO_FORMAT in ("both", "all"):
    # ── Mode BOTH/ALL (.deb + .rpm [+ .apk]) — dispatch par extension ───────
    from services.validator_apt import (                              # noqa: F401
        ValidationResult,
        run_validation_pipeline as _apt_run_pipeline,
        validate_format as _apt_validate_format,
        validate_checksum as _apt_validate_checksum,
        validate_gpg as _apt_validate_gpg,
        validate_provenance_sha256 as _apt_validate_provenance,
        validate_clamav as _apt_validate_clamav,
        validate_cve_grype as _apt_validate_cve,
        validate_dependencies as _apt_validate_deps,
        _resolve_deps_recursive,           # utilisé par routers/artifacts.py (branche _is_apt())
        _extract_cvss,                     # utilisé par tests (inspection interne)
    )
    from services.validator_rpm import (                              # noqa: F401
        run_validation_pipeline as _rpm_run_pipeline,
        validate_format as _rpm_validate_format,
        validate_checksum as _rpm_validate_checksum,
        validate_gpg as _rpm_validate_gpg,
        validate_provenance_sha256 as _rpm_validate_provenance,
        validate_clamav as _rpm_validate_clamav,
        validate_cve_grype as _rpm_validate_cve,
        validate_dependencies as _rpm_validate_deps,
    )
    from services.validator_apk import (                              # noqa: F401
        run_validation_pipeline as _apk_run_pipeline,
    )

    def _is_rpm_path(path: str) -> bool:
        return str(path).endswith(".rpm")

    def run_validation_pipeline(                                      # noqa: E302
        pkg_path: str,
        expected_sha256: str | None = None,
        strict_deps: bool = False,
        distro: str | None = None,
        apk_control_checksum: str | None = None,
    ) -> ValidationResult:
        if _is_apk_path(pkg_path):
            return _apk_run_pipeline(pkg_path, expected_sha256, strict_deps, distro, apk_control_checksum)
        if _is_rpm_path(pkg_path):
            return _rpm_run_pipeline(pkg_path, expected_sha256, strict_deps, distro)
        return _apt_run_pipeline(pkg_path, expected_sha256, strict_deps, distro)

    def validate_format(pkg_path: str, result: ValidationResult):    # noqa: E302
        if _is_rpm_path(pkg_path):
            return _rpm_validate_format(pkg_path, result)
        return _apt_validate_format(pkg_path, result)

    def validate_checksum(pkg_path: str, result: ValidationResult):  # noqa: E302
        if _is_rpm_path(pkg_path):
            return _rpm_validate_checksum(pkg_path, result)
        return _apt_validate_checksum(pkg_path, result)

    def validate_gpg(pkg_path: str, result: ValidationResult):       # noqa: E302
        if _is_rpm_path(pkg_path):
            return _rpm_validate_gpg(pkg_path, result)
        return _apt_validate_gpg(pkg_path, result)

    def validate_provenance_sha256(                                   # noqa: E302
        pkg_path: str, expected_sha256: str | None, result: ValidationResult
    ):
        if _is_rpm_path(pkg_path):
            return _rpm_validate_provenance(pkg_path, expected_sha256, result)
        return _apt_validate_provenance(pkg_path, expected_sha256, result)

    def validate_clamav(pkg_path: str, result: ValidationResult):    # noqa: E302
        if _is_rpm_path(pkg_path):
            return _rpm_validate_clamav(pkg_path, result)
        return _apt_validate_clamav(pkg_path, result)

    def validate_cve_grype(                                           # noqa: E302
        pkg_path: str, result: ValidationResult, distro: str | None = None
    ):
        if _is_rpm_path(pkg_path):
            return _rpm_validate_cve(pkg_path, result, distro)
        return _apt_validate_cve(pkg_path, result, distro)

    def validate_dependencies(pkg_path: str, result: ValidationResult) -> list[dict]:  # noqa: E302
        if _is_rpm_path(pkg_path):
            return _rpm_validate_deps(pkg_path, result)
        return _apt_validate_deps(pkg_path, result)

elif _REPO_FORMAT == "all":
    # ── Mode ALL (.deb + .rpm + .apk) — dispatch par extension ──────────────
    from services.validator_apt import (                              # noqa: F401
        ValidationResult,
        run_validation_pipeline as _apt_run_pipeline,
        validate_format as _apt_validate_format,
        validate_checksum as _apt_validate_checksum,
        validate_gpg as _apt_validate_gpg,
        validate_provenance_sha256 as _apt_validate_provenance,
        validate_clamav as _apt_validate_clamav,
        validate_cve_grype as _apt_validate_cve,
        validate_dependencies as _apt_validate_deps,
        _resolve_deps_recursive,
        _extract_cvss,
    )
    from services.validator_rpm import (                              # noqa: F401
        run_validation_pipeline as _rpm_run_pipeline,
    )
    from services.validator_apk import (                              # noqa: F401
        run_validation_pipeline as _apk_run_pipeline,
    )

    def _is_rpm_path(path: str) -> bool:                             # noqa: E302
        return str(path).endswith(".rpm")

    def run_validation_pipeline(                                      # noqa: E302
        pkg_path: str,
        expected_sha256: str | None = None,
        strict_deps: bool = False,
        distro: str | None = None,
        apk_control_checksum: str | None = None,
    ) -> ValidationResult:
        if _is_apk_path(pkg_path):
            return _apk_run_pipeline(pkg_path, expected_sha256, strict_deps, distro, apk_control_checksum)
        if _is_rpm_path(pkg_path):
            return _rpm_run_pipeline(pkg_path, expected_sha256, strict_deps, distro)
        return _apt_run_pipeline(pkg_path, expected_sha256, strict_deps, distro)

elif _is_rpm():
    # ── Mode RPM (.rpm / createrepo_c) ───────────────────────────────────────
    from services.validator_rpm import (                              # noqa: F401
        ValidationResult,
        run_validation_pipeline,
        validate_format,
        validate_checksum,
        validate_gpg,
        validate_provenance_sha256,
        validate_clamav,
        validate_cve_grype,
        validate_dependencies,
    )

elif _is_apk():
    # ── Mode APK (.apk / APKINDEX Alpine) ────────────────────────────────────
    from services.validator_apt import (                              # noqa: F401
        ValidationResult,
        _extract_cvss,
    )
    from services.validator_apk import (                              # noqa: F401
        run_validation_pipeline,
        validate_format,
        validate_checksum,
        validate_gpg,
        validate_clamav,
        validate_cve_grype,
        validate_dependencies,
    )
    # Stubs pour compat ascendante (appellés par certains routers en mode APT)
    def validate_provenance_sha256(                                   # noqa: E302
        pkg_path: str, expected_sha256: str | None, result: ValidationResult
    ):
        validate_checksum(pkg_path, expected_sha256, result)

    def _resolve_deps_recursive(path: str, max_depth: int = 6) -> list[dict]:  # noqa: E302
        """Stub — résolution récursive non disponible en mode APK."""
        return []

else:
    # ── Mode APT (.deb / reprepro) ────────────────────────────────────────────
    from services.validator_apt import (                              # noqa: F401
        ValidationResult,
        run_validation_pipeline,
        validate_format,
        validate_checksum,
        validate_gpg,
        validate_provenance_sha256,
        validate_clamav,
        validate_cve_grype,
        validate_dependencies,
        _resolve_deps_recursive,           # utilisé par routers/artifacts.py
        _extract_cvss,                     # utilisé par tests (inspection interne)
    )
