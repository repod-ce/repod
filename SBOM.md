# SBOM Summary — repod-apt

Generated: 2026-05-23  
Tool: [Syft](https://github.com/anchore/syft) v1.44.0  
Format: CycloneDX JSON  
Files: see `*.sbom.cdx.json` in this repository

## Backend image (`repod-apt-backend.sbom.cdx.json`)

- **532** named packages (6001 total entries including file paths)

### GPL v2 / Copyleft components

| Name | Version | Note |
|------|---------|------|
| `clamav` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-base` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-daemon` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `clamav-freshclam` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `libclamav12` | 1.4.3+dfsg-1 | Antivirus engine — clamd socket |
| `reprepro` | 5.4.6+really5.3.2-1+deb13u1 | APT repo management — exec |

### Permissive-license highlights

| Name | Version | License | Role |
|------|---------|---------|------|
| `github.com/anchore/grype` | v0.112.0 | Apache 2.0 | CVE scanner |
| `github.com/anchore/syft` | v1.44.0 | Apache 2.0 | SBOM generator |
| `fastapi` | 0.136.1 | MIT | Backend framework |
| `python` | 3.10.20 | PSF | Runtime |

## Frontend image (`repod-apt-frontend.sbom.cdx.json`)

- **72** named packages (1052 total entries including file paths)

### Permissive-license highlights

| Name | Version | License | Role |
|------|---------|---------|------|
| `nginx` | 1.31.1-r1 | BSD | Web server |

---

> GPL v2 components are invoked as **independent processes** (subprocess exec or Unix socket).
> They are not statically or dynamically linked against repod's AGPL-3.0 code.
> Source code is available at the upstream repositories listed in [NOTICES](./NOTICES).