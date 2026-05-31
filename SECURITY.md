# Security Policy

## Overview

LegionForge Guardian follows [OWASP SAMM](https://owaspsamm.org/) practices and [LegionForge's Security Roadmap](https://github.com/LegionForge/dev-rig) for supply-chain and application security.

## Reporting Security Issues

If you discover a security vulnerability, please email **jp@legionforge.org** with:
- Description of the vulnerability
- Steps to reproduce (if applicable)
- Your name and contact information (optional)

**Please do not open public GitHub issues for security vulnerabilities.**

## Security Controls

### Phase 1: Supply Chain Hardening (v0.1.2+)

#### 1.1 Action Pinning & Dependency Automation

- ✅ All GitHub Actions pinned to commit SHAs (no mutable tags like `@v4` or `@main`)
- ✅ Dependabot configured to auto-update action references weekly
- ✅ Dependency updates require review before merging

**Files**: `.github/dependabot.yml`, `.github/workflows/*.yml`

#### 1.2 Least-Privilege Permissions

- ✅ No `GITHUB_TOKEN` default permission escalation
- ✅ Each workflow declares minimal required permissions
- ✅ `security-events: write` only on workflows uploading security reports

**Permissions by workflow:**
- `ci.yml`: Delegates to dev-rig reusable workflows
- `dast.yml`: `security-events: write` (SARIF upload)
- `publish.yml`: `contents: read` (build), `id-token: write` (OIDC), `attestations: write` (SLSA)
- `lint-workflows.yml`: `contents: read`

#### 1.3 Workflow Security Linting

- ✅ zizmor scans all workflows for OWASP CI/CD Top 10 risks
- ✅ Automated checks for:
  - Unpinned action references
  - Template injection vulnerabilities
  - Dangerous event triggers
  - Excessive GITHUB_TOKEN permissions

**File**: `.github/workflows/lint-workflows.yml`

#### 1.4 Egress Control & Runtime Hardening

- ✅ harden-runner enabled on all Guardian-controlled jobs
- ✅ Restricts outbound network to whitelisted endpoints
- ✅ Prevents exfiltration post-compromise

**Egress policy**: `audit` (logs violations, doesn't fail builds in v0.1.2)

**Allowed endpoints by workflow**:
- All workflows: `github.com:443`, `api.github.com:443`
- DAST: ↑ (scanning localhost)
- Publish: ↑ + `pypi.org:443`, `upload.pypi.org:443`

### Phase 2: OWASP Top 10 Testing

- ✅ **SAST** (Static): semgrep (p/python, p/fastapi) + CodeQL for injection/access control
- ✅ **DAST** (Dynamic): OWASP ZAP baseline scan for runtime auth/headers/session issues
- ✅ **Dependency Audit**: pip-audit for vulnerable packages
- ✅ **Secret Scanning**: gitleaks prevents credential commits
- ✅ **SBOM**: Cyclonedx for supply-chain transparency

### Phase 3: Build Provenance (v0.1.2+)

- ✅ SLSA v1.1 build attestations on all PyPI releases
- ✅ Verifiable supply chain: code → artifact → registry
- ✅ `actions/attest-build-provenance` generates cryptographic proof

## Known Issues & Roadmap

### v0.1.2 (In Progress)
- [ ] Apply Phase 1.5: OSS Risk Audit MVP
- [ ] Upgrade CI coverage threshold: 50% → 70%
- [ ] Document OWASP ZAP findings and remediation

### v0.1.3 (Planned)
- [ ] Escalate harden-runner egress to block mode
- [ ] Phase 2 SOTA (OSV-Scanner, SLSA L2)
- [ ] Hardened Python install (PEP 668)

### v0.2.0+ (Future)
- [ ] Governance policy enforcement
- [ ] Attestation verification on installs

## CI/CD Pipeline

**Trigger**: Push/PR to main

**Jobs**:
1. Lint (dev-rig): ruff, black
2. Test (dev-rig): pytest + coverage
3. SAST (dev-rig): semgrep + CodeQL
4. Audit (dev-rig): pip-audit
5. Secrets (dev-rig): gitleaks
6. SBOM (dev-rig): cyclonedx
7. Lint-Workflows: zizmor
8. DAST: OWASP ZAP

**Publish Trigger**: Git tag `v*`

## References

- [OWASP SAMM](https://owaspsamm.org/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP CI/CD Top 10](https://owasp.org/www-project-ci-cd-security/)
- [SLSA Framework](https://slsa.dev/)
- [zizmor](https://github.com/woodruffw/zizmor)
- [harden-runner](https://github.com/step-security/harden-runner)

## License

MIT. See [LICENSE](LICENSE).
