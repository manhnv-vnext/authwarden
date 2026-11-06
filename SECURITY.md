# Security Policy

## Supported Versions

Only the latest release of AuthWarden is actively supported with security patches.

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

## Reporting a Vulnerability

The AuthWarden team takes security seriously. If you believe you have found a security vulnerability in AuthWarden itself (e.g. false negatives, ReDoS, path traversal, or secret handling issues), please do **NOT** open a public issue.

Instead, please report it via:
- **GitHub Private Vulnerability Reporting**: Go to the [Security tab](https://github.com/manhnv-vnext/authwarden/security/advisories/new) and click **Report a vulnerability**.
- Or contact the maintainers directly via repository issues labeled with `confidential`.

### What to include in your report:
- A clear description of the vulnerability.
- Steps to reproduce or a minimal proof of concept (PoC).
- Potential impact and affected versions.

We will acknowledge receipt of your vulnerability report within 48 hours and provide a remediation timeline.

## Security Guarantees & Philosophy

AuthWarden is engineered with strict defensive security principles:
1. **Zero External Runtime Dependencies**: Immune to npm upstream supply chain attacks.
2. **Zero Telemetry or Data Exfiltration**: Scans run 100% locally. Code never leaves your machine.
3. **Safe Active Secret Verification**: Only performs non-destructive, read-only authentication probes (`GET /v1/user`, `GET /v1/charges?limit=1`). Never modifies account state.
4. **Auto-Redaction by Default**: All discovered secrets are masked in output (`sk_live_51M***...***`) to prevent accidental leaks in terminal logs or CI artifacts.
