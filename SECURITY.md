# Security Policy

## Scope

QPKI is designed for **education and prototyping**. It is not intended for production use without additional security review and hardening.

Issues in the following areas are considered security vulnerabilities:
- Cryptographic implementation flaws
- Private key exposure
- Certificate validation bypasses

Issues that are **not** vulnerabilities:
- Missing features or hardening for production use
- Performance issues
- Documentation gaps

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report vulnerabilities privately via email:
- **Email:** remi.blancher@proton.me
- **Subject:** `[QPKI Security]` followed by a brief description

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact

## Response Timeline

- Acknowledgment within **7 days**
- Initial assessment within **14 days**
- Fix timeline communicated after assessment

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0+    | Yes       |
| < 1.0   | Best effort |
