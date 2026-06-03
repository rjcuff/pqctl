# Security Policy

## Alpha Software

pqctl is alpha software. Do not use it to protect production secrets yet.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Report privately via [GitHub Security Advisories](https://github.com/rjcuff/pqctl/security/advisories/new) or email **ryan.cuff@icloud.com**.

We aim to respond within 72 hours.

## Scope

- Cryptographic correctness issues (wrong algorithm, broken signing, decryption failures)
- Key material exposure or leakage
- Any issue that could compromise user key files

## Out of Scope

- Issues in upstream libraries (report to [Cloudflare CIRCL](https://github.com/cloudflare/circl) or [spf13/cobra](https://github.com/spf13/cobra))
- Feature requests
