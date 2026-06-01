# WSTG Coverage — <target>

Tracks what was actually tested vs. silently skipped, so thoroughness is provable, not assumed.
Aligned to the OWASP Web Security Testing Guide (latest) 12 categories, mapped to this workspace's skills.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` tested · `[N/A]` not applicable (say why) · `[skip]` deliberately skipped (say why)

> Drive testing from `_RECON/<target>/phase4_candidates.json` (impact-first). This checklist is the
> safety net that catches categories the impact ranking didn't surface — not a reason to test everything.

| # | WSTG category | Workspace skill(s) | Status | Notes / evidence (link `_EXPLOIT/` or candidate id) |
|---|---------------|--------------------|--------|------------------------------------------------------|
| 1 | Information Gathering | `recon`, `recon-mapper`, `information-disclosure`, `secrets-exposure` | [ ] | |
| 2 | Configuration & Deployment Mgmt | `information-disclosure`, `secrets-exposure`, `cloud-storage-misconfig`, `subdomain-takeover`, `dependency-confusion` | [ ] | HTTP methods, backup/old files, admin interfaces, exposed `.git` |
| 3 | Identity Management | `authentication` | [ ] | registration, account provisioning, username enumeration |
| 4 | Authentication | `authentication`, `jwt`, `oauth`, `saml-sso` | [ ] | login, reset, MFA/2FA, default creds, lockout |
| 5 | Authorization | `access-control-idor`, `path-traversal`, `oauth` | [ ] | IDOR/BOLA, privilege escalation, forced browsing |
| 6 | Session Management | `csrf`, `jwt` | [ ] | cookie flags, session fixation, logout/timeout, CSRF |
| 7 | Input Validation | `sql-injection`, `xss`, `os-command-injection`, `ssti`, `nosql-injection`, `xxe-injection`, `essential-skills` | [ ] | also LDAP / XPath / CRLF-header-injection (no dedicated skill — test by hand) |
| 8 | Error Handling | `information-disclosure` | [ ] | stack traces, verbose errors (noise unless it leaks/chains) |
| 9 | Weak Cryptography | `deserialization` (padding oracle) | [ ] | usually low-impact/noise; report only if it chains to real impact |
| 10 | Business Logic | `business-logic`, `race-conditions`, `file-upload` | [ ] | workflow skipping, limits, price/qty tampering, upload RCE |
| 11 | Client-side | `dom-based`, `xss`, `clickjacking`, `cors`, `prototype-pollution`, `open-redirect`, `web-cache-deception`, `web-cache-poisoning`, `websockets` | [ ] | DOM XSS, postMessage, CORS, redirect→token theft |
| 12 | API | `api-testing`, `graphql`, `web-llm-attacks`, `host-header`, `request-smuggling` | [ ] | mass assignment, hidden endpoints, method tampering, GraphQL introspection |

## Out-of-scope / not touched
- (list anything explicitly excluded by `scope/`, so it's clear it was intentionally avoided)

## Identities used (see `scope/credentials.md`)
- unauthenticated · user A (low-priv) · user B (low-priv, different tenant) · admin (if provided)
