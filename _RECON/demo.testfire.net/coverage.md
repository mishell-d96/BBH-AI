# WSTG Coverage — demo.testfire.net

Tracks what was actually tested vs. silently skipped, so thoroughness is provable, not assumed.
Aligned to the OWASP Web Security Testing Guide (latest) 12 categories, mapped to this workspace's skills.

**Status legend:** `[ ]` not started · `[~]` in progress · `[x]` tested · `[N/A]` not applicable (say why) · `[skip]` deliberately skipped (say why)

> Drive testing from `_RECON/demo.testfire.net/phase4_candidates.json` (impact-first). This checklist is the
> safety net that catches categories the impact ranking didn't surface — not a reason to test everything.

| # | WSTG category | Workspace skill(s) | Status | Notes / evidence (link `_EXPLOIT/` or candidate id) |
|---|---------------|--------------------|--------|------------------------------------------------------|
| 1 | Information Gathering | `recon`, `recon-mapper`, `information-disclosure`, `secrets-exposure` | [x] | recon-mapper run; nmap (80/443/8080 Tomcat), ffuf, nuclei. Public swagger spec `/swagger/properties.json` leaks full API incl. admin endpoints; login.jsp HTML comment leaks SiteOps phone. |
| 2 | Configuration & Deployment Mgmt | `information-disclosure`, `secrets-exposure`, `cloud-storage-misconfig`, `subdomain-takeover`, `dependency-confusion` | [~] | Tomcat/Coyote; swagger UI exposed. No backup/.git probing done yet. |
| 3 | Identity Management | `authentication` | [~] | API addUser tested (C3, see below); username enumeration not yet. |
| 4 | Authentication | `authentication`, `jwt`, `oauth`, `saml-sso` | [x] | **C5 CONFIRMED: SQLi auth bypass on POST /api/login** (`admin' or '1'='1` -> 200 + usable token). Token = base64(user:base64(pass):sig) — weak/forgeable, lead. |
| 5 | Authorization | `access-control-idor`, `path-traversal`, `oauth` | [x] | **C1 CONFIRMED: read-BOLA GET /api/account/{accountNo}** (`_EXPLOIT/...BOLA...md`). **C2 CONFIRMED 2026-06-06: read-BOLA GET /api/account/{id}/transactions** (200 + non-owned 800000 history). **Write-BOLA POST /api/transfer CONFIRMED** (money OUT of non-owned acct; auth enforced, ownership not) but **DISCARDED accepted-risk-by-design** (panel `wf_029f73b0-741`) — not logged to `_EXPLOIT/`. See `notes.md`. |
| 6 | Session Management | `csrf`, `jwt` | [ ] | not yet |
| 7 | Input Validation | `sql-injection`, `xss`, `os-command-injection`, `ssti`, `nosql-injection`, `xxe-injection`, `essential-skills` | [~] | SQLi proven on login (C5). search.jsp/feedback.jsp XSS (C8/C9) not yet tested. |
| 8 | Error Handling | `information-disclosure` | [~] | verbose 500s observed (path-traversal attempt); not pursued as standalone (noise). |
| 9 | Weak Cryptography | `deserialization` (padding oracle) | [skip] | API token is base64, not encrypted blob; no deser surface seen. Revisit token-forgery as auth lead. |
| 10 | Business Logic | `business-logic`, `race-conditions`, `file-upload` | [x] | **`/api/transfer` money movement TESTED 2026-06-06**: write-BOLA (debit non-owned account) confirmed; happy-flow + 3-control differential (auth enforced / invalid-source rejected / debit in victim ledger). Accepted-risk-by-design → discarded, not logged. Race-condition on transfer not pursued (by-design demo). |
| 11 | Client-side | `dom-based`, `xss`, `clickjacking`, `cors`, `prototype-pollution`, `open-redirect`, `web-cache-deception`, `web-cache-poisoning`, `websockets` | [ ] | not yet |
| 12 | API | `api-testing`, `graphql`, `web-llm-attacks`, `host-header`, `request-smuggling` | [~] | Full REST API mapped via swagger. C3 admin/addUser: no-token=401 but low-priv jsmith token=200 "success" (broken function-level authz signal) — BUT created user couldn't log in; **contradiction, NOT cleanly proven, held as lead, not reported.** C6 path-traversal index.jsp?content= -> 500, not vulnerable to naive payload. |

## Out-of-scope / not touched
- (list anything explicitly excluded by `scope/`, so it's clear it was intentionally avoided)

## Identities used (see `scope/credentials.md`)
- unauthenticated · user A (low-priv) · user B (low-priv, different tenant) · admin (if provided)
