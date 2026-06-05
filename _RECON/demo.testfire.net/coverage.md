# WSTG Coverage — demo.testfire.net (IBM AltoroJ, accepted-risk-by-design)

Tracks what was actually tested vs. silently skipped. Provenance: intentionally-vulnerable training target
→ methodology validation only, findings not payable. See `notes.md` for the surface map.

**Legend:** `[ ]` not started · `[~]` in progress · `[x]` tested · `[N/A]` not applicable · `[skip]` deliberately skipped (reason)

| # | WSTG category | Status | Notes / evidence |
|---|---------------|--------|------------------|
| 1 | Information Gathering | [x] | Surface mapped (`notes.md`): legacy bank + REST API + swagger UI. Server: Apache-Coyote/Tomcat, AltoroJ. |
| 2 | Configuration & Deployment | [x] | `index.jsp?content=../WEB-INF/web.xml` discloses deployment descriptor (logged Iteration-1 path-traversal). admin interface `/admin/admin.jsp` found. No exposed `.git`. |
| 3 | Identity Management | [~] | `admin` user + low-priv (`jsmith`) confirmed via SQLi. Registration not deeply tested (low value on demo). |
| 4 | Authentication | [x] | **SQLi auth bypass on BOTH `/api/login` (Iter-1) AND `/doLogin`→Admin (Iter-2).** Highest-impact category, fully exercised. |
| 5 | Authorization | [x] | API BOLA `/api/account/{n}` (Iter-1) + **legacy-UI BOLA `/bank/showAccount?listAccounts=N`** (Iter-2, jsmith reads any account); `AltoroAccounts` client-trusted cookie; admin forced-browse gated for anon (302). doTransfer source-ownership ENFORCED (negative). |
| 6 | Session Management | [~] | JSESSIONID Secure+HttpOnly. **API `Authorization` token reversibly embeds cleartext password** (`base64(user):base64(pass):sig`) — credential exposure (finding #6). CSRF/session-fixation deprioritized. |
| 7 | Input Validation | [x] | Reflected XSS `/sendFeedback` + `search.jsp?query=`. SQLi: `/api/login` + `/doLogin`. **Negatives:** queryxpath XPath (exceptions swallowed), listAccounts (int-cast), showTransactions dates (date-validated). |
| 8 | Error Handling | [x] | Verbose SQL/NumberFormat 500 stack traces (info-disclosure noise; used as a signal, not reported). |
| 9 | Weak Cryptography | [N/A] | No crypto-bearing tokens beyond the base64 `AltoroAccounts` blob (covered under Authorization). |
| 10 | Business Logic | [x] | Transfer money-movement DISCARDED Iter-1 (by-design). Iter-2: cross-account transfer BLOCKED (source-ownership enforced); admin `changePass`/`addUser` are **inert stubs** (200 but no side effect — verified, NOT ATO). |
| 11 | Client-side | [~] | Reflected XSS covered (cat 7). No CSP. clickjacking/CORS = low value, deprioritized. |
| 12 | API | [x] | Full surface mapped via `/swagger/properties.json` (saved `api_spec.json`). `/api/login` SQLi (bypass + blind extraction), `/api/account/{n}` BOLA, **`/api/transfer` source-ownership BOLA** (finding #7). `/feedback/{id}` auth-gated (no IDOR); `/admin/*` inert. |

## Deliberately skipped low-value sinks (recorded, not silently dropped)
- `subscribe.jsp`, `survey_questions.jsp` — newsletter/survey; low impact, no sensitive action.
- `cgi.exe` — legacy artifact; no exploitable behavior surfaced.
- `default.jsp?content=` — **same include/traversal class** as the already-logged `index.jsp?content=`; duplicate, not re-tested.
- `status_check.jsp` — confirmed **inert stub, not SSRF** (see `notes.md` negative results).

## Out-of-scope / not touched
- Only `demo.testfire.net` is in scope (`scope/scope.md`). No other host, subdomain, or asset touched.

## Identities used
- unauthenticated baseline · `jsmith` (low-priv) · `admin` (obtained via SQLi, the finding itself — no issued admin creds).
