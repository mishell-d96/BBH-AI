# demo.testfire.net — recon notes & surface map (re-established 2026-06-05)

> Prior recon artifacts were deleted (commit `92e0858`). This re-establishes the MAP-FIRST baseline.
> **Provenance: IBM AltoroJ demo** (Apache-Coyote/Tomcat, REST API 1.0.2). Bare-hostname scope, no RoE →
> **accepted-risk-by-design**: methodology validation only, findings NOT payable. Panel auto-DISCARDs by-design.

## Surface (from homepage + login.jsp scrape)
- **Legacy banking app:** `/login.jsp` → `POST /doLogin` (uid/passw) → `/bank/main.jsp`, `/bank/showAccount?listAccounts=<acct>`, transfer, `/admin/admin.jsp` (Edit Users).
- **REST API:** `/api/login`, `/api/account/{accountNo}`, swagger UI at `/swagger/index.html` (spec JSON endpoints 404 — UI only).
- **Content include sinks:** `/index.jsp?content=`, `/default.jsp?content=` (RequestDispatcher include — path traversal class).
- **Input sinks:** `/search.jsp?query=` (GET), `/sendFeedback` (POST), `subscribe.jsp`, `survey_questions.jsp`, `/feedback.jsp`, `/status_check.jsp`, `cgi.exe`.
- Session cookie `JSESSIONID` (Secure, HttpOnly). Authz cookie `AltoroAccounts` (base64, NOT HttpOnly, client-trusted account list).

## Findings this session (2026-06-05 unauth + 2026-06-07 authenticated)
| # | Candidate | Verdict | Artifact |
|---|-----------|---------|----------|
| 1 | `POST /doLogin` form-login SQLi → **Admin** session + read any account | **CONFIRMED** (executed, differential). Impact honestly scoped: read/visibility yes, admin-write ATO no (see refuted). | `_EXPLOIT/2026-06-05_..._SQLi-formlogin-admin_doLogin.md` |
| 2 | `search.jsp?query=` reflected XSS (raw HTML body, no CSP) | **CONFIRMED** (same class as logged `/sendFeedback` XSS — noted, not re-logged) | this file |
| 3 | `AltoroAccounts` cookie = client-side-trusted authz (tamperable account list) | **CONFIRMED primitive** (folded into finding #1 + skill) | finding #1 |
| 4 | `GET /bank/showAccount?listAccounts=N` legacy-UI BOLA — low-priv jsmith reads any account | **CONFIRMED** (no server-side ownership check; cookie-tamper not even required) | `_EXPLOIT/2026-06-05_..._BOLA_legacy-showAccount.md` |
| 5 | `POST /api/login` **blind boolean SQLi → credential extraction** — recovered admin pw="admin" (Derby, table `people`, boolean oracle, calibrated on jsmith) | **CONFIRMED** (escalates the logged auth-bypass to full credential-store disclosure) | `_EXPLOIT/2026-06-07_..._blindSQLi-cred-extraction_api-login.md` |
| 6 | API `Authorization` token = `base64(base64(user):base64(pass):sig)` — reversibly embeds cleartext password | **CONFIRMED** (jsmith token → `jsmith`/`demo1234`; admin → `admin`/`admin`) | finding #5 (secondary) |
| 7 | `POST /api/transfer` **money-movement BOLA** — no source-account ownership check (form `doTransfer` HAS it; API does not) | **CONFIRMED** (jsmith debits non-owned 800000; 3.59 marker in 800000 ledger; controls 401) | `_EXPLOIT/2026-06-07_..._BOLA_api-transfer-source.md` |

### Full API surface (from `/swagger/properties.json`, basePath `/api`) — saved to `api_spec.json`
`/login` (get,post) · `/account` (get) · `/account/{accountNo}` (get) · `/account/{accountNo}/transactions`
(get,post) · `/transfer` (post — **BOLA #7**) · `/feedback/submit` (post) · `/feedback/{feedbackId}` (get —
requires auth, 500s by int id; no clean IDOR) · `/admin/addUser` (post — inert, see refuted) ·
`/admin/changePassword` (post — inert, see refuted) · `/logout` (get).

### Refuted by side-effect check (canned-200 wins — do NOT report these)
- **admin `changePass` is an INERT STUB.** Returns HTTP 200, but after "changing" jsmith's password the
  **old password still works** and the **new one fails** → password unchanged. A 200 that lied. So the
  doLogin-SQLi→admin chain is **NOT** password-change ATO on this instance.
- **admin `addUser` is INERT.** 200 re-render, but the created user **cannot log in** (302→login.jsp).
- These validate the access-control-idor guardrail: *a 200/success is not a side effect — verify it.*

### Negative results (input-validated / not vulnerable — saves re-testing)
- **`status_check.jsp` / `util/serverStatusCheckService.jsp?HostName=` is NOT SSRF.** Uniform `OK` for
  every input incl. unrouteable/garbage, flat ~0.55–0.69s timing → inert stub (now codified in `ssrf`
  skill "Reality check FIRST").
- **`/bank/queryxpath.jsp?query=` — XPath injection NOT exploitable here.** All metachars (`' " ] * //`)
  return a graceful "News title not found" with **zero exceptions** → input escaped / exceptions swallowed.
- **`/bank/showAccount?listAccounts=` — NOT SQLi.** Integer-cast: `listAccounts=800002'` →
  `java.lang.NumberFormatException` (verbose 500 = info-disclosure noise only).
- **`/bank/doTransfer` enforces source-account ownership.** `fromAccount=800000` (non-owned) →
  "ERROR: Originating account is invalid" → no cross-account fund movement.
- **`/bank/showTransactions` dates NOT SQLi.** `startDate='` AND `startDate=''` *both* 500 with
  `java.sql.SQLException: Date-time query must be in the format yyyy-mm-dd HH:mm:ss` → date-format
  validated before SQL; break/heal differential fails the SQLi hypothesis.
- **`/bank/customize.jsp?content=` did not traverse** to `WEB-INF/web.xml` (the working traversal sink is
  `/index.jsp?content=`, already logged).
- Swagger spec JSON endpoints all 404 (`/api/swagger.json`, `/v2/api-docs`, `/openapi.json`, …) — UI only.

### Search XSS quick repro
```bash
curl -sk -G https://demo.testfire.net/search.jsp --data-urlencode 'query=<svg/onload=alert(1)>'
# -> payload reflects RAW in "No results were found for the query: <svg/onload=alert(1)>" (text/html, no CSP)
```

## Coverage vs prior findings
Already logged previously: API SQLi auth-bypass (`/api/login`), API BOLA (`/api/account/{n}`),
path-traversal→WEB-INF (`/index.jsp?content=`), reflected XSS (`/sendFeedback`).
Added this session: legacy form-login SQLi→admin (closes the API-side "admin not proven" lead),
search.jsp reflected XSS, client-trusted-cookie authz primitive.

## Friction → Iteration-2 improvements (see _TOOLING/beta-retrospective.md)
1. Shell ate XSS metachars inline in URL → false "not reflected". Fix: essential-skills probe-delivery hygiene (`curl -G --data-urlencode`).
2. Nearly false-claimed SSRF on an inert stub. Fix: ssrf "Reality check FIRST" reachability differential.
3. Over-dumped a full transaction history verifying read access. Fix: data-minimization — extract one marker line.
4. zsh `status` read-only var aborted a loop. Fix: noted in essential-skills.
