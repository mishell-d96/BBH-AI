# Target notes — demo.testfire.net (AltoroJ REST API 1.0.2)

Target-specific gotchas captured to make re-testing faster. Generally-applicable lessons go in skills,
not here.

## Provenance / reporting status
- **Intentionally-vulnerable** IBM AltoroJ demo bank. Scope file is a bare hostname, no rules of
  engagement. Per panel `wf_029f73b0-741`: catalogued bugs here are **accepted-risk-by-design — NOT
  payable real-program findings.** Everything below is **methodology validation**, not a submission.

## Auth
- Published low-priv creds: `jsmith / demo1234`. Owns accounts **800002, 800003, 4539082039396288**.
- Token is the `Authorization` value from `POST /api/login` (JSON body). It is **short-lived / rotates** —
  re-capture per request batch; don't reuse a token across slow multi-step scripts (lost auth twice this way).
- Use `jq -r '.Authorization'` to extract — the token contains `+`/`/`/`=`, so a sloppy `sed` can mangle it.
- Helper: `source _RECON/demo.testfire.net/altoro.sh` then `atok`, `aget <path>`, `apost <path> <json>`.

## Data quirks
- Account **balance fields are integer-overflowed** (e.g. `-$1000...0.00`) from years of public abuse —
  **balance before/after is NOT clean proof**. Prove money movement via the **transaction ledger**
  (`GET /api/account/{id}/transactions`) instead, with a **unique marker amount** (e.g. `3.71`).
- Account IDs are **sequential**: 800000–800005 observed live (800000 Corporate, 800001 Checking are
  NOT owned by jsmith — good non-owned targets for BOLA differentials).

## Confirmed (methodology-validated) issues
- **SQLi auth-bypass** `POST /api/login` (username field) → token as any named user. `_EXPLOIT/...SQLi...md`
- **Read-BOLA** `GET /api/account/{id}` and `/{id}/transactions` → any customer's balance/history. `_EXPLOIT/...BOLA...md`
- **Write-BOLA** `POST /api/transfer` → move money OUT of a non-owned account (`fromAccount` ownership not
  checked; auth IS enforced; server resolves the account — invalid id → "Originating account is invalid").
  Technically clean, DISCARDED as accepted-risk-by-design (panel `wf_029f73b0-741`). Not logged to `_EXPLOIT/`.

## Sweep 2026-06-06 (workflow `wf_9b675c91-675`, 8 candidates, each adversarially verified)
All accepted-risk-by-design — methodology validation only, none payable.
- **C6 path traversal `/index.jsp?content=` → CONFIRMED (real).** Naive/encoded `../etc/passwd` → 500 (Jasper NPE); the `content=` sink is a **context-bound `RequestDispatcher`/`jsp:include`**, not raw file read — so `../WEB-INF/web.xml` discloses the deployment descriptor (AuthFilter/AdminFilter/StartupListener class names, `/adimn/*` typo'd admin mapping). Direct `/WEB-INF/web.xml` → 404 (control). `_EXPLOIT/path-traversal_...md`.
- **C8 reflected XSS `/search.jsp?query=` → CONFIRMED (real).** `<script>alert(document.domain)</script>` reflected unencoded at line 103; no CSP/X-CTO. 
- **C9 reflected XSS `POST /sendFeedback` (`name`) → CONFIRMED (real).** Form posts to `/sendFeedback` (not feedback.jsp) fields `name/email_addr/subject/comments/cfile`; JSON API `/api/feedback/submit` fields `name/email/subject/comments`. SQLi refuted (quote reflected, no DB error). `_EXPLOIT/2026-06-05_...reflectedXSS...md`.
- **TOKEN analysis → CONFIRMED (real).** Token = `base64( base64(user) : base64(pass) : sig )`. (1) **Password disclosure** — middle segment base64-decodes to cleartext password. (2) **Signature NOT verified** — empty/absent sig accepted; an attacker can **construct a valid token for another user offline** (`base64("admin":"admin":")` → returned admin's accounts 800000/800001 without ever calling /api/login). user:pass still validated against the store (wrong pass → 401), so it's reversibly-encoded creds + a decorative ignored signature. `admin:admin` is a valid demo cred.
- **C3 `POST /api/admin/addUser` BFLA → REFUTED (impact).** Real authz gap (no-token/garbage-token → 401, jsmith token → 200) but the endpoint is an **inert stub**: "created" users can't authenticate (API 400 / web 302→login.jsp), re-creating the same username never conflicts, role/isAdmin/admin mass-assignment ignored. *Lesson: a 200 "success" is not a side effect — verify the action actually happened.*
- **C4 `POST /api/admin/changePassword` → LEAD (needs effect-proof).** Low-priv token reaches the admin function (BFLA), but it returns `{success}` even for nonexistent users → can't claim ATO without proving the password actually changed on a real target; the verify loop is structurally unclosable here (addUser users aren't authenticatable, jsmith off-limits).
- **C7 `/api/feedback/{id}` IDOR → REFUTED at ids 1,2** (no PII; 500 = no object at that id). *Lesson: object-lookup-returns-empty = "untestable at tested id", not "IDOR refuted" — a populated id may still be vulnerable.*
- **APIGAP (method tampering / content-type confusion / mass-assignment) → no impact** here (by-design); mass-assignment "ignored" only provable by re-deriving identity from the returned token, not the 200.

## Open leads (untested)
- `POST /api/admin/addUser`, `/api/admin/changePassword` — return 200 for low-priv token, but created users
  couldn't subsequently log in → contradictory, function-level-authz lead, not cleanly proven.
- `index.jsp?content=` path-traversal (naive `../` → 500), `search.jsp?query=` reflected XSS,
  `feedback.jsp` stored XSS/SQLi — all by-design on this demo; low priority given provenance.
