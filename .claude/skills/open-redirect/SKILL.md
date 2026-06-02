---
name: open-redirect
description: "Open redirects (server-side 302 Location reflection & DOM location sinks) — low alone, a force-multiplier (-> OAuth token theft, SSRF whitelist bypass, CSP). Use for URL-shaped params (redirect/redirect_uri/return/returnUrl/next/url/dest/callback/goto), post-login/logout/SSO redirects."
---

# Open Redirect

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.

## When to test
- Any param whose value is or becomes a URL/path: `redirect`, `redirect_url`, `redirect_uri`, `return`, `returnUrl`, `returnTo`, `next`, `url`, `dest`, `destination`, `continue`, `callback`, `goto`, `out`, `link`, `target`, `image_url`, `u`.
- Response reflects the param into a `Location:` header (3xx) — server-side.
- Client JS reads `location.hash` / `location.search` / `document.referrer` and feeds a navigation sink (`location`, `location.href`, `location.assign()`, `location.replace()`, `window.open()`) — DOM-based.
- Post-login / post-logout redirects, SSO `RelayState`, OAuth `redirect_uri`, link-tracking / interstitial / "leaving site" pages.

## Impact & priority
HONEST: a standalone open redirect is **LOW** severity. Many programs explicitly mark it out of scope or N/A. Its real value is as a **force-multiplier** inside a chain. Triage:
- **High** only when chained (OAuth token/code theft, SSRF filter bypass, CSP/whitelist bypass, auth/token leak).
- **Low / informational** standalone — and only worth a report if the program's policy accepts standalone open redirect. Otherwise chain it or drop it.
Prioritize redirect params that sit inside auth flows (`redirect_uri`, `returnTo`, `RelayState`) — those are the ones that escalate.

## Detection
**Server-side (302 Location reflection):** set the param to a clean attacker domain and watch the `Location` header.
```
curl -sik 'https://target/login?next=https://evil.example' | grep -i '^location:'
# Vulnerable: Location: https://evil.example
```
**DOM-based (location sink):** find sources flowing to sinks. Vulnerable patterns (OWASP WSTG-CLNT-04):
```js
var redir = location.hash.substring(1);
if (redir) window.location = 'https://' + decodeURIComponent(redir);   // open redirect
window.location = decodeURIComponent(redir);                           // also enables javascript: XSS
```
Trigger: `https://target/page#//evil.example` or `...#javascript:alert(document.domain)`. Test by loading in a browser/headless and observing the navigation; grep JS bundles for the sinks above.

## Exploitation
Confirm an off-origin navigation, not just reflection. Payloads to escalate past naive validation:
- Absolute: `https://evil.example`
- Protocol-relative: `//evil.example`, `///evil.example`, `\/\/evil.example`
- Scheme-relative: `https:evil.example` (bypasses `//` filters)
- Userinfo `@`: `https://trusted.tld@evil.example` (browser host = `evil.example`)
- Backslash confusion: `https://trusted.tld\@evil.example`, `https://trusted.tld\.evil.example`
- Whitelist prefix/suffix/substring: `https://trusted.tld.evil.example`, `https://evil.example/trusted.tld`, `https://evil.example?trusted.tld`, `https://evil.example#trusted.tld`
- Encoded: `%2f%2fevil.example`, Unicode dot `%E3%80%82`, double-encoding
- CRLF-adjacent: if `Location` reflection allows `%0d%0a`, pivot toward header injection (separate finding).
For DOM `javascript:`-capable sinks, `javascript:alert(document.domain)` proves it's actually XSS — escalate to the XSS skill, that's the higher-severity finding.

## Chain for impact
THIS IS THE POINT — an open redirect is a primitive, report the chain:
- **OAuth `redirect_uri` token/code theft** → if the redirect lands inside an OAuth/SSO flow, attacker captures `code`/`access_token` from the URL/fragment. Hand to `/oauth`.
- **SSRF filter bypass** → server-side fetchers that allow only whitelisted hosts can be pointed at an internal target via a redirect on a trusted host. Hand to `/ssrf`.
- **CSP / whitelist bypass** → redirect on a CSP-allowed origin to smuggle navigation/loads past the allowlist.
- **Phishing on a trusted domain** → credential harvest with a genuine domain + valid TLS cert (the standalone story; usually low).
- **Token leak via `Referer`** → redirect off-site so secrets in the URL/`Referer` (reset tokens, session ids, OAuth codes) leak to the attacker host.

## Common bypasses
Full catalog (parser-differential `@`/`\`, whitelist prefix/suffix/substring flaws, encoding, scheme tricks, HPP) → see `reference.md`.

## Minimal PoC
Minimal, safe, single curl that proves the redirect to an attacker-controlled domain — for `./_EXPLOIT/`:
```
curl -sik 'https://target/login?next=//evil.example' | grep -i '^location:'
# PROVEN: Location: //evil.example   (off-origin redirect, no auth needed)
```
For DOM-based, log the one URL that navigates off-origin (e.g. `https://target/p#//evil.example`) plus the sink line from the JS bundle. Keep the PoC benign — redirect to a domain you control, never weaponize.

## Don't report as noise
A standalone open redirect with **no chain** on a program that rejects open redirects is noise. Do not file it. Either (a) chain it to OAuth/SSRF/token-leak for real impact, or (b) drop it. Reflection without an actual off-origin navigation is not even a finding.

## Deep reference
See `reference.md`. Sources: PortSwigger DOM-based open redirection (https://portswigger.net/web-security/dom-based/open-redirection); OWASP WSTG-CLNT-04 (https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect); PayloadsAllTheThings Open Redirect (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect).
