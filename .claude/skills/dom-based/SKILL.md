---
name: dom-based
description: >-
  Finds and proves DOM-based client-side vulnerabilities by tracing taint from
  attacker-controllable sources to dangerous JS sinks. Use when the target has
  rich client-side JS / SPAs and URL fragments influence the DOM; when you see
  client-side JS sinks (innerHTML, outerHTML, eval, Function, setTimeout,
  setInterval, document.write, document.writeln, location/location.href,
  element.src, postMessage, setRequestHeader, document.cookie, JSON.parse,
  WebSocket); when sources like location.hash, location.search, document.URL,
  document.referrer, window.name, document.cookie, localStorage/sessionStorage
  or postMessage flow into those sinks. Covers DOM XSS, DOM open-redirect,
  DOM cookie manipulation, JavaScript/eval injection, web-message (postMessage)
  manipulation, DOM clobbering, and taint-flow analysis. Keywords: DOM XSS,
  client-side, sink, source, taint, hash payload, DOM Invader, Trusted Types.
---

# DOM-based vulnerabilities

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


DOM-based bugs live entirely in client-side JS: an attacker-controllable **source**
flows into a dangerous **sink** without sanitization. The server may never see the
payload (fragment-based), so this is often missed by server-side scanners.

## When to test
- Rich client-side JS, SPAs (React/Vue/Angular), heavy templating, ad/analytics glue.
- URL fragments (`#...`) or query params that visibly change the DOM or app state.
- Pages that read `location.*`, `document.referrer`, `window.name`, `postMessage`,
  or web storage and write into the page.
- Cross-origin `postMessage` handlers (iframes, payment/SSO widgets, embeds).

## Impact & priority (honest)
- **DOM XSS / JS injection (eval) = HIGH signal.** Arbitrary JS in victim origin →
  account takeover, token theft. Always report with a working PoC.
- **Web-message (postMessage) → JS/HTML sink = HIGH** when no/weak origin check.
- **DOM open-redirect, cookie manipulation, link manipulation = LOW** on their own;
  only report if chained (e.g. open-redirect → OAuth token leak, cookie-fix → session).
- **DOM clobbering = MEDIUM/HIGH** when it overrides a config var that reaches a sink.
- Self-XSS, theoretical taint with no controllable source = **not reportable**.

## Detection (trace taint: source → sink)
1. Grep the JS for sinks; for each, walk backwards to find what feeds it.
2. Use **DOM Invader** (Burp's embedded browser) to auto-trace sources→sinks and
   auto-generate canary payloads; or DevTools → set breakpoints on the sink.
3. Inject a unique harmless canary via a source and watch where it lands:
   - `#dom-canary-7f3` in `location.hash`, `?q=dom-canary-7f3` in search.
   - For `window.name`: set it in a controlled page, then navigate to target.
   - For `postMessage`: send canary from a test iframe, log handler behavior.
4. If the canary reaches a sink unencoded, escalate to a real (still safe) payload.

## Exploitation (key source→sink combos)
- **`location.hash`/`search` → `innerHTML`/`document.write`** → DOM XSS.
  Use a non-script vector if `<script>` won't run after parse:
  `#<img src=x onerror=alert(document.domain)>` or `<svg onload=...>`.
- **source → `eval`/`Function`/`setTimeout`(string)** → JS injection: `#alert(document.domain)`.
- **`location.hash` → `location`/`location.href`** → open redirect (validate the
  `https:`/`//` parsing logic; many `startsWith` checks are bypassable).
- **`postMessage` → `eval`/`innerHTML`/`location`** → web-message XSS/redirect when
  the handler skips/weakens `e.origin` checks (`indexOf`/`endsWith` are bypassable).
- **DOM clobbering**: when JS does `var cfg = window.cfg || {}`, inject HTML with
  matching `id`/`name` to forge `cfg` and steer a downstream sink.

## Sinks / sources (the 16 DOM vuln types → primary sink)
| Vuln type | Primary sink | Vuln type | Primary sink |
|---|---|---|---|
| DOM XSS | `document.write`/`innerHTML` | Ajax header manip | `setRequestHeader()` |
| Open redirect | `window.location` | Local file-path manip | `FileReader.readAsText()` |
| Cookie manipulation | `document.cookie` | Client-side SQLi | `ExecuteSql()` |
| JavaScript injection | `eval()` | HTML5-storage manip | `sessionStorage.setItem()` |
| Document-domain manip | `document.domain` | Client-side XPath inj | `document.evaluate()` |
| WebSocket-URL poison | `WebSocket()` | Client-side JSON inj | `JSON.parse()` |
| Link manipulation | `element.src` | DOM-data manipulation | `element.setAttribute()` |
| Web-message manip | `postMessage()` | DoS (ReDoS) | `RegExp()` |

Controllable sources: `location` (`.hash`/`.search`/`.href`), `document.URL`,
`document.documentURI`, `document.referrer`, `window.name`, `document.cookie`,
`localStorage`/`sessionStorage`, `postMessage` data. Full code examples → `reference.md`.

## Minimal PoC (harmless, for ./_EXPLOIT/)
Concrete fragment payload hitting a sink — proves execution without harm:
```
https://target.example/page#<img src=x onerror=alert(document.domain)>
```
Or for an `eval`/JS sink:
```
https://target.example/search#alert(document.domain)
```
Log to `./_EXPLOIT/<host>-dom-xss.md`: the URL, the source, the sink (with the JS
line), the rendered/executed result (screenshot or console line showing the origin).
Use `alert(document.domain)` or a benign DNS/log marker only — never data exfil,
never a real redirect to a third-party site (use `//127.0.0.1` if proving redirect).

## Don't report as noise
- Sink present but **no attacker-controllable source** reaches it.
- Source is sanitized/encoded before the sink (e.g. `textContent`, encoded HTML).
- Open-redirect / cookie / link manipulation with no chained impact.
- "Taint" that requires the victim to already control their own input (self-XSS)
  or requires implausible victim interaction with no real-world delivery.
- `alert(1)` in a sandboxed/`null`-origin iframe with no parent reach.

## Deep reference
See `reference.md` for the full taint-flow model, every source/sink, all 16 vuln
types with vulnerable code, DOM clobbering technique, and prevention (avoid sinks,
sanitize with DOMPurify, Trusted Types).
- https://portswigger.net/web-security/dom-based
- https://portswigger.net/web-security/dom-based/dom-clobbering
