# Web Cache Deception — Reference

Comprehensive companion to `SKILL.md`.
Source: https://portswigger.net/web-security/web-cache-deception

---

## 1. What it is (and what it isn't)

**Web cache deception (WCD)** tricks a web cache into storing **sensitive, dynamic** content, which the attacker then retrieves. The victim does the "work" of authenticating; the cache stores their private response under a key the attacker can also request.

Contrast with **web cache poisoning**: poisoning manipulates the cache *key* / unkeyed inputs to make the cache serve **attacker-controlled malicious** content to other users. WCD goes the other way — it captures **victim** content out of the cache. Different goal, same root enabler: a discrepancy between cache and origin.

---

## 2. Web cache fundamentals

### Cache keys
A cache derives a **cache key** from elements of the request — typically the URL path and (some) query parameters, sometimes headers/content-type. Two requests with the same key → **cache hit** (stored copy served). Different keys → **cache miss** → forwarded to origin (and the response may then be stored).

If a *static-looking* URL produces the same cache key for the attacker and the victim, both reach the same stored response — that is the leak.

### Cache rules
Operators add rules deciding what gets stored. The common families WCD abuses:

- **Static file-extension rules** — cache anything ending in `.css`, `.js`, `.ico`, `.png`, `.woff`, etc.
- **Static directory rules** — cache anything under a path prefix: `/static`, `/assets`, `/scripts`, `/images`, `/resources`.
- **Filename rules** — cache specific well-known files: `robots.txt`, `index.html`, `favicon.ico`, `sitemap.xml`.

These rules frequently **override / ignore** the origin's `Cache-Control` headers — which is exactly why dynamic content ends up cached.

### Cache-status indicators
- `X-Cache: hit` — served from cache. `X-Cache: miss` — from origin (often cached afterward). `X-Cache: dynamic` — origin generated it, not cached.
- `Age: <seconds>` — present/growing → response is being cached.
- `Cache-Control: public, max-age=N` (N>0) — cacheable. `no-store` / `private` → meant not to be cached.
- **Timing**: repeat requests that are markedly faster suggest a cache hit.

### Cache buster
When probing, append a **unique query string** per request (`?cb=<random>`) so each probe gets its own cache key. This avoids polluting real keys, avoids false hits from prior tests, and avoids serving stale data to real users. Burp Param Miner: *Settings > Add dynamic cachebuster*.

---

## 3. Constructing the attack

1. **Find a dynamic, sensitive endpoint** reachable by GET/HEAD/OPTIONS that returns your private data (account page, profile, API key view, settings).
2. **Find a path-parsing discrepancy** between cache and origin (sections 4–5).
3. **Craft a URL** the origin maps to the sensitive endpoint but the cache maps to a cacheable static resource.
4. **Victim loads it** (while authenticated) → response cached under the shared key.
5. **Attacker requests the same URL** (no session) → reads the cached private response.

Always validate on **your own account**: confirm the origin still returns *your* data through the crafted URL, then confirm an unauthenticated request to the same URL returns that cached data.

---

## 4. Discrepancy taxonomy (static extension rules)

The cache stores because the URL ends in a static extension; the origin serves dynamic content because it parses the path differently.

### 4.1 Path-mapping discrepancies
URL-to-resource mapping styles differ.

- **Traditional mapping**: URL ≈ filesystem path, e.g. `/path/in/fs/resource.html`.
- **REST-style mapping**: logical endpoint; trailing segments treated as parameters or ignored, e.g. `/api/orders/123` where extra trailing path is dropped.

**Payload**: `/api/orders/123/wcd.css`
- Origin (REST): resolves the order/profile endpoint, ignores `/wcd.css` → returns sensitive data.
- Cache (extension rule): sees `.css` → stores it.

**Detect**:
1. Add an arbitrary segment: `/api/orders/123/foo`. If the response is unchanged, the origin ignores trailing segments.
2. Swap in a static extension: `/api/orders/123/foo.js`. If now cached (`X-Cache: hit`, `Age`), the discrepancy is confirmed.

### 4.2 Delimiter discrepancies
The origin's framework treats a character as a delimiter (truncating the path); the cache treats it literally.

| Framework | Delimiter |
|-----------|-----------|
| Java Spring | `;` (matrix variables) |
| Ruby on Rails | `.` (response format) |
| OpenLiteSpeed | `%00` (encoded null) |

**Payload (Spring)**: `/profile;wcd.css`
- Origin: truncates at `;` → `/profile` → sensitive data.
- Cache: literal `;` → path ends in `.css` → stored.

**Detect**:
1. Baseline with arbitrary string: `/settings/users/listaaa` (note response).
2. Insert candidate delimiter: `/settings/users/list;aaa`.
   - Matches the clean `/settings/users/list` response → origin treats `;` as a delimiter.
   - Matches the `...listaaa` response → `;` is **not** a delimiter for the origin.
3. Add a static extension: `/settings/users/list;aaa.js`. If cached → the cache does **not** treat `;` as a delimiter. Discrepancy confirmed.

**Browser constraint**: browsers encode `{ } < >` and truncate at `#` (raw), so those raw characters are hard to deliver. Prefer encoded forms (section 4.3).

### 4.3 Delimiter-decoding discrepancies
Cache and origin decode encoded characters selectively/differently.

**Payload**: `/profile%23wcd.css` (`%23` = `#`)
- Origin: decodes `%23`→`#`, uses `#` as a fragment/delimiter → `/profile` → sensitive data.
- Cache: does **not** decode `%23` → full literal path ends in `.css` → stored.

Other useful encodings (often truncate when decoded): `%00` (null), `%0A` (newline), `%09` (tab). Test each as both raw and encoded; methodology mirrors 4.2.

---

## 5. Static directory & filename rules

### 5.1 Static directory rules + normalization discrepancies
Here the cache stores because the path falls under a cached **prefix** (`/assets`, `/static`), and a normalization difference lets the origin resolve a different, sensitive path.

**Case A — origin normalizes `..%2f`, cache doesn't:**

`/assets/..%2fprofile`
- Cache: literal path under `/assets` → matches directory rule → stored.
- Origin: decodes `%2f`→`/`, resolves `..` → `/profile` → sensitive data.

**Case B — cache normalizes `..%2f`, origin doesn't:** combine with a delimiter discrepancy so the origin still lands on the dynamic path.

`/profile;%2f%2e%2e%2fassets`
- Cache: decodes + resolves dot-segments → `/assets` → matches rule → stored.
- Origin: truncates at `;` → `/profile` → sensitive data.

**Detect origin normalization**: send (non-cacheable method, e.g. POST) `/aaa/..%2fprofile`.
- Returns profile data → origin decodes `/` and resolves the dot-segment.
- Returns error → it doesn't.

**Detect cache normalization**: take a genuinely-cached static file and prefix a traversal: `/aaa/..%2fassets/js/stockCheck.js`.
- No longer cached → cache does **not** normalize (it's keying the literal path; good for Case A).
- Still cached → cache normalized the path.

**Confirm the rule is directory-based (not extension-based)**: request `/assets/aaa` (no static extension, non-existent). If still cached → it's a `/assets` prefix rule.

### 5.2 Filename rules
The cache stores specific well-known files (`robots.txt`, `index.html`, `favicon.ico`). Use the same normalization technique, targeting the exact filename instead of a directory prefix.

**Payload**: `/profile%2f%2e%2e%2findex.html` (or `/my-account/%2e%2e%2findex.html`)
- Cache: decodes/normalizes to `/index.html` → matches filename rule → stored.
- Origin: doesn't decode → resolves the dynamic path → sensitive data.

**Detect**: GET the suspected file directly (`/robots.txt`) and check for `X-Cache: hit`/`Age` to confirm a filename rule exists.

---

## 6. Detection checklist (quick)

1. Identify a dynamic endpoint returning YOUR sensitive data.
2. Append arbitrary segment → unchanged response? (path-mapping signal)
3. Append static extension (`/x.js`, `/x.css`) + cache buster → `X-Cache: hit` / `Age`?
4. Probe delimiters (`;`, `.`, encoded `%23 %00 %0A %09`) per 4.2/4.3.
5. Probe directory/filename rules + normalization per section 5.
6. **Cross-account proof**: re-request the crafted URL with no session → returns your cached private data? → confirmed.

---

## 7. Prevention (for the report's remediation section)

- Send `Cache-Control: no-store` (and `private`) on all dynamic/authenticated responses; ensure the CDN **respects** origin `Cache-Control` rather than overriding it with blanket extension/directory rules.
- Make cache and origin **parse paths identically** (delimiters, decoding, normalization) — eliminate the discrepancy.
- Validate that the response `Content-Type` matches the URL's apparent static extension before caching; don't cache `text/html` served at a `.css` URL.
- Enable CDN cache-deception protections (e.g. Cloudflare "Cache Deception Armor").
- Scope static caching to genuinely-static directories/files only.

---

## 8. Scope & safety (workspace doctrine)

- Re-read `./scope/` before any request; confirm the asset and technique are in scope.
- Prove with **your own account only**. Never request or retrieve another user's cached response — that is harvesting real users' PII and is out of bounds.
- Use a cache buster while probing so you don't cache real users' data or serve stale content.
- Minimal safe PoC: one crafted URL, the cache-hit headers, one redacted leaked field. Log to `./_EXPLOIT/` only once a genuine sensitive leak is proven.
