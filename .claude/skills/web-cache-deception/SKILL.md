---
name: web-cache-deception
description: Tricks a web cache into storing a dynamic, authenticated response so it can be retrieved unauthenticated — leaking the victim's PII, tokens, or account data. Use when a CDN/cache (Cloudflare, Akamai, Fastly, Varnish, CloudFront) caches static extensions (.css/.js/.png/.ico) AND the origin serves dynamic authenticated content. Strong signals: appending /foo.css or an extra path segment to a profile/account/settings endpoint still returns the dynamic page; path-mapping confusion (REST vs traditional); delimiter discrepancies (; . %00); delimiter-decoding (%23, %2f, %2e); static-directory rules (/static /assets); filename rules (robots.txt, index.html, favicon.ico); cache rules that ignore Cache-Control. X-Cache: hit / Age header / Cache-Control: public on a private page.
---

# Web Cache Deception (WCD)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Coax a cache into storing a sensitive *dynamic* response by making the URL look like a *static* cacheable resource. The victim loads the crafted URL while authenticated; the cache keys and stores their private response; the attacker requests the same URL with no session and reads the cached copy. Impact comes from *what leaks*, not the caching itself.

## When to test

Both must hold:
1. The cache stores responses by **static signals** — a file extension (`.css`/`.js`/`.ico`), a directory prefix (`/static`, `/assets`), or a known filename (`robots.txt`) — often ignoring `Cache-Control`.
2. The origin serves **dynamic, authenticated content** (profile, account, settings, API responses with PII/tokens/CSRF secrets) that can be reached via a URL the cache will treat as static.

No cache in front, or only genuinely-static content cached → not applicable.

## Impact & priority

Honest framing: WCD is high-signal **only when a cached response actually leaks something sensitive** — PII, API keys, session/CSRF tokens, account details — that an unauthenticated attacker can then retrieve. That maps to "sensitive data exposure" / partial account takeover (CSRF-token theft → request forgery). Severity scales with what leaks and how broadly (shared cache key = any visitor can fetch a victim's stored response).

Caching a response with **no sensitive data** is noise. Do not report it.

## Detection

1. Pick a dynamic endpoint that returns YOUR sensitive data (e.g. `/my-account`).
2. Append an arbitrary segment / static extension and compare:
   - `/my-account/wcd.js` — does it still return your account page (origin ignores the suffix)?
3. Check cache indicators on that crafted URL: `X-Cache: hit`/`miss`, `Age:`, `Cache-Control: public, max-age=...`, faster repeat timing.
4. Use a **cache buster** (unique query string per probe) so your tests don't collide and you don't poison a real key.
5. Confirm the cross-account angle: request the crafted URL **without your session cookie** — if it returns YOUR cached account data, the discrepancy is proven.

## Exploitation

The attack lives in a **discrepancy** between how the cache and origin parse the path:

- **Static extension rules via path mapping** — REST origin ignores trailing segments, cache sees the `.css`: `/api/orders/123/foo.css`.
- **Delimiter discrepancies** — origin truncates at a delimiter the cache treats literally: Spring `;` → `/profile;wcd.css`; Rails `.`; OpenLiteSpeed `%00`.
- **Delimiter-decoding discrepancies** — origin decodes then truncates, cache does not: `/profile%23wcd.css` (`%23`=`#`), also `%00`/`%0A`/`%09`.
- **Static directory rules** — origin normalizes `..%2f`, cache does not: `/assets/..%2fmy-account` (cache caches under `/assets`, origin serves `/my-account`).
- **Filename rules** — same trick onto a known filename: `/my-account/%2e%2e%2findex.html`.

## Common bypasses

- Encoded delimiters when the raw one is browser-mangled: `%23` for `#`, `%2f` for `/`, `%2e` for `.`, `%00`/`%09`/`%0A`.
- Normalization mismatch direction: if the **cache** normalizes `..%2f` but the origin doesn't, combine with a delimiter: `/my-account;%2f%2e%2e%2fassets`.
- Mix extension + directory rules; try variants the cache decodes but the origin doesn't (and vice versa).

## Minimal PoC (your OWN account only)

Prove a leak with your own session, then prove retrieval without it. Never use another user's data.

```bash
# 1) Authenticated request to crafted URL — origin serves YOUR account, cache stores it.
curl -s -o /dev/null -D - "https://TARGET/my-account/wcd.js?cb=$RANDOM" \
  -H "Cookie: session=<YOUR_OWN_SESSION>" | grep -iE 'x-cache|age|cache-control'

# 2) Fetch the SAME URL with NO cookie — proves the dynamic response is cached & readable.
curl -s "https://TARGET/my-account/wcd.js?cb=SAME_AS_ABOVE" | grep -iE 'your-email|csrf|apiKey'
```

Log to `./_EXPLOIT/` only after a real leak is confirmed: the crafted URL, the cache-hit headers, and the redacted sensitive field that leaked. One record, your own. No bulk retrieval, no harvesting other users' cached pages.

## Don't report as noise

- Caching of public/non-sensitive responses (marketing pages, generic JSON with no PII).
- A discrepancy that exists but caches nothing private, or where `Cache-Control: no-store`/`private` is honored.
- Theoretical "it might cache" with no demonstrated leak — prove it or drop it.

## Deep reference

See `reference.md` (fundamentals, discrepancy taxonomy, detection recipes, prevention) and
https://portswigger.net/web-security/web-cache-deception
