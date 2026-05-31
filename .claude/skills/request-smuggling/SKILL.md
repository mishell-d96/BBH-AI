---
name: request-smuggling
description: >-
  Detect and prove HTTP request smuggling (HTTP desync) where chained HTTP
  processors disagree on message boundaries, letting an attacker prepend bytes
  to another user's request. Use when the target sits behind a front-end/back-end
  proxy, CDN, reverse proxy, or load balancer; when you see Content-Length +
  Transfer-Encoding handling differences or want to test CL.TE, TE.CL, TE.TE,
  HTTP/2 downgrade (H2.CL / H2.TE), CL.0, or 0.CL desync. Covers timing-based
  and differential detection, front-end control bypass, capturing victim
  requests, reflected-XSS amplification, web cache poisoning/deception, response
  queue poisoning, and request tunnelling. Keywords: request smuggling, HTTP
  desync, CL.TE, TE.CL, TE.TE, H2.CL, H2.TE, CL.0, chunked, Transfer-Encoding,
  Content-Length, HTTP/2 downgrade, response queue poisoning, cache poisoning.
---

# HTTP Request Smuggling (Desync)

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Two chained HTTP processors (front-end CDN/proxy/LB + back-end app) disagree on
where one request ends and the next begins. The attacker's trailing bytes get
prepended to the *next* connection user's request. This is shared-state by
nature — see "Safety" below. It is high-skill but high-signal.

## When to test
- A reverse proxy, CDN, WAF, or load balancer sits in front of the app server
  (look for `Via`, `X-Cache`, `Server`, `CF-RAY`, differing error pages).
- HTTP/1.1 is spoken upstream, or HTTP/2 is downgraded to HTTP/1.1 to the back end.
- The connection between front-end and back-end is reused across users (classic
  server-side desync) — or test CL.0 / client-side desync where it isn't.
- Skip pure single-server, HTTP/2-end-to-end targets for *classic* CL/TE (still
  consider CL.0 / client-side desync).

## Impact & priority
High-signal when proven: bypass front-end access controls (reach `/admin`,
inject trusted headers like `X-SSL-CLIENT-CN`), capture other users' requests
(session tokens, PII), turn header-only reflected XSS into zero-click, mass web
cache poisoning/deception, response queue poisoning (steal arbitrary responses /
account takeover), and request tunnelling. Caveat: high effort, environment-
sensitive, and dangerous to bystanders — only escalate past detection with care.

## Detection
- **Timing-based** (first, lowest risk): send a request the back-end will block
  on, waiting for bytes that never come. A consistent multi-second delay vs a
  control = desync signal.
  - CL.TE probe: front-end honours `Content-Length` and forwards a truncated
    body; back-end honours chunked `Transfer-Encoding` and waits for the next chunk.
  - TE.CL probe: front-end honours `Transfer-Encoding`; back-end waits for more
    `Content-Length` bytes. **Test CL.TE before TE.CL** — TE.CL probing can
    disrupt real users if the target is actually CL.TE.
- **Differential responses** (confirmation): over a fresh connection, smuggle a
  prefix that breaks the *follow-up* request (e.g. routes it to `/404`), then
  send a benign follow-up. A wrong/404 response on the follow-up confirms desync.
- Use separate connections for attack + follow-up, match URL/params so both hit
  the same back-end, expect races, retry. Prefer self-targeted follow-ups.

## Exploitation
- **Bypass front-end controls**: front-end sees `/home`, back-end processes the
  smuggled `/admin`. Also inject front-end-trusted headers the back-end believes.
- **Reveal request rewriting**: smuggle a reflecting POST param placed last; the
  back-end folds the next request's rewritten headers (e.g. `X-Forwarded-For`)
  into your stored value.
- **Capture victim requests**: smuggle a POST to a storage endpoint with an
  oversized `Content-Length`; the victim's request body gets appended and stored.
- **Reflected XSS amplification**: deliver header-based reflected XSS (e.g.
  `User-Agent`) to the next user with no click.
- **Web cache poisoning / deception**: poison a cached URL with an off-site
  redirect, or cache a victim's private response under a static URL you can read.
- **Response queue poisoning**: desync the response stream to steal other users'
  full responses — extremely high impact, extremely high blast radius.
- **Request tunnelling / HTTP/2**: smuggle via H2.CL / H2.TE downgrade or tunnel
  requests even without connection reuse; CRLF in HTTP/2 header values re-arms on
  downgrade.

## Variants (brief)
- **CL.TE** — front-end CL, back-end TE(chunked).
- **TE.CL** — front-end TE(chunked), back-end CL.
- **TE.TE** — both do TE; one is tricked by an obfuscated `Transfer-Encoding`
  (tabs, spacing, dup headers, `Transfer-Encoding: chunked\r\nTransfer-Encoding: x`).
- **H2.CL / H2.TE** — HTTP/2 front-end downgrades to HTTP/1.1; injected
  `content-length` / `transfer-encoding` not reconciled with H2 framing.
- **CL.0** — back-end ignores `Content-Length` (treats body as next request);
  works single-server, no chunking/H2 needed.
- **0.CL** — front-end ignores body, back-end honours `Content-Length`.
- **Client-side desync (CSD) / pause-based** — browser-compatible HTTP/1 triggers
  the desync from the victim's own browser; pause-based reveals latent flaws.

## Minimal PoC for ./_EXPLOIT/
1. Establish a baseline (normal response + timing) on a benign endpoint.
2. Run a **timing probe** (CL.TE first): a smuggled chunked prefix that makes the
   back-end block; record delta vs baseline over several trials.
3. Confirm with a **differential probe**: smuggle a prefix that routes a benign
   *self* follow-up to a harmless path (e.g. `/<random-404>`) and observe the
   anomalous response on your own follow-up — not a third party's.
4. Stop at minimal confirmation. Log to `./_EXPLOIT/`: exact requests, raw
   responses, timing table, variant, and the front-end/back-end fingerprint.
- Tooling: Burp **HTTP Request Smuggler** extension (auto-probes CL.TE/TE.CL/CL.0/
  H2 desync, includes a smuggle-probe scanner) + **Turbo Intruder** for timing.
  Disable Burp's "Update Content-Length" and send raw when crafting manually.

## Don't report as noise
- Timing blips with no reproducible differential confirmation of an actual desync.
- Presence of both `Content-Length` and `Transfer-Encoding` alone (theoretical).
- "Could be vulnerable" headers with no proven boundary disagreement.
- Anything you cannot demonstrate without harming uninvolved users.

## Safety (paramount)
Smuggling poisons shared connection state and can hit **other real users**.
Keep PoCs self-targeted, low-volume, and on harmless paths. Never queue
malicious prefixes that a bystander's request would execute, never mass-poison a
shared cache, and never run response-queue-poisoning against production user
traffic. If a safe self-contained PoC isn't possible, report the confirmed
detection signal and stop.

## Deep reference
See `reference.md` for full mechanics, all variants, obfuscation, detection
methodology, and exploitation depth.
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/request-smuggling/finding
- https://portswigger.net/web-security/request-smuggling/exploiting
- https://portswigger.net/web-security/request-smuggling/advanced
- https://portswigger.net/web-security/request-smuggling/browser
