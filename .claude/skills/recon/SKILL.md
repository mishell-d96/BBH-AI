---
name: recon
description: Quick, lightweight attack-surface sketch — fast subdomain/content/parameter discovery and tech fingerprinting for a single target, without baselining or skill-routing. Use when the operator explicitly wants a SHALLOW, fast look ("quick recon", "just enumerate subdomains", "what's the tech stack", "any obvious endpoints"). For a full engagement — mapping the whole app, verifying happy flows, impact-scoring, and routing findings to vuln skills — use `/recon-mapper` instead (that is the map-first entry point the workflow expects). Keywords: quick recon, subdomain enumeration, content discovery, parameter discovery, fingerprinting, spidering, sitemap, crawl, asset discovery.
---

# Recon — quick attack-surface sketch

A fast, shallow look at a single target's surface. **This is the lightweight option.** For a real
hunt, prefer **`/recon-mapper`** — the full map-first pipeline that also baselines happy flows,
impact-scores candidates, and routes them to the right vuln skills (and which the workflow gate
expects before any vuln-class testing). Use this `recon` skill only when the operator asks for a
quick sketch. Optimize for signal, not coverage.

## Scope first (SCOPE GATE)
- Read `./scope/` BEFORE any request. Confirm the asset is explicitly in scope, the action is permitted, and you are within stated rate limits / restrictions.
- Only actively enumerate assets that are explicitly in scope. Wildcards (`*.example.com`) still require confirming each resolved host is in-program.
- Anything uncertain or out-of-scope: passive recon only, or skip entirely.
- Re-check the gate on every new asset and every new technique. Out-of-scope hosts are never touched — not even a single probe.

## Goal
Produce a prioritized inventory of attack surface and select a few high-impact targets to test. The deliverable is hypotheses ("this endpoint likely has IDOR because…"), not a dump of every path. Depth on the promising 20%, not noise across 100%.

## Passive recon (safe, no aggressive touching of the target)
- Certificate transparency (crt.sh, censys) for subdomains and internal hostnames.
- Public docs: API docs, developer portals, status pages, changelogs, help center.
- JavaScript files: pull and read them for endpoints, API routes, params, feature flags, secrets.
- Wayback / web archives & common-crawl: historical URLs, dead-but-live params, old API versions.
- GitHub / GitLab / npm: org repos, leaked keys, internal hostnames, API schemas, `.env` mistakes.
- Search engines / Google dorking for indexed sensitive paths.

## Active recon (in-scope only, rate-limited, non-destructive)
- Content & directory discovery (sane wordlists, throttled).
- Endpoint enumeration: crawl the app, harvest from JS, diff API versions.
- HTTP method & content-type probing (GET vs POST vs PUT/DELETE/PATCH; JSON vs form vs XML).
- Parameter discovery (Param Miner / arjun-style) on interesting endpoints.
- Tech fingerprinting: server, framework, language, CDN/WAF, auth provider, third-party integrations.
- Spider authenticated and unauthenticated views.
- Map auth flows & roles: how login/session/token works; what roles and tenants exist.

## What to capture (the inventory)
- Hosts/subdomains (live, with tech).
- Endpoints & API routes (method, auth required, params).
- Parameters (names, types, where reflected/stored/used).
- Auth model: session vs token/JWT/OAuth, cookie flags, CSRF defenses.
- Roles & tenants: admin/user/guest, org boundaries.
- Tech stack & versions.
- Interesting features: file uploads, redirects, SSRF-prone fetchers, integrations/webhooks, GraphQL/REST APIs, payment, import/export, account management.

## From recon to hypotheses (route to the right skill)
- Object IDs in URLs/bodies, multi-tenant → **access-control-idor**
- URL/host/webhook fetchers, PDF/image-from-URL, integrations → **ssrf**
- Search/filter/report/`id`/`sort` params hitting data → **sql-injection**
- Reflected/stored user input in HTML/JS → **xss**
- REST/GraphQL endpoints, mass-assignment, versioned APIs → **api-testing**
- Login with social/SSO, `redirect_uri`, tokens → **oauth**
- Upload endpoints, avatars, import → **file-upload**
- Open redirects, link previews → relevant redirect/ssrf skills

## Tooling
Burp Suite (spider/crawl, Param Miner), ffuf / feroxbuster (content discovery), subfinder / amass (subdomains), httpx (probing/fingerprint), nuclei (targeted templates), waybackurls / gau, katana (crawl). Tools find candidates; **you manually validate**. Never report scanner output as a finding — prove it.

## Don't
- No out-of-scope hosts, ever.
- No aggressive scanning that breaches stated rate limits / thread caps.
- No DoS, no destructive methods (mass DELETE/PUT) during recon, no data exfiltration.

## Deep reference
See `reference.md` for the full playbook: subdomain enum, content/JS/param discovery, method probing, fingerprinting, multi-role/multi-tenant mapping, API recon, wordlists, and the P1/P2 prioritization rubric.
