---
name: subdomain-takeover
description: "Subdomain takeover from dangling DNS. Use when a CNAME points to an unclaimed service (GitHub Pages, S3, Heroku, Azure, Fastly, Shopify, Zendesk, Netlify), or a subdomain returns NXDOMAIN or a service 404 ('no such app', 'no such bucket', 'there isn't a GitHub Pages site here'). Keyword: can-i-take-over-xyz."
---

# Subdomain Takeover

> **Prereq — surfaced during mapping:** This class is driven by `/recon-mapper`'s asset inventory (Phase 1/2 subdomain enumeration + DNS). Run the map first and test the dangling records it discovers. Prioritize by impact and chain into cookie/session theft, OAuth/CSP whitelist abuse, or trusted-domain phishing rather than filing a bare "dangling DNS" note.

A subdomain takeover happens when a DNS record (usually a CNAME) still points at a
third-party service whose backing resource has been deleted/never claimed. You
register that resource on the provider and now control content served from the
target's subdomain.

## When to test
- A subdomain resolves via CNAME to a third-party provider (`*.github.io`, `*.s3.amazonaws.com`, `*.herokuapp.com`, `*.azurewebsites.net`, `*.netlify.app`, `*.surge.sh`, etc.) but the provider serves an "unclaimed" page.
- A subdomain returns NXDOMAIN while a CNAME exists (dangling pointer), or returns a service-specific "not found" fingerprint.
- Recon flagged abandoned/decommissioned subdomains, old marketing/status/docs hosts, or anything pointing at a SaaS you can sign up for.

## Impact & priority
Be honest about trust relationship — that drives severity.
- **High:** takeover of a subdomain the main app trusts. Cookies scoped to the parent domain (`.example.com`) can be set/read; OAuth `redirect_uri` allowlists or CSP/CORS allowlists include the subdomain; the subdomain is whitelisted by SSO/embeds. Leads to session theft, token theft, script injection, or highly convincing phishing on a legitimate-looking host.
- **Medium:** subdomain used by users but with no cookie/OAuth/CSP trust — still good for phishing and reputational abuse.
- **Low:** isolated, unused subdomain with no trust relationship and no user traffic. Often informational.
Prove the chain, not just the dangle.

## Detection
1. Enumerate subdomains (subfinder, amass, CT logs).
2. Resolve them and pull CNAME chains (dnsx, dig) — find records pointing to external services.
3. For each external pointer, fetch the host and check whether the provider serves an **unclaimed/not-found** page vs a real site.
4. Match the response against a known service fingerprint (table below / reference.md / can-i-take-over-xyz). NXDOMAIN on a CNAME target is also a strong signal for Azure/Elastic Beanstalk/Discourse.
5. Confirm the resource is genuinely unclaimed on the provider before proceeding.

Automation: `subjack`, `nuclei -t http/takeovers/`, and the can-i-take-over-xyz matrix.

## Exploitation
Claim the unclaimed resource on the third-party provider (create the bucket / GitHub Pages repo + custom domain / Heroku app / Netlify site / etc.) with the exact name the CNAME expects, then serve **your** content from the target subdomain. Stop at proof: serve a **harmless unique marker** — an HTML page on a random/hidden path with your researcher handle and the report ID in an HTML comment. Do NOT deface index pages, do NOT host real phishing/credential forms, and do NOT submit the PoC URL to the Wayback Machine.

## Chain for impact
- **Cookie theft / fixation:** if cookies are scoped to the parent domain, your subdomain can read or overwrite them — pivot to session hijack on the main app.
- **OAuth:** if the subdomain is an allowed `redirect_uri` (or matched by a wildcard), capture authorization codes/tokens. See `/oauth`.
- **CSP / CORS:** if the subdomain is in a `script-src`/`connect-src` or CORS allowlist, inject script or read authenticated cross-origin data. See `/cors`.
- **Phishing:** legitimate-looking host on the real domain dramatically raises credibility.

## Service fingerprints
Brief excerpt — full matrix + claim steps in reference.md.

| Service | Status | Fingerprint |
|---|---|---|
| AWS/S3 | Vulnerable | `The specified bucket does not exist` |
| AWS/Elastic Beanstalk | Vulnerable | `NXDOMAIN` |
| Microsoft Azure | Vulnerable | `NXDOMAIN` |
| GitHub Pages | Edge case | `There isn't a GitHub Pages site here.` |
| Heroku | Edge case | `No such app` |
| Netlify | Edge case | `Not Found - Request ID:` |
| Shopify | Edge case | `Sorry, this shop is currently unavailable.` |
| Bitbucket | Vulnerable | `Repository not found` |
| Surge.sh | Vulnerable | `project not found` |
| Ghost | Vulnerable | `Site unavailable.` |
| Pantheon | Vulnerable | `404 error unknown site!` |
| Fastly | Not vulnerable | `Fastly error: unknown domain:` |
| Zendesk | Not vulnerable | `Help Center Closed` |

## Minimal PoC (for ./_EXPLOIT/)
Log exactly two facts: (1) the dangling record and (2) proof you control the claimed resource.
```
target:      assets.example.com
dns:         assets.example.com. CNAME victim-bucket.s3.amazonaws.com.
fingerprint: HTTP 404 "The specified bucket does not exist"
claim:       created S3 bucket "victim-bucket" in <region> under my account
proof:       https://assets.example.com/poc-<handle>-<reportid>.html
             body: <!-- subdomain takeover PoC by <handle>, report <id>, harmless marker -->
trust:       cookies Domain=.example.com observed -> chains to session theft (see /oauth, /cors)
```

## Don't report as noise
- NXDOMAIN / dead CNAME pointing at a service that is **not claimable** (or already protected, e.g. Fastly, Zendesk).
- Subdomains with no trust relationship and no user traffic — flag, but don't oversell severity.
- "Potential" takeovers without an actual claimed-resource marker proving control.

## Deep reference
See `reference.md` for the full per-service fingerprint/claim matrix, tooling, chaining, and prevention.
- https://www.hackerone.com/blog/guide-subdomain-takeovers-20
- https://github.com/EdOverflow/can-i-take-over-xyz
