# Recon Playbook (Deep Reference)

Practical, impact-first reconnaissance for an authorized bug-bounty workspace. Everything here is **scope-gated and non-destructive**. Before any active step, confirm in `./scope/` that the asset is in scope, the technique is permitted, and you are within rate limits. When in doubt, stay passive.

---

## 0. Scope discipline (repeat, because it matters)
- Resolve the scope into a concrete allow-list of hosts/domains/IPs and a deny-list.
- For wildcard scopes (`*.example.com`), every discovered subdomain must still be checked against program rules (some carve out `corp.`, `internal.`, acquisitions, or third-party SaaS).
- Note rate limits, allowed methods, prohibited actions (no DoS, no automated scanners, no spam to support, no real payments), and PII handling rules. Respect them literally.
- Recheck the gate when you pivot to a new host, a new subdomain, or a more aggressive technique.

---

## 1. Subdomain enumeration

**Passive (preferred, low-touch):**
- Certificate transparency: `crt.sh` (`%.example.com`), Censys, Facebook CT.
- Passive DNS / aggregators: `subfinder`, `amass enum -passive`, Project Discovery chaos, SecurityTrails, VirusTotal.
- Search/archives: `gau`, `waybackurls`, Google/Bing dorks (`site:example.com`).

**Active (in-scope, rate-limited):**
- Resolve candidates with `httpx` (`-status-code -title -tech-detect -web-server`) to find live hosts and fingerprint fast.
- DNS brute force only if permitted: `amass enum -brute` or `puredns` with a sane resolver list and throttling.
- Virtual-host / SNI discovery for hosts sharing an IP.

**What to keep:** live host, status, title, tech, whether it requires auth, and why it's interesting (admin panel, staging, API gateway, old app).

---

## 2. Content & directory discovery
- Tools: `ffuf`, `feroxbuster`, Burp content discovery.
- Throttle: cap threads and add delay to honor rate limits (`-rate`, `-t`, `-p`). Recursion only where it pays off.
- Filter noise: match/ filter by status, size, words, lines (`-fc 404 -fs <size>` or auto-calibrate). Watch for soft-404s (200 with "not found" body).
- Hunt for: `/api`, `/admin`, `/internal`, `/.git/`, `/backup`, `/old`, `/v1`,`/v2`, `/swagger`, `/graphql`, `/actuator`, `/debug`, `/.env`, config and backup files (`.bak`, `~`, `.old`, `.zip`).
- Extension-aware fuzzing based on detected stack (`.php`, `.aspx`, `.jsp`, `.json`).

---

## 3. JavaScript analysis (high yield)
- Collect all JS (crawl + sourcemaps). Beautify minified bundles; pull `.map` files to recover original source.
- Extract:
  - **Endpoints / API routes** (fetch/axios/XHR URLs, route tables).
  - **Parameters** and request shapes (body keys, headers).
  - **Feature flags / hidden features / role checks** done client-side (often enforced nowhere else → access-control bug).
  - **Secrets**: API keys, tokens, cloud creds, third-party keys (then verify, don't assume).
- Tools/patterns: `katana -jc`, LinkFinder-style regexes, `gf` patterns, grep for `apiKey|secret|token|/api/|fetch(|axios`.
- Client-side role/feature gating is a recurring source of IDOR/broken-access findings — flag every "if user.isAdmin" enforced only in JS.

---

## 4. Parameter discovery
- Tools: Burp **Param Miner** (guess query/body/header/cookie params), `arjun`, `ffuf` with a param wordlist.
- Test for: reflected params (XSS/open-redirect candidates), data-access params (`id`, `user`, `account`, `org` → IDOR/SQLi), control params (`debug`, `admin`, `role`, `format`, `callback`).
- Look for **mass assignment**: send extra fields (`isAdmin`, `role`, `verified`) the UI never exposes.
- Header params: `X-Forwarded-For`, `X-Original-URL`, `X-Forwarded-Host`, custom `X-*` toggles.

---

## 5. HTTP method & content-type probing
- Try `OPTIONS` to enumerate allowed methods; probe `PUT/DELETE/PATCH/HEAD` on resource endpoints (non-destructively — read/`OPTIONS` first, never bulk-delete real data).
- Method-based access control gaps: `GET` blocked but `POST`/`PUT` allowed, or vice versa.
- Content-type swaps: send JSON to a form endpoint and vice versa; try XML (XXE candidate), multipart, `application/x-www-form-urlencoded`. Different parsers = different bugs.
- Override headers: `X-HTTP-Method-Override`, `_method` param.

---

## 6. Tech fingerprinting
- `httpx -tech-detect`, Wappalyzer, response headers (`Server`, `X-Powered-By`, `Set-Cookie` patterns), error pages, favicon hash (`shodan`/`fofa`).
- Identify: web server, language/framework, templating engine (SSTI surface), WAF/CDN (and how to stay under its thresholds), auth provider (Auth0/Okta/Cognito → OAuth surface), CMS, GraphQL/REST, cloud provider.
- Map versions to known CVEs — but validate exploitability against the live target before claiming impact.

---

## 7. Mapping multi-role & multi-tenant apps (critical for access-control bugs)
- **Register at least two accounts** (two users, ideally also two orgs/tenants, and one low-priv + one admin if possible). This is the single highest-ROI recon setup for P1/P2 access-control findings.
- Document every role, the features each can reach, and every object that carries an ID (users, orgs, files, invoices, settings).
- Build a matrix: action × role → expected vs observed authorization. Cross-account access to another user's/tenant's object = IDOR/broken access control.
- Capture how tenancy is scoped (org ID in path? in JWT? in a header?) — tenancy controls are frequently bypassable.
- Map the auth flow end to end: signup, login, MFA, session/token issuance, refresh, password reset, invite, SSO. Note cookie flags, CSRF tokens, JWT claims.

---

## 8. API recon (per PortSwigger "API recon")
- **Find the API docs first.** Look for Swagger/OpenAPI (`/swagger`, `/swagger.json`, `/openapi.json`, `/api-docs`, `/v3/api-docs`), GraphQL (`/graphql`, `/graphiql`, introspection), Postman collections, developer portals.
- If no docs: derive endpoints from JS, mobile app traffic, and by guessing parallel resources (if `/api/v1/users/{id}` exists, probe `/orders`, `/invoices`, `/admin`).
- Enumerate API versions (`v1`/`v2`/`internal`) — older versions often miss new authz checks.
- For each endpoint capture: method, auth requirement, params, object IDs, and whether the response leaks more than the UI shows (over-fetching / excessive data exposure).
- GraphQL: run introspection if allowed; map queries/mutations, look for fields that bypass REST authz, and batching/aliasing abuse.
- Probe content negotiation and mass assignment (see §4/§5).

---

## 9. Wordlists
- Content/dirs: SecLists `Discovery/Web-Content` (`raft-*`, `common.txt`, `directory-list-*`), API-specific lists (`api/`, `actuator`, `swagger`).
- Params: SecLists `burp-parameter-names.txt`, Param Miner's built-ins, Arjun's bundled list.
- Subdomains: SecLists `Discovery/DNS` (`subdomains-top1million-*`, `dns-Jhaddix.txt`).
- Tailor wordlists to detected tech (don't fuzz `.php` on a Node app). Smaller, relevant lists beat huge generic ones and respect rate limits.

---

## 10. Prioritization rubric — where P1/P2 actually come from
Rank discovered surfaces by likely impact, then test the top few. Typical high-yield surfaces:

| Priority | Surface | Why it pays |
|---|---|---|
| P1/P2 | Object IDs across accounts/tenants (IDOR/BOLA) | Direct data access; easy to prove with 2 accounts |
| P1/P2 | Auth/session/SSO/OAuth flaws, JWT, password reset | Account takeover |
| P1/P2 | SSRF-prone fetchers, webhooks, "import from URL" | Internal access / cloud metadata |
| P1/P2 | SQLi / injection on data-backed params | DB compromise |
| P1/P2 | Admin/internal endpoints reachable by low-priv users | Privilege escalation |
| P2/P3 | File upload (type/path/SSRF/stored-XSS chains) | RCE/XSS/overwrite |
| P2/P3 | Stored XSS in shared/multi-user contexts | Session theft, worm |
| P3 | Reflected XSS, open redirect | Lower impact, often chainable |
| Info | Version disclosure, verbose errors | Context, not a finding alone |

Heuristics:
- Surfaces touching **other users' data** or **authorization** outrank everything.
- New, undocumented, or legacy API versions > polished main UI.
- Features that take a **URL, file, or template** as input are bug magnets.
- Anything enforced **only client-side** is presumed broken until proven otherwise.

Convert each prioritized surface into a one-line hypothesis with the target skill, e.g.:
`"/api/v1/invoices/{id} returns other tenant's invoice → access-control-idor"`.

---

## 11. Handing off
- Keep a living inventory (hosts, endpoints, params, roles, tech, features).
- Only proven, validated issues graduate to `./_EXPLOIT/`. Recon produces leads and hypotheses, not findings.
- Stay non-destructive and within rate limits throughout. Re-read `./scope/` whenever the target set changes.
