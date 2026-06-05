---
name: api-testing
description: "REST/JSON API testing — authz bypass, mass assignment (isAdmin/role), hidden endpoints/params, HTTP method tampering, content-type confusion, server-side parameter pollution (SSPP). Use for REST/JSON/SPA/mobile backends, Swagger/OpenAPI, or pivoting API findings into IDOR/SQLi/broken auth."
---

# API Testing

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test (any API: documented or hidden)
- Endpoints under `/api/`, `/v1/`, `/rest/`, `/graphql`, or JSON/XML request bodies.
- Swagger/OpenAPI docs exposed (`/swagger/index.html`, `/openapi.json`, `/api-docs`).
- SPA/mobile backends where JS or app traffic reveals the real endpoints.
- Any response that returns an object with more fields than the form sends (mass-assignment signal).
- Server-side requests built from your input (search-by, profile lookups) — SSPP candidates.

## Impact & priority (be honest)
- HIGH signal: API authz bypass, mass assignment to privileged fields (`isAdmin`, `role`, `access_level`), hidden-parameter privilege elevation, SSPP that overrides server-controlled params (e.g. dropping `publicProfile=true` to reach other users' data). These are account takeover / privilege escalation.
- These overlap heavily with **access-control-idor** (object-level authz) and broken auth — an API endpoint that ignores ownership is IDOR; reaching it via a hidden method/param/SSPP is the API-testing angle. Cross-reference that skill for the authz-impact proof.
- LOW signal: verbose docs, old API versions, OPTIONS disclosure, error-message leakage with no exploitable follow-through.

## Detection (API recon)
1. Find docs: probe `/api`, `/swagger/index.html`, `/openapi.json`, `/api-docs`, and parent paths (from `/api/v1/users/123` walk back to `/api/v1`, `/api`). Burp Scanner / OpenAPI Parser BApp parse them. **Pull the spec FIRST** — grep the Swagger UI HTML for the spec URL to get exact endpoint + field names before guessing: `curl -sk https://target/swagger/index.html | grep -oiE '(properties\.json|[a-z0-9/_.-]*api-docs[a-z0-9/_.-]*|[a-z0-9/_.-]*swagger\.json|spec ?: ?["'\''][^"'\'']+)'`.
2. Find endpoints: crawl, read JS bundles (JS Link Finder), diff documented vs. observed routes.
3. Enumerate methods: cycle `GET/POST/PUT/PATCH/DELETE/OPTIONS` on a low-value object; `OPTIONS` and `405` responses reveal allowed verbs.
4. Enumerate content types: flip `Content-Type` JSON<->XML<->form (Content Type Converter BApp) to reach alternate parsers / weaker defenses.
5. Fuzz hidden params (CLI-first with **arjun**, `~/.local/bin/arjun`): `arjun -u 'https://target/api/users/123' -m GET`; for write/JSON bodies `arjun -u 'https://target/api/users/123' -m JSON` (also `-m POST`; arjun supports only GET/POST/JSON/XML — for PUT/PATCH method-tampering use curl/ffuf, not arjun); `arjun --passive` harvests candidate names from wayback/commoncrawl. Param Miner (guesses ~65k names/req) is the Burp alternative. Watch responses for echoed/return objects exposing undocumented fields.

## Exploitation
- **Method tampering**: an action blocked on `POST` may succeed on `PUT`/`PATCH`/`DELETE`, or auth checks may only guard one verb.
- **Content-type switching**: resend a JSON body as XML to hit an XXE-capable parser, or bypass a JSON-only filter.
- **Mass assignment**: add fields the object exposes but the form omits — `"isAdmin":true`, `"role":"admin"`, `"access_level":"administrator"`. Confirm by re-reading your own object / privilege state.
  - **Highest-signal heuristic**: diff the fields a `GET` *returns* vs. the fields the edit form / `PATCH` *accepts*. Returned-but-not-accepted fields (`role`, `isAdmin`, `tenant`, `balance`) are the prime mass-assignment / SSPP candidates — feed those names to `arjun` and a `PATCH` test. **Always re-derive identity/privilege from the returned token or cookie, not from a 200** — a 200 means the request parsed, not that the field bound.
- **Hidden-parameter privilege elevation**: discovered params (e.g. `id`, `admin`) bound by the framework into the model.
- **Server-side parameter pollution (SSPP)**: when your input is folded into a server-side request:
  - Query string: `%23` (`#`) truncates trailing server params; `%26` (`&`) injects/overrides params (`name=peter%26name=carlos` — last/first/joined wins per stack).
  - REST path: `%2f..%2f` path traversal to redirect the server-side route (`name=peter%2f..%2fadmin`).
  - Structured formats: break out of JSON via `","key":"value` or escaped quotes to inject sibling fields.
- **Pivot**: feed reachable params into SQLi, SSRF, and IDOR tests — APIs are a delivery surface, not the end.

## Authz testing — division of labor
- **Autorize (passive breadth)**: replay everything you browse as a second account / unauth; catches obvious missing checks across the whole surface cheaply.
- **AuthMatrix or scripted stateful `curl` replay (depth)**: reserve for crown-jewel / money / admin endpoints and `create-as-A` -> `access-as-B` chains, where order and state matter and passive replay misses it.
- **Drive the depth pass from `_RECON/<target>/phase2_surface.json`** so endpoints that Autorize never happened to hit aren't silently skipped — mark each tested / N-A in `coverage.md`.
- **OpenAPI/Swagger spec in scope?** Feed spec + 2 accounts to **Schemathesis** (`pip install schemathesis`) to enumerate cross-user access over the whole documented surface, then hand-validate every hit — never report raw tool output. Rate limits still bind.
- **Rotating-token one-liner** (re-fetch per batch when tokens rotate):
  ```bash
  TOKEN=$(curl -sk -X POST https://T/api/login -H 'Content-Type: application/json' \
    -d '{"username":"...","password":"..."}' | jq -r '.Authorization')
  curl -sk https://T/api/... -H "Authorization: $TOKEN"
  ```

## Recon workflow
See `reference.md` for the full recon checklist, SSPP variants, and OWASP API Top 10 mapping. Run the **recon** skill first for surface discovery, then map authz impact with **access-control-idor**.

## Minimal PoC (for ./_EXPLOIT/)
Mass assignment to a privileged field:
```bash
# Add a field the API exposes in GET but never in the edit form.
curl -s -X PATCH https://target/api/users/wiener \
  -H 'Authorization: Bearer <low-priv-token>' \
  -H 'Content-Type: application/json' \
  -d '{"email":"wiener@example.com","isAdmin":true}'
# Confirm: re-read self and show the privilege actually changed.
curl -s https://target/api/users/wiener -H 'Authorization: Bearer <low-priv-token>'
```
SSPP query-string override (truncate a server-enforced filter):
```bash
# %23 drops the server-appended &publicProfile=true, reaching private records.
curl -s 'https://target/userSearch?name=victim%23&back=/home' \
  -H 'Authorization: Bearer <low-priv-token>'
```
Keep PoC read-only / non-destructive: prove the privilege change or data exposure, then stop. Log request, response, and the proven impact to `./_EXPLOIT/`.

## Don't report as noise
- Public/verbose docs, reachable old API versions, or OPTIONS verb lists with no exploit.
- Reflected/injected params that are parsed but change nothing security-relevant.
- Mass-assignment fields that bind but grant no privilege or data access. No proven impact => not a finding.

## Deep reference
See `reference.md`. Sources:
- https://portswigger.net/web-security/api-testing
- https://portswigger.net/web-security/api-testing/server-side-parameter-pollution
