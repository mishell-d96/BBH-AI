---
name: graphql
description: "GraphQL vulns — introspection/suggestion schema mapping, full ARGUMENT enumeration, access-control/IDOR via object args, exposed admin mutations, argument injection (SQLi/cmd/path-traversal/file-write), token-argument JWT forgery, alias rate-limit bypass, batching brute-force, recursion/cost DoS, CSRF. Use for /graphql or /api/graphql, __schema/__typename, queries/mutations, batched arrays, suggestions."
---

# GraphQL API vulnerabilities

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test (any GraphQL endpoint)
Any endpoint that speaks GraphQL: a path like `/graphql`, `/api`, `/api/graphql`, `/graphql/v1`, or any
request/response containing `query`, `mutation`, `__typename`, `__schema`, aliases, or a batched array of
operations. If you can send a GraphQL document, this skill applies.

## Impact & priority (honest)
- **High signal:** Broken object-level/function-level authorization — IDOR via object ID arguments,
  unprotected mutations that change state, privilege/role fields settable by the caller, unsanitized
  arguments reaching a SQL/NoSQL/OS sink. These are real, proven, reportable.
- **Medium:** Alias/batching that defeats rate limiting on a sensitive action (2FA, password check, coupon),
  *when you can demonstrate the bypass works*.
- **Informational only (usually not worth a report on its own):** Introspection enabled, verbose
  field-suggestion errors. These are leads, not findings. Only escalate if they expose something genuinely
  sensitive AND reachable.

## Detection
1. Find the endpoint: probe `/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/v1`.
2. Universal probe: `query{__typename}` → a GraphQL endpoint returns `{"data":{"__typename":"query"}}`.
3. Try introspection (probe query in reference.md). If it returns the schema, map it.
4. Try alternate transports: GET with URL-encoded `query=`, and POST `application/x-www-form-urlencoded`.
   Defenses are often only applied to POST `application/json`.
5. If introspection is disabled: use field suggestions ("Did you mean …") and the **clairvoyance** tool to
   reconstruct the schema. See reference.md.

### Map the schema COMPLETELY — fields AND arguments AND every root (don't stop at field names)
Reconstructing field *names* is not a map. The highest-impact bugs hide in **arguments you never enumerated**
and **fields on a root you never probed**. When introspection is off:
- **Probe every guessed field on ALL THREE roots — `query`, `mutation`, AND `subscription`.** Graphene/Apollo
  suggestions only surface *near* matches, so a field on a different root than you guessed stays invisible.
  (Real miss: `systemDiagnostics` — a 2nd OS-command-injection sink — was a **query**; probed only as a
  mutation, so it never appeared. `query{field}` AND `mutation{field}` AND `subscription{field}` for each guess.)
- **Enumerate ARGUMENTS, not just fields.** `Unknown argument "x"` with no suggestion ≠ "no args" — the engine
  just won't volunteer them. Brute a wordlist against each interesting field:
  `filter query search keyword id ids uuid public private limit offset order sort name username password
  token jwt cmd command host hostname port path url uri file filename scheme content title body data`.
  A name that returns a *type/coercion* error instead of "Unknown argument" is a REAL arg → test it.
  (Real miss: the SQLi lived in `pastes(filter:)`; I tested `search(keyword:)`, never enumerated `pastes`' args.)
- A field whose error names a resolver (`resolve_system_diagnostics() missing args 'username','password'`)
  leaks both the **sink** and its **required args** — and is itself a stack-trace disclosure.

## Exploitation
- **Introspection → schema map.** Pull the full schema, enumerate Query/Mutation types, find object-fetch
  fields (`user(id:)`, `product(id:)`) and state-changing mutations.
- **Access control / IDOR.** Call an object-fetch field with IDs you shouldn't see (other users' records,
  delisted/sequential IDs). Proof = data belonging to another principal returned to you.
- **Exposed mutations / privilege fields.** Look for mutations callable without proper authz
  (`deleteUser`, `updateRole`, `setAdmin`), or input fields like `isAdmin`/`role` the client can set.
- **Unsanitized arguments — test EVERY string arg for the FULL injection set, not the one the name implies.**
  Each string/ID argument can be SQLi, NoSQLi, OS-command, path-traversal, SSRF, *and* XSS sink. A negative
  on one class does NOT close the arg — run the whole set per arg (ties to "run owned skills to completion").
  - SQLi: boolean differential is the fastest confirmer — `filter:"zzznomatch"` (0 rows) vs
    `filter:"zzznomatch' or 1=1-- -"` (all rows). Row-count flip = injection. (This is exactly the
    `pastes(filter:)` bug; one boolean pair proves it.)
  - Command injection: any arg feeding an exec/fetch (`host`/`path`/`cmd`/`url`) → wrap payload in separators
    `;id;` / `|id|` (a single concatenated token can hang → 504; bracketing splits it cleanly).
  - **File/path args on mutations → arbitrary file write / path traversal.** Any `filename`/`path`/`file` arg
    on an upload/import mutation: `filename:"../../../../tmp/x"` writes outside the intended dir.
    (Real miss: `uploadPaste(filename:)` traversal — enumerated the mutation, never exercised its sink.)
- **Returned auth tokens are a finding surface — decode and forge them.** If a `login`/`signin` mutation
  returns a token (`accessToken`/`token`/`jwt`), **immediately decode it** (JWT? opaque?) and route to
  `/jwt` (alg:none, weak-secret, RS256→HS256) or `/custom-opaque-tokens`. Also test **identity-claim
  arguments** — a field like `me(token:)` / `viewer(jwt:)` that takes a token as an *argument* often skips
  signature verification → forge the identity claim for unauth ATO. (Real miss: `me(token:)` JWT forgery.)
- **Client-side feature gates are bypass candidates.** A cookie/header that toggles a feature
  (`env=graphiql:disable`, `X-Debug:0`, `mode=prod`) is attacker-controlled — flip it
  (`graphiql:disable`→`graphiql:enable`) to unlock the GraphiQL console / debug interface.
- **Rate-limit bypass via aliases.** Pack many aliased calls of a guard field into one HTTP request to
  defeat per-request rate limiting (coupon/2FA/OTP checks).
- **Batching brute-force.** Send a JSON array of operations (or many aliases) to brute-force OTP/2FA codes
  or credentials in one request. See reference.md for syntax.
- **DoS / cost-amplification class set** (demonstrate the query is *accepted* and *expensive* — do NOT
  actually flood a shared/real target; measure one request's cost vs a trivial baseline):
  - **Deep recursion** via a circular relation (`pastes{owner{pastes{owner{…}}}}`) — nest a few levels and
    show latency climbing; no depth limit = vulnerable.
  - **Circular fragments** (`fragment A on T{...B}` / `fragment B on T{...A}`) — accepted = no cycle guard.
  - **Field duplication** (repeat the same expensive field N times) and **alias overloading** (`q1: q2: …`).
  Absence of query-cost analysis / depth limit / batching cap is the finding; prove acceptance + a cost delta.
- **GraphQL CSRF.** If the endpoint accepts `x-www-form-urlencoded` (or GET) and lacks CSRF tokens, a
  cross-site request can trigger a state-changing mutation. `application/json` is not browser-forgeable.

## Bypassing introspection defenses
Naive defenses block `__schema` with a brittle regex, or only on one transport. Whitespace/newline tricks
after `__schema`, plus GET and `x-www-form-urlencoded` transports, often bypass them. Full payloads and the
clairvoyance workflow are in reference.md.

## Minimal PoC (for ./_EXPLOIT/)
Keep it minimal and SAFE — read one unauthorized record or perform the least-impactful proven mutation.
IDOR read:
```bash
curl -s https://TARGET/graphql \
  -H 'Content-Type: application/json' \
  -b 'session=LOW_PRIV_TOKEN' \
  -d '{"query":"query{ user(id:1){ id email role } }"}'
```
A response returning user 1's email/role to a low-privilege session proves the access-control break. Log the
request, response, and the principal mismatch to `./_EXPLOIT/`.

> **Authz cross-check:** GraphQL object/node/edge resolvers are a prime spot for BOLA/IDOR. Run object-level access-control tests here too — see `/access-control-idor` (compare two accounts against node IDs and nested fields), and `/api-testing` for mass-assignment on mutations.

## Don't report as noise
- Introspection enabled with nothing sensitive or unauthorized actually reachable.
- Verbose field suggestions / "Did you mean" alone.
- Schema disclosure with no access-control or injection consequence.
Map it, then prove an authorization, injection, or brute-force consequence — or drop it.

## Deep reference
See `reference.md` and https://portswigger.net/web-security/graphql for full queries, transport tricks,
batching syntax, and prevention.
