---
name: graphql
description: "GraphQL vulns — introspection schema mapping, access-control/IDOR via object args, exposed admin mutations, argument injection (SQLi), alias rate-limit bypass, batching brute-force, CSRF. Use for /graphql or /api/graphql, __schema/__typename, queries/mutations, batched arrays, suggestions."
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

## Exploitation
- **Introspection → schema map.** Pull the full schema, enumerate Query/Mutation types, find object-fetch
  fields (`user(id:)`, `product(id:)`) and state-changing mutations.
- **Access control / IDOR.** Call an object-fetch field with IDs you shouldn't see (other users' records,
  delisted/sequential IDs). Proof = data belonging to another principal returned to you.
- **Exposed mutations / privilege fields.** Look for mutations callable without proper authz
  (`deleteUser`, `updateRole`, `setAdmin`), or input fields like `isAdmin`/`role` the client can set.
- **Unsanitized arguments.** Arguments flowing to a backend query may be injectable (SQLi/NoSQLi). Confirm
  with a safe, non-destructive probe before claiming impact.
- **Rate-limit bypass via aliases.** Pack many aliased calls of a guard field into one HTTP request to
  defeat per-request rate limiting (coupon/2FA/OTP checks).
- **Batching brute-force.** Send a JSON array of operations (or many aliases) to brute-force OTP/2FA codes
  or credentials in one request. See reference.md for syntax.
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
