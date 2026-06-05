# GraphQL — deep reference

Primary source: https://portswigger.net/web-security/graphql

This reference backs the `graphql` skill. Always operate within scope and prefer minimal, non-destructive
proofs. Confirm a real authorization/injection/brute-force consequence before reporting.

---

## 1. GraphQL basics

- **Schema** defines types, fields, and the entry-point types: `Query` (read), `Mutation` (write/state
  change), `Subscription` (stream).
- **Query** retrieves data; **Mutation** modifies server-side data. Both select fields and pass arguments.
- **Aliases** rename returned fields, which lets you include the *same* field multiple times in one
  document (normally disallowed because object keys must be unique). This is the basis of alias-based
  rate-limit bypass and brute-force.
- **Fragments** are reusable field sets (`fragment X on Type { ... }`), used to keep large queries
  (like introspection) compact.
- **Variables** parameterize a query: `query($code:Int){ isValidDiscount(code:$code){ valid } }` with a
  separate `variables` JSON object.

Typical transport: `POST /graphql` with `Content-Type: application/json` and body
`{"query":"...","variables":{...},"operationName":"..."}`.

---

## 2. Finding GraphQL endpoints

Common paths (also try each with a trailing `/v1`):
`/graphql`, `/api`, `/api/graphql`, `/graphql/api`, `/graphql/graphql`, `/graphql/v1`.

**Universal probe** — works on any GraphQL server because `__typename` is reserved:
```
query{__typename}
```
A GraphQL endpoint responds `{"data":{"__typename":"query"}}` (or `Query`).

**Transport probing** — always test all of these; defenses often cover only one:
- `POST` with `application/json` (standard).
- `GET` with the query in a URL parameter: `GET /graphql?query={__typename}`.
- `POST` with `application/x-www-form-urlencoded`.

---

## 3. Introspection

Introspection is a built-in feature that lets you query the schema itself.

**Probe (is it enabled?):**
```graphql
{
  __schema {
    queryType { name }
  }
}
```

**Standard full introspection query:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
```

**Reading the result:**
- `queryType` / `mutationType` name the root types — enumerate their `fields` to see every available
  operation.
- For each field, `args` shows accepted arguments (look for `id`, `userId`, filters → IDOR/injection
  candidates).
- Mutations are your state-changing surface — scan for `delete*`, `update*`, `set*`, `create*`, anything
  touching roles/permissions/payments.
- `inputFields` on input objects can reveal privilege fields the client may set (`isAdmin`, `role`).
- Save the schema; a GraphQL voyager/visualizer makes large schemas readable.

---

## 4. Bypassing introspection defenses

Defenses are frequently a brittle regex on the literal string `__schema`, or applied to only one transport.

**Whitespace / newline trick** — a newline after `__schema` is valid GraphQL but slips past `__schema{`
regexes:
```graphql
query{__schema
{queryType{name}}}
```

**GET with URL-encoded body** (the same payload, encoded):
```
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

**Alternate content type:** repeat the introspection POST as `application/x-www-form-urlencoded` — the
defense may only guard `application/json`.

**If introspection is truly disabled — schema suggestions / clairvoyance:**
- Apollo and others return helpful errors: `Cannot query field "usr" ... Did you mean "user"?`. Each
  suggestion leaks a real field name.
- **clairvoyance** automates this: it fuzzes field names and reconstructs a partial schema from the
  suggestion errors. Use it when introspection is blocked but suggestions are on.
- Defense: Apollo Server v4+ `hideSchemaDetailsFromClientErrors` disables suggestions.

---

## 5. Exploiting unsanitized arguments (injection)

Arguments often flow straight into a backend query. A field like `product(category:"...")` may concatenate
into SQL → SQLi; likewise NoSQL/OS sinks.
- Test argument values for injection just as you would any input (e.g. error-based / boolean probes).
- Confirm non-destructively (boolean/time differential, not DROP/DELETE) before claiming impact.
- Both query and mutation arguments are in scope.

---

## 6. Access control / IDOR via object arguments

The most common high-impact GraphQL bug: object-fetch fields take an ID/identifier and the resolver lacks
an authorization check.
```graphql
query {
  product(id: 3) { id name listed }
}
```
- Sequentially numbered IDs let you fetch records you shouldn't (e.g. a delisted product, another user's
  account).
- Test object-fetch fields AND mutations: can a low-privilege session read/modify another principal's
  object? Can it call an admin-only mutation?
- Proof = data or a state change belonging to a different principal, performed by your lower-privileged
  session.

---

## 7. Rate-limit bypass using aliases

If the rate limiter counts HTTP requests rather than operations, pack many aliased calls into one request:
```graphql
query isValidDiscount($code: Int) {
  isValidDiscount(code: $code) { valid }
  isValidDiscount2: isValidDiscount(code: $code) { valid }
  isValidDiscount3: isValidDiscount(code: $code) { valid }
}
```
Each alias is evaluated independently, so one HTTP request tests N candidates. Effective against coupon
checks, OTP/2FA verification, and similar guarded endpoints.

---

## 8. Batching attacks (brute-forcing 2FA / passwords)

Two batching mechanisms:

**(a) Aliases** — as in section 7, many copies of the verification field in one document, each with a
different candidate value (via variables or inline literals).

**(b) JSON array batching** — many servers accept a top-level array of operations in a single HTTP request:
```json
[
  {"query":"mutation{ verify2FA(code:\"0001\"){ ok } }"},
  {"query":"mutation{ verify2FA(code:\"0002\"){ ok } }"},
  {"query":"mutation{ verify2FA(code:\"0003\"){ ok } }"}
]
```
The server returns an array of results, one per operation. This brute-forces short OTP/2FA codes or password
guesses while making a single request, bypassing per-request throttling and sometimes lockout logic.

Detect batching support by sending a 2-element array and checking for a 2-element array response. Keep PoCs
minimal — demonstrate the bypass mechanism, do not run a full credential-stuffing campaign.

---

## 9. GraphQL CSRF

Arises when the endpoint **does not validate the request content type** and **has no CSRF token**.
- `application/json` is safe-ish: browsers cannot send it cross-site via a simple form.
- Vulnerable: endpoint accepts `application/x-www-form-urlencoded` (or `text/plain`, or GET) for a
  state-changing mutation.
- PoC: an auto-submitting cross-site form posting `query=mutation{...}` as url-encoded, triggering the
  mutation using the victim's ambient cookies.
- Confirm the mutation actually executes and changes state to prove impact.

---

## 10. Prevention (for write-ups / remediation advice)

- **Disable introspection** on production/private APIs (e.g. Apollo config). For public APIs, audit which
  fields are exposed and never expose sensitive data (emails, internal IDs).
- **Disable field suggestions** in client errors (`hideSchemaDetailsFromClientErrors` in Apollo v4+).
- **Authorization** at the resolver/object level for every field and mutation — never trust client-supplied
  IDs or privilege fields.
- **Query depth & cost limits** to prevent DoS via deeply nested/expensive queries; cap query byte size and
  the number of aliases/root fields/operations per request (this also blunts alias/batching brute-force).
- **CSRF defense:** accept only `application/json` POST, validate content type matches the body, and use
  CSRF tokens for state-changing operations.
- **Rate limiting** should count operations/aliases, not just HTTP requests, and apply lockout to sensitive
  verification flows.

---

Reference: https://portswigger.net/web-security/graphql
