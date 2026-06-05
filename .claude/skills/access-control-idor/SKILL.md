---
name: access-control-idor
description: "Broken access control — IDOR/BOLA, horizontal & vertical privilege escalation, forced browsing to /admin or privileged functions. Use when requests expose object refs (id/uuid/account/order/user/filename), role/isAdmin flags, multi-step flows, or you can compare two accounts' access."
---

# Access Control & IDOR

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Test **every object reference and every privileged function**. Whenever a request contains an identifier that names a resource (`id`, `uuid`, `user`, `account`, `order`, `customer_number`, `invoice`, `file`, `doc`), or whenever functionality is meant to be restricted (admin panels, role changes, deleting other users, viewing other tenants), it is in scope. This is consistently THE highest-ROI bug class in bug bounty: cheap to find, broad impact, low false-positive rate.

## Impact & priority
Broken access control / IDOR is high-signal and routinely lands **P1/P2**:
- Horizontal IDOR -> reading or modifying other users' data (PII, messages, orders) = P2, often P1 at scale.
- Vertical escalation -> reaching admin functionality, changing roles, deleting/managing other accounts = P1.
- Horizontal->vertical -> compromise an admin via IDOR, then take over the platform = P1.
Honest framing: a single proven object you don't own, returned with sensitive data, is a real finding. Report impact, not theory.

## Detection
**Default breadth pass — passive cross-account replay.** Run a passive cross-account replay (Burp Autorize, or a scripted mitmproxy/curl harness when a custom token breaks Autorize): set account B's token AND an unauthenticated context as the two replay vantages, scope to the in-scope host + an `/api/` regex, and leave it running during all mapping. Every request you make as A is auto-replayed as B and as anon. Bypassed rows are **CANDIDATES, never findings** — each still needs the differential below.

Two-account method is the gold standard:
1. Authenticate as **two** low-priv users (A and B) and ideally one admin.
2. As A, capture every request that references an object or privileged action.
3. Replay A's requests using **B's session** (and B's object IDs in A's session). If A can read/modify B's resource, that's IDOR.
4. As a low-priv user, hit admin/privileged endpoints directly (forced browsing): `/admin`, links from `robots.txt`, JS-leaked hidden URLs, wordlist brute force.
5. **Compare responses by CONTENT, never by length** — per-user payloads differ in size, so a length diff is noise. Use the app's denial fingerprint (its own forbidden/unauthorized JSON string) as the deny-oracle, and confirm a real hit only when **A's unique data marker appears in B's / anon's body**. Watch for redirects that still leak the body. GUIDs aren't safe if they leak elsewhere (messages, reviews, API listings).
6. **403-vs-404 existence-leak oracle:** a `403` where an absent resource returns `404` confirms the object **exists** but enforcement is the only thing standing in the way (also leaks valid IDs to harvest). Same logic in forced browsing: `403 ≠ 404` = the path is real.
7. **Test WRITE / DELETE / trigger across the A→B boundary, not just GETs** — state-changing BOLA is ~46% of confirmed cases. For every read you diff, diff the matching update/delete/state-flip too.

```bash
# Forced-browsing oneshot — 403 (path exists, gated) is the signal, not 404
ffuf -u 'https://target/FUZZ' \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -H 'Cookie: session=<low-priv>' -mc 200,302,403 -fr login
# -fr login filters reflected login redirects; mc 403 keeps existence-leaking paths.
```

## Session-liveness canary (don't mistake an expired session for a result)
Authenticated sessions expire mid-test. When that happens **every** request to a gated endpoint suddenly
returns the same `302→/login` (or `401`) — which is easy to misread as "the endpoint got fixed", "SQLi
gone", or "access now denied". Before trusting any authenticated-endpoint result:
- Keep a **liveness canary** — a known-good owned-resource request (e.g. your own account page). If the
  canary stops returning your data, the session died: **re-authenticate and re-run**, don't record a verdict.
- A **uniform** status flip across *all* probes (every one → 302/401) is a session/cookie signal, not a
  finding. A *real* control change is differential (some pass, some don't).

## Acquiring valid IDs (obfuscation is not authorization)
You need a *real* foreign object ID to prove a hit. **Obfuscation is not authorization** — an opaque ID still leaks.
- **Sequential integers:** increment/decrement by one to the adjacent record. Don't bulk-enumerate; one foreign object proves it.
- **Opaque IDs (UUID/hash/slug) — DON'T guess.** Harvest cross-tenant IDs that the app itself hands you, then replay as B: list/search/export endpoints, error messages, `Location`/email links, and GraphQL `node`/edge responses.
- **GraphQL global IDs:** base64-decode → increment the embedded numeric → re-encode, then query the `node`.
- **Wildcards / sentinels:** try `me`, `0`, `-1`, `null`, or a **known other identifier** in the ID slot — some backends resolve these to the current/first/other user.

## Exploitation
**Vertical escalation**
- *Unprotected functionality*: admin URL has no server-side check — request it directly (`/admin`, hidden `/administrator-panel-yb556` found in client JS).
- *Parameter-based roles*: role/privilege carried in a user-controllable place — flip `admin=true`, `role=1`, `isAdmin`, hidden field, or cookie.
- *Client-side-trusted authorization state*: **decode every opaque/serialized cookie** (base64, JSON, pipe/CSV blobs). If it encodes the **list of objects/accounts/entitlements you may access**, your **role**, or **balances/limits**, the server is trusting client state for authz — tamper it (add a foreign account ID, flip a role, raise a limit) and replay. A cookie that carries `acct~type~balance|acct~type~balance` is a tamper-to-BOLA primitive; hand the decode ladder to `/custom-opaque-tokens` if the encoding is non-obvious.
- *Platform / URL-matching quirks*: see Common bypasses below.

**Horizontal escalation (IDOR)**
- Change the identifier to another user's: `GET /myaccount?id=123` -> `id=124`. Same for static files: `/static/12144.txt` -> another number.
- Works on read AND write (update email, change password, transfer funds).

**Horizontal -> vertical**
- Use IDOR to reach an admin user's account/details, capture or reset their credentials, then use admin functionality.

**Multi-step process gaps**
- A guarded flow (load form -> submit change -> confirm) may only check access on step 1. Submit the final step's request directly with the required params.

**Referer / location-based control**
- If access is gated only by the `Referer` header on sub-pages, forge it. If gated by geo/IP, route through a proxy/VPN — both are attacker-controlled and not real access control.

## Common bypasses
- **HTTP method switch**: blocked `POST /admin/deleteUser` may allow `GET` or other verbs.
- **URL case / format quirks**: `/ADMIN/DELETEUSER`, trailing slash `/admin/deleteUser/`, suffix `/admin/deleteUser.anything` (Spring `useSuffixPatternMatch`).
- **Non-standard headers**: `X-Original-URL: /admin/deleteUser` or `X-Rewrite-URL` on a request to `/` may bypass front-end path rules.
- More variants, framework specifics, and examples in **reference.md**.

## Minimal PoC
Prove with the **least intrusive** evidence: your own session reaching exactly ONE object you don't own (a single controlled test object you set up, or one ID adjacent to yours), or a low-priv session hitting an admin endpoint. Never iterate to harvest real users' data.

```bash
# Horizontal IDOR — user A's token reading object owned by test user B
curl -i 'https://target.example/api/orders/1002' \
  -H 'Authorization: Bearer <USER_A_TOKEN>'
# 200 + B's order details => proven IDOR. Stop. Do not enumerate further.

# Vertical — low-priv session reaching admin function (forced browsing)
curl -i 'https://target.example/admin/deleteUser?username=carlos' \
  -H 'Cookie: session=<LOW_PRIV_SESSION>'
# Header bypass variant:
curl -i 'https://target.example/' \
  -H 'Cookie: session=<LOW_PRIV_SESSION>' \
  -H 'X-Original-URL: /admin'
```
Log proven findings to `./_EXPLOIT/` with this single curl repro, the two account contexts, and the exact response evidence (status + the one cross-user field returned).

**Write / money-movement BOLA — copy-paste differential skeleton** (drives the 3-control discipline below; the unique marker makes the effect provably *yours*):

```bash
TGT=https://target.example; OBJ=1002          # OBJ = victim object you do NOT own
A='Authorization: Bearer <USER_A_TOKEN>'

# 0) Victim state BEFORE (read the ledger/record you'll mutate)
curl -s "$TGT/api/accounts/$OBJ/transactions" -H "$A" | jq '.[-1]'

# 1) Baseline — A acts on A's OWN object (record the success shape)
curl -i -X POST "$TGT/api/accounts/<USER_A_OBJ>/transfer" -H "$A" \
  -d 'to=<A_DEST>&transferAmount=3.71'

# 2) Attack — A acts on the NON-OWNED object, UNIQUE marker (3.71, never a generic 1)
curl -i -X POST "$TGT/api/accounts/$OBJ/transfer" -H "$A" \
  -d 'to=<A_DEST>&transferAmount=3.71'

# 3) Control-A — same attack with NO auth header => expect 401 (defect is ownership, not authn)
curl -i -X POST "$TGT/api/accounts/$OBJ/transfer" \
  -d 'to=<A_DEST>&transferAmount=3.71'

# 4) Control-B — non-existent id => expect a DISTINCT not-found, proving the server resolved & could've checked
curl -i -X POST "$TGT/api/accounts/999999999/transfer" -H "$A" \
  -d 'to=<A_DEST>&transferAmount=3.71'

# 5) Victim state AFTER — the 3.71 marker now in the victim ledger is the proof, not the success JSON
curl -s "$TGT/api/accounts/$OBJ/transactions" -H "$A" | jq '.[-1]'
```

## Proving a state-change / money-movement BOLA (attribution discipline)
Read-IDOR is proven by a response body. **Write/action BOLA** (transfer, refund, password change,
delete, status flip on a non-owned object) needs proof the action *actually executed against the
victim object* — and on a shared/noisy target a generic success message is not enough. Use this
3-control differential; it isolates "broken ownership check" from "no auth" and "endpoint can't
resolve the object", and makes the effect uniquely yours:

1. **Baseline** — perform the action on an object you **own** (owned→owned). Record the success shape.
2. **Attack** — perform it with the **non-owned** object as the target/source, with a **unique
   attacker-chosen marker value** (e.g. `transferAmount=3.71`, a tagged note, an odd quantity) — *never*
   a generic `1`/`$1` that other testers' traffic also produces. Capture the object's state
   **before and after** (its transaction log / record), so the marker change is provably *your* request.
3. **Control A — auth enforced:** same request **without** the session → expect `401/redirect`. Proves the
   defect is *ownership*, not a missing-auth endpoint.
4. **Control B — server resolves the object:** point the action at a **non-existent** id → expect a
   distinct "invalid/not found" error. Proves the server looks the object up and *had the data to check
   ownership* but didn't — converting "missing feature" into "broken authorization".

A success message the server generates by reflecting your input is **not** independent proof; the
before/after state delta on the victim object with your unique marker is. Keep it minimal and
reversible (smallest amount, into an account you control, one object).

**Field guardrails (avoid the common false positives):**
- **A `200`/`"success"` is NOT proof of a side effect.** Before claiming a state change or privesc, verify the action *actually happened*: log in as the user you supposedly created, hit a duplicate/conflict on re-creating it, or find your unique marker in the victim's ledger.
- **Run BOTH a no-token AND a garbage-token control.** `no-token → 401` **+** `garbage-token → 401` **+** `valid-low-priv-token → 200` proves the gap is missing **authorization**, not missing **authentication**. (Control-A above is the no-token leg; add the garbage-token leg to seal it.)
- **`500`/empty on object lookup = untestable, not refuted.** When the tested id resolves to nothing, record `"untestable: no object at tested id"`, NOT `"IDOR refuted"` — a *populated* id may still be vulnerable; go acquire a real foreign id (see above) and retry.

## Chain for impact
A single cross-user read is already a finding — the big payouts come from chaining it:
- **Horizontal IDOR → vertical ATO:** use the IDOR to reach an *admin/staff* user's object, then harvest or reset their credentials → hand off to `/authentication` for full takeover.
- **Role/`isAdmin` flip → privilege escalation:** a user-controllable role here is usually the same root cause as mass-assignment / prototype-pollution → cross-check `/api-testing` and `/prototype-pollution`.
- **IDOR over a token / reset / invite object → account takeover** of arbitrary users.
- Once one impactful instance is proven (and only then), route to `/reporting`. Don't enumerate real users to inflate it.

## Don't report as noise
- Accessing **your own** data, or an object you own from a different endpoint.
- A "missing" control with **no sensitive data or action** behind it (e.g. a public catalog ID).
- Purely theoretical "the ID is sequential" with no demonstrated cross-user access to a concrete victim object.
- Self-XSS-style setups where only the attacker is affected.

## Deep reference
See **reference.md** for the full taxonomy, bypass catalog, and worked examples.
- https://portswigger.net/web-security/access-control
- https://portswigger.net/web-security/access-control/idor
