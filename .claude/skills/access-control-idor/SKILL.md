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
Two-account method is the gold standard:
1. Authenticate as **two** low-priv users (A and B) and ideally one admin.
2. As A, capture every request that references an object or privileged action.
3. Replay A's requests using **B's session** (and B's object IDs in A's session). If A can read/modify B's resource, that's IDOR.
4. As a low-priv user, hit admin/privileged endpoints directly (forced browsing): `/admin`, links from `robots.txt`, JS-leaked hidden URLs, wordlist brute force.
5. **Compare responses** — status, length, body. Watch for redirects that still leak the body. GUIDs aren't safe if they leak elsewhere (messages, reviews, API listings).

## Exploitation
**Vertical escalation**
- *Unprotected functionality*: admin URL has no server-side check — request it directly (`/admin`, hidden `/administrator-panel-yb556` found in client JS).
- *Parameter-based roles*: role/privilege carried in a user-controllable place — flip `admin=true`, `role=1`, `isAdmin`, hidden field, or cookie.
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
