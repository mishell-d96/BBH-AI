---
name: business-logic
description: "Business/application logic flaws — abusing legitimate functionality. Use for multi-step workflows (checkout, KYC, reset), price/quantity/discount tampering, negative numbers, rounding, parameter removal, excessive client-side trust, coupon/refund/gift-card abuse, state-machine skipping, replay."
---

# Business logic vulnerabilities

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Flaws in the design and implementation of an application that allow an attacker
to elicit **unintended behavior** by manipulating legitimate functionality.
They arise from flawed developer **assumptions** about how users will interact —
not from a single broken endpoint. They are invisible during normal use; you
find them by understanding the domain and then breaking assumptions.

## When to test
- Multi-step flows where order/state matters: checkout, signup, password reset, 2FA, KYC, onboarding.
- Anywhere money, points, credit, quantity, or discounts are computed.
- Anywhere client-side controls (hidden fields, JS validation, prices in the request, `role`/`isAdmin` params) gate a server action.
- Anywhere a value is encrypted and the ciphertext is handed back to the user.
- Anywhere an email address or domain decides authorization (e.g. `@company.com` -> admin).

## Impact & priority (be honest)
- **P1/P2** — direct $ loss (buy at manipulated/negative price, infinite credit, free refunds), privilege escalation, auth/2FA bypass, access to other tenants' data.
- **P3** — limited abuse with a real but bounded business cost (e.g. exceed a per-user limit).
- **Noise** — theoretical workflow oddity with no business or monetary impact, no privilege/data gain. Do NOT report.

## Detection (map, then break)
1. **Map the intended workflow.** Walk it normally in a proxy. Note every parameter, state transition, and server-side decision point. Write down the developer's implicit assumptions.
2. **Enumerate the assumptions** — "user must pass step N before N+1", "price comes from us", "amount is positive", "this param is always present", "only browsers submit this", "this user was trusted at login so stays trusted".
3. **Break each assumption** and observe whether server-side state/validation actually re-checks it.

## Exploitation
- **Excessive client-side trust** — intercept and edit values the client computes/validates: price, total, currency, `quantity`, `discount`, `role`, `userId`, hidden fields. Server must re-derive, not trust.
- **Unconventional input** — submit negative numbers, zero, decimals/extreme precision, huge values, integer overflow, abnormally long strings, unexpected types/arrays/null. Classic: negative transfer/quantity reverses the money flow.
- **Flawed assumptions about user behavior** — remove or empty "mandatory" params (functions keyed on param presence); replay steps out of order / forced browsing to skip 2FA or validation; abuse "trusted once = trusted forever" where controls are only enforced early.
- **Domain-specific flaws** — re-read business rules adversarially. e.g. earn a 10%-off-over-$1000 discount, then remove items but keep the discount; stack coupons; refund more than paid; exploit rounding to mint fractional currency.
- **Encryption oracle** — if user input is encrypted and the ciphertext returned (e.g. in a cookie/"stay logged in"), use the app to encrypt attacker-chosen data, then feed that ciphertext where the app expects identically-encrypted trusted input.
- **Email parser discrepancies** — when domain decides access, craft an address that passes registration validation but is parsed differently elsewhere (encoding, comments, sub-addressing, unicode) so it resolves to a privileged domain.

## Common bypasses
- Re-apply/recompute the trusted value AFTER the privileged action (discount-then-modify-cart).
- Delete a parameter entirely rather than altering it.
- Reorder/replay requests; jump straight to the final step.
- Change type: string -> array, number -> negative/float, omit -> null.
- Reuse a valid encrypted token from one feature in another.

## Minimal PoC (for ./_EXPLOIT/)
Capture the **smallest** request sequence that proves the abuse and its $ / privilege impact. Prove it via a **state delta (ledger/balance), not a reflected `"success":true`** — a 200 with a happy message means nothing if the balance never moved. Read state before, tamper, read state after:
```bash
T=https://TARGET; TOK=eyJ...   # program-issued token

# 1. balance BEFORE
curl -s "$T/api/account/A" -H "Authorization: Bearer $TOK" | jq '.balance'

# 2. tamper: negative amount reverses the money flow (B -> A)
curl -s -X POST "$T/api/transfer" \
  -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"from":"A","to":"B","amount":-100}'

# 3. balance AFTER — finding is real ONLY if the delta is wrong (A went UP)
curl -s "$T/api/account/A" -H "Authorization: Bearer $TOK" | jq '.balance'
```
Log: exact requests/responses, the assumption broken, the **before/after delta** that proves it, and one-line impact ("$100 transfer to B credited $100 to A instead"). Keep it non-destructive — one proof transaction, do not drain real inventory or balances.

**When also test race:** If the value gates a once-only or balance-limited action (transfer, withdrawal, coupon, refund), also run `/race-conditions` — the single-packet double-spend is the sibling test on the same endpoint.

## Don't report as noise
- Workflow you can complete out of order but that yields no privilege/data/$ gain.
- Negative/odd input the server actually rejects or normalizes.
- Client-side-only validation where the server independently re-validates.
- "Best practice" hardening with no demonstrable exploit.

## Deep reference
See `reference.md` for full categories, examples, and prevention.
- https://portswigger.net/web-security/logic-flaws
- https://portswigger.net/web-security/logic-flaws/examples
