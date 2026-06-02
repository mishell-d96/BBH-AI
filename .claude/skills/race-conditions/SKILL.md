---
name: race-conditions
description: "Race conditions — concurrent requests colliding in a TOCTOU window to overrun a limit or skip a state check. Use for 'once only' actions: coupon/gift-card redemption, withdrawal/transfer, OTP/2FA attempt counters, single-use tokens, limit-overrun, double-spend. Single-packet attack."
---

# Race Conditions

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Any action the app treats as **"once only" or limited**, where a check is
followed by a state update: redeem (coupon/gift-card/voucher), withdraw/transfer
funds, vote, apply, claim a seat/slot, spend a balance, consume a single-use
token, or increment an attempt counter (rate-limit / OTP / 2FA). The bug lives
in the **race window** between time-of-check and time-of-use (TOCTOU): fire
multiple requests concurrently so several pass the check before any commits.

## Impact & priority (honest)
- **High signal:** anything financial or limit-overrunning — redeem a gift card
  N times, withdraw beyond balance (double-spend), brute past a rate/OTP limit,
  claim more units than allowed. Direct $ or auth impact → report.
- **Medium:** hidden multi-step / state-machine bypass (e.g. access before MFA
  enforcement commits), partial-construction privilege gain.
- **Noise — do NOT report:** races with no security or financial consequence
  (duplicate analytics rows, cosmetic counter drift, idempotent endpoints,
  duplicates the app dedupes/reconciles anyway). No impact = no report.

## Detection — Predict, Probe, Prove
1. **Predict:** pick endpoints where concurrent requests touch the **same
   record** and a limit/uniqueness matters. Keeps test scope (and volume) tiny.
2. **Probe:** benchmark sequentially first (know the normal response), then send
   a **small** batch (e.g. ~10-20) in parallel and diff the behavior — extra
   successes, duplicated effects, counter under-increment.
3. **Prove:** find the mechanism, drop every non-essential request, and
   reproduce consistently with the **minimum** request count.

Keep volume LOW. This is timing, not flooding — a handful of synced requests
beats a storm. Never turn it into a DoS.

## Exploitation patterns
- **Limit-overrun:** parallel requests each pass the limit check before the
  decrement/insert commits (classic gift-card / discount / withdrawal).
- **Hidden multi-step sub-states:** one request kicks off a multi-stage process;
  a parallel request slips into the transient sub-state (e.g. authenticated
  before 2FA enforcement lands).
- **Multi-endpoint:** different endpoints racing on shared state; usually needs
  **connection warming** to align arrival.
- **Single-endpoint:** same endpoint, different values, same session — e.g. two
  resets colliding so a token is issued for a different user.
- **Partial construction:** object built across steps; inject array/nil syntax
  (PHP `param[]=`) to match an uninitialized field mid-creation.

**Synchronization:**
- **Single-packet attack (HTTP/2):** pack 20-30 requests into one TCP packet to
  erase network jitter. Burp Repeater group → *Send in parallel*; or Turbo
  Intruder.
- **Last-byte synchronization (HTTP/1):** withhold final byte of each request,
  then release together. Same tools.

## Common bypasses
- **Session-based locking** (e.g. PHP serializes requests per session): give
  each parallel request a **distinct session token** so they run concurrently.
- **Connection warming:** send a cheap, harmless request (GET homepage) first to
  prime back-end connections; on jittery targets, induce a small server-side
  delay to widen the window for the single-packet attack.

## Minimal PoC (for ./_EXPLOIT/)
Capture a **safe, low-volume** repro proving the collision, e.g. double-spend:
1. Baseline: one redeem → balance/limit moves by exactly one.
2. Attack: send N (small) identical redeems in a single synced batch
   (Repeater group "Send in parallel" or Turbo Intruder single-packet).
3. Evidence: M>1 successes against a single-use limit (e.g. one $10 gift card
   credited twice). Log: request, count sent, count succeeded, before/after
   state, and the exact tool/sync method. Keep N minimal — just enough to win.

## Don't report as noise
If you cannot show a concrete security or financial effect (real over-spend,
real auth/limit bypass, real privilege gain), it is not a finding. Cosmetic or
self-healing races are noise — drop them.

## Deep reference
See `reference.md` for full mechanics of each pattern, sync techniques, tooling,
and prevention.
- https://portswigger.net/web-security/race-conditions
- https://portswigger.net/research/smashing-the-state-machine
