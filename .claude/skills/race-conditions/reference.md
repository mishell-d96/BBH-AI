# Race Conditions — Deep Reference

Source: https://portswigger.net/web-security/race-conditions
Research: https://portswigger.net/research/smashing-the-state-machine (PortSwigger,
James Kettle — "Smashing the State Machine: The True Potential of Web Race
Conditions", Black Hat USA 2023).
Labs: https://portswigger.net/web-security/all-labs#race-conditions
Burp parallel send docs:
https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group#sending-requests-in-parallel

## What a race condition is
Race conditions occur when a website processes requests concurrently without
adequate safeguards, so the outcome depends on uncontrolled timing. They are a
subclass of business-logic flaw. The **race window** is the interval in which a
collision is possible — typically between a check and the corresponding state
change. The broader framing: many endpoints are **state machines** with hidden,
transient sub-states; concurrent requests let you observe/exploit those
sub-states the developer assumed were atomic.

---

## Vulnerability patterns

### 1. Limit-overrun (TOCTOU)
The classic and most common variant. A limit is enforced by:
(check current value) → (perform action) → (update value). If two+ requests pass
the **check** before any reaches the **update**, all proceed, overrunning the
limit. Examples:
- Redeem a gift card / voucher more than once (credit balance multiple times).
- Reuse a single-use discount/promo code.
- Withdraw or transfer funds beyond the actual balance (double-spend).
- Exceed a per-user cap (votes, applications, seats, coupons, stock units).
- Bypass a rate / OTP / 2FA attempt limit by submitting many guesses in one
  synchronized batch before the counter increments.
TOCTOU = time-of-check to time-of-use: the exploited gap is the temporary
sub-state between validation and the database commit.

### 2. Hidden multi-step sequences
A single HTTP request internally triggers a **multi-step process** with
intermediate sub-states that exist before the response is returned. A parallel
request can land inside that sub-state. Example from the research: during login,
there is a moment where the user is treated as authenticated before MFA/2FA
enforcement is fully applied — a concurrent request can ride that window to reach
authenticated functionality without completing 2FA. Detect by sending a request
that starts the process plus a request that probes the protected state, in
parallel.

### 3. Multi-endpoint race conditions
The collision spans **different endpoints** acting on shared state (e.g. one
endpoint adds an item to a basket while another applies payment/checkout). Hard
part: getting requests to hit the server at the right relative moment because the
endpoints may have different processing times.
- Use **connection warming** (below) to remove first-request latency.
- The single-packet attack ensures simultaneous *arrival*, but back-end
  processing order can still vary — you may need several attempts.

### 4. Single-endpoint race conditions
Parallel requests to the **same endpoint** carrying **different values**, often
within one session. Example: two password-reset requests in the same session for
different users collide so the generated reset token / email mapping is corrupted
(token issued for user A is delivered for user B). State stored in mutable
per-session fields that get overwritten mid-process is the tell.

### 5. Partial construction race conditions
An object is created across **multiple internal operations**, leaving a window
where the object exists but key fields are uninitialized (null/empty/default). A
concurrent request that matches the uninitialized field can act on the
half-built object. Injection trick: send array or nil syntax (PHP `param[]=`,
or omitting a value) so the field is empty/uninitialized during the window,
matching a database NULL/default and granting unintended access (e.g. an API key
or session that hasn't been finalized).

### 6. Time-sensitive attacks
When secrets/tokens are generated with **predictable, non-cryptographic** inputs
(e.g. a timestamp seed), two requests issued at the same instant can produce
**identical tokens** for different users. Send tightly synchronized requests to
collide token generation. This is technically a timing/race issue even when the
"race window" is the shared generation moment rather than a check-then-update.

---

## Detection & exploitation methodology

### Predict — Probe — Prove
1. **Predict.** Identify security-critical endpoints where multiple requests
   could interact with the same record (the same gift card, the same balance,
   the same counter, the same token). This narrows where a collision could
   matter and keeps the number of test requests minimal.
2. **Probe.** Establish a **benchmark** with sequential requests so you know the
   normal response/behavior. Then send requests **in parallel** and look for
   deviations: extra 200s, duplicated side effects, a counter that increments
   fewer times than requests sent, unexpected tokens/states.
3. **Prove.** Work out the underlying mechanism, **remove every request that
   isn't required**, and reproduce reliably with the smallest request count.
   This is essential for a clean, low-noise PoC.

### Synchronization techniques
- **Single-packet attack (HTTP/2).** Place the final frames of 20-30 requests
  into a **single TCP packet** and send it, so all requests are processed in the
  same network event. Eliminates network jitter as a variable — the dominant
  technique from the research. Built into Burp Repeater (v2023.9+) and Turbo
  Intruder.
- **Last-byte synchronization (HTTP/1).** For targets that don't support HTTP/2,
  send all but the **final byte** of each request, wait for the buffers to fill,
  then release the last byte of every request together. Greatly reduces inter-
  request timing variance versus naive parallel sends.
- **Connection warming.** Send one or more inconsequential requests (e.g. `GET /`
  homepage) on the connection first so TCP/TLS/back-end connection setup latency
  doesn't skew the timed batch. Especially important for multi-endpoint races.
- **Inducing delay for jittery targets.** On high-jitter back ends, you can
  intentionally create a small server-side delay (e.g. by abusing a
  rate/resource limit with dummy requests) so the meaningful requests land
  inside a more predictable window for the single-packet attack.

### Tooling
- **Burp Repeater request groups.** Add requests to a group, then **Send group
  in parallel** (uses single-packet attack on HTTP/2, last-byte sync on HTTP/1).
  Best for small, hand-crafted sets — ideal for the minimal PoC.
- **Burp "Trigger race conditions" custom action** automates the parallel send.
- **Turbo Intruder** (Python-scripted extension): use for attacks needing many
  requests, retries, gates, or programmatic control. Supports both the single-
  packet attack and last-byte sync. Use `engine.openGate()` to release a held
  batch simultaneously.

Keep request volume **low** at all times — synchronized timing, not volume, wins
a race. A few-dozen synced requests is the tool; thousands is a DoS and is out of
scope.

---

## Prevention (for triage/report remediation notes)
- Make the check-and-update **atomic**: a single database transaction that both
  verifies and applies the state change, eliminating the sub-state.
- Use **datastore integrity constraints** — uniqueness constraints, conditional
  updates (`UPDATE ... WHERE balance >= amount`), row locking / `SELECT ... FOR
  UPDATE`, optimistic concurrency (version columns).
- Avoid mutating per-session state mid-process; batch state updates so partial
  states aren't observable.
- Don't generate security tokens from predictable/timestamp inputs; use a CSPRNG.
- Consider stateless, signed client-side state (e.g. JWTs) where appropriate —
  with awareness of their own trade-offs.
- Don't rely on framework session locking as a safeguard: it's bypassable with
  distinct session tokens per request.
