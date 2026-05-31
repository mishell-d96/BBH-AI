# HTTP Request Smuggling — Deep Reference

Comprehensive reference for the `request-smuggling` skill. Sources:
- https://portswigger.net/web-security/request-smuggling
- https://portswigger.net/web-security/request-smuggling/finding
- https://portswigger.net/web-security/request-smuggling/exploiting
- https://portswigger.net/web-security/request-smuggling/advanced
- https://portswigger.net/web-security/request-smuggling/browser

> SAFETY FIRST: Request smuggling manipulates state on a connection that is
> **shared between users**. A poisoned prefix is executed against whoever's
> request arrives next on that back-end connection. Treat every technique below
> as something that can harm uninvolved people. Keep PoCs self-targeted,
> low-volume, on harmless paths, and stop at minimal confirmation.

---

## 1. How desync arises

Modern apps chain HTTP processors: a front-end (CDN, reverse proxy, WAF, load
balancer) forwards requests over a (often reused) back-end connection to the app
server. Both must agree exactly where each request's body ends. HTTP/1.1 offers
two ways to declare body length:

- **Content-Length (CL):** a byte count, e.g. `Content-Length: 11`.
- **Transfer-Encoding: chunked (TE):** the body is a series of chunks, each
  prefixed by its size in hex on its own line, terminated by a `0` chunk
  followed by `\r\n\r\n`:
  ```
  b\r\n
  q=smuggling\r\n
  0\r\n
  \r\n
  ```

The spec says if **both** headers are present, `Content-Length` must be ignored
(or the message rejected). In practice, chained servers handle the ambiguity
differently. If the front-end uses one header to find the body end and the
back-end uses the other, the front-end forwards bytes the back-end interprets as
the **start of the next request** — those bytes are the "smuggled prefix" that
gets glued onto the next user's request.

Desync persists as long as the front-end<->back-end connection is reused. Some
variants (CL.0, client-side desync) work even on single-server / non-reused
setups.

---

## 2. Classic variants

### CL.TE
Front-end uses **C**ontent-**L**ength; back-end uses **T**ransfer-**E**ncoding.
Front-end forwards the full CL-bounded body; back-end stops at the chunked
terminator and treats the remainder as a new request.

Detection (timing) — front-end forwards only `CL` bytes, omitting `X`; back-end
finishes the `1`/`A` chunk and **blocks waiting for the next chunk**:
```
POST / HTTP/1.1
Host: vulnerable.example
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

Confirmation (differential) — smuggle a fake request that breaks the *follow-up*:
```
POST /search HTTP/1.1
Host: vulnerable.example
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x
```
A benign follow-up then receives a 404, confirming the smuggled `GET /404`
prefixed it.

### TE.CL
Front-end uses **T**ransfer-**E**ncoding; back-end uses **C**ontent-**L**ength.

Detection (timing) — front-end forwards the chunked body and omits `X`; back-end
honours `Content-Length: 6` and **blocks waiting for more bytes**:
```
POST / HTTP/1.1
Host: vulnerable.example
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
> **Order matters:** always test **CL.TE first**. If the target is actually
> CL.TE, a TE.CL probe can leave a dangling smuggled prefix that disrupts real
> users.

Confirmation — the chunk size is the hex length of the smuggled request block:
```
POST /search HTTP/1.1
Host: vulnerable.example
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0


```
In Burp Repeater: disable **Update Content-Length**, and ensure the trailing
`\r\n\r\n` after the final `0` is present.

### TE.TE (obfuscated TE)
Both servers support `Transfer-Encoding`, but one is induced to **ignore** a
deliberately malformed variant so it falls back to `Content-Length` — collapsing
to a CL.TE or TE.CL underneath. Obfuscation examples (one must be tolerated by
one server, rejected/ignored by the other):
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:\tchunked          (tab)
Transfer-Encoding: chunked\r\nTransfer-Encoding: x   (duplicate)
Transfer-Encoding:[space]chunked
X: X\nTransfer-Encoding: chunked     (header folding / smuggled via LF)
```
Test variants one at a time; identify which server you tricked, then proceed as
CL.TE or TE.CL.

---

## 3. HTTP/2 desync variants

When a front-end speaks HTTP/2 to clients but **downgrades to HTTP/1.1** to the
back-end, it rewrites the H2 message into H1 syntax. H2 carries length implicitly
in its framing, so any `content-length`/`transfer-encoding` *inside* the H2
message is attacker-controlled metadata that may not be reconciled with the true
frame length.

- **H2.CL:** attacker injects a `content-length` header in the H2 request that
  disagrees with the actual H2 body length. On downgrade the back-end trusts the
  injected CL → boundary mismatch → smuggling.
- **H2.TE:** attacker injects `transfer-encoding: chunked` into the H2 request.
  The spec says front-ends must strip TE from H2 (chunked is illegal in H2). If
  the front-end fails to, the downgraded H1 request carries chunked encoding the
  back-end honours → smuggling.
- **HTTP/2 CRLF injection:** H2's binary framing lets header *values* contain
  raw `\r\n` without splitting the header. On downgrade these re-arm as HTTP/1
  delimiters, enabling header injection / request splitting (e.g. inject a whole
  smuggled request via a header value).
- **Pseudo-header / request-line injection:** manipulating `:path`, `:method`,
  `:authority` during downgrade can construct ambiguous request lines.

HTTP/2 **end-to-end** (no downgrade) is the robust defence; these variants
require a downgrade step.

---

## 4. CL.0, 0.CL, and client-side desync

### CL.0
The back-end **ignores `Content-Length` entirely** on certain endpoints (e.g.
static handlers, redirects, some servers/methods) — effectively ignoring the
request body. The body you send is then parsed as the next request. Works
**single-server**, no chunking or H2 needed.
Probe: send a request to a CL.0-prone endpoint with a smuggled `GET /<path>` in
the body and watch whether the follow-up on the same connection returns the
smuggled path's response. Endpoints that return static content or redirects
regardless of body are prime candidates.

### 0.CL
Inverse: the **front-end** ignores the body while the **back-end** honours
`Content-Length`. Less common; detected by pause-based techniques.

### Client-side desync (CSD)
Uses **fully browser-compatible HTTP/1 requests** to trigger desync between the
victim's own browser and the server — no specialist client needed. Enables:
- attacks on single-server sites otherwise immune to smuggling,
- client-side cache poisoning (including intranet/internal sites),
- credential theft and internal pivoting via the victim's browser.
The attacker hosts JS that makes the victim's browser send a request whose body
the server treats as a second request, poisoning the victim's own connection.

### Pause-based desync
Send the headers, promise a body, then **wait**. Reveals latent server-side and
client-side desync that timing probes miss (e.g. a server that times out and
re-parses the buffered bytes as a new request). Applies to both CL.0-style and
classic flows; useful on "seemingly secure" targets.

---

## 5. Detection methodology

1. **Fingerprint the chain.** Confirm a front-end exists (`Via`, `X-Cache`,
   `CF-RAY`, `Server`, distinct error pages, header reordering/casing). Note
   whether HTTP/2 is offered and whether it's downgraded.
2. **Timing probes (lowest risk first).** Run CL.TE timing, then TE.CL, then
   CL.0 / H2 probes. A reproducible multi-second delay vs a control request is a
   desync signal — but timing alone is **not** a finding.
3. **Differential confirmation.** Over a **fresh** connection, send an attack
   request that smuggles a prefix breaking a **self** follow-up (route it to a
   harmless `/<random>` 404), then immediately send the benign follow-up on a
   separate connection. An anomalous follow-up response confirms the desync.
   - Use the **same URL and parameter names** so both requests hit the same
     back-end pool.
   - Send the follow-up **immediately** after the attack.
   - Expect **races** with real traffic; retry. If you can't reproduce cleanly,
     do not escalate.
4. **Identify the exact variant** (which server uses CL vs TE) before any
   exploitation, so payload sizing is correct and predictable.

Automate with Burp **HTTP Request Smuggler** (probes CL.TE / TE.CL / CL.0 / H2
desync, smuggle-probe + scan) and **Turbo Intruder** for precise timing/HTTP/2
control. Always disable "Update Content-Length" for manual crafting.

---

## 6. Exploitation techniques (in depth)

> Only proceed past detection if you can do so **without affecting other users**.
> Prefer self-targeted demonstrations. Stop at minimal proof.

- **Bypass front-end access controls.** Front-end authorises the outer
  `/home`; the smuggled `/admin` (or other restricted path) is processed by the
  back-end with no further checks. Also inject headers the front-end normally
  sets/strips — e.g. `X-SSL-CLIENT-CN: administrator` for mTLS-derived identity,
  internal auth headers, `X-Forwarded-For`.
- **Reveal front-end request rewriting.** Smuggle a POST whose reflected param
  is placed **last** in the body; the back-end appends the next request's
  rewritten form (added headers, IP, session-derived data) into your stored
  value, exposing what the front-end injects.
- **Capture other users' requests.** Smuggle a POST to a storage feature
  (comment/profile/email) with an **oversized `Content-Length`**; the victim's
  subsequent request fills the gap and is stored (session cookies, tokens, PII).
  Captured data usually truncates at the first delimiter (`&`).
- **Reflected XSS amplification.** Deliver reflected XSS — including in headers
  like `User-Agent` that are otherwise hard to control — to the next user with
  **no interaction**.
- **On-site redirect -> open redirect.** If the app redirects using the `Host`
  header (or protocol-relative `//attacker.com/...` paths), smuggle an
  attacker-controlled host so the next user is redirected off-site (dangerous
  when their request was for an imported JS resource).
- **Web cache poisoning.** Smuggle a request yielding an off-site redirect, then
  a normal request; the cache stores the malicious response against the second
  request's URL — served persistently to all users of that URL.
- **Web cache deception.** Smuggle a request for a victim-specific sensitive
  endpoint (e.g. `/private/messages`); the victim's request appends, the back-end
  serves it in the victim's session, and the cache stores that private response
  under a **static** URL the attacker can later fetch. The caching URL is often
  unknown in advance — may require probing several static URLs.
- **Response queue poisoning.** Desynchronise the **response** stream so the
  back-end's responses are returned to the wrong requests, letting the attacker
  steal arbitrary users' full responses (account takeover). Extremely high
  impact **and** extremely high blast radius — do not run against live user
  traffic.
- **Request tunnelling.** Tunnel a second request through the front-end even
  with **no connection reuse**, leaking internal/front-end-added headers or
  poisoning caches. Often paired with HTTP/2 downgrade / CRLF injection.

---

## 7. Tooling

- **Burp HTTP Request Smuggler** (James Kettle): automated CL.TE / TE.CL / TE.TE
  / CL.0 / HTTP/2 desync probing, smuggle-probe scanner, and PoC generation.
- **Turbo Intruder:** scriptable, precise control over timing, connection reuse,
  and raw HTTP/2 frames — essential for timing probes and HTTP/2 variants.
- **Burp Repeater:** manual crafting; disable **Update Content-Length**, send
  raw, and use the HTTP/2 tab's "Inspector" to inject illegal headers/pseudo-
  headers for H2.CL / H2.TE testing.
- Keep raw request/response captures and a timing table for `./_EXPLOIT/`.

---

## 8. Prevention (for reporting/remediation advice)

- **Use HTTP/2 end-to-end** and disable HTTP downgrading to HTTP/1.1 where
  possible — eliminates most classic and H2 desync.
- If downgrading is unavoidable, **normalise**: reject ambiguous messages, never
  forward both `Content-Length` and `Transfer-Encoding`, strip/validate `TE` on
  H2->H1, and reconcile injected lengths with true frame length.
- Make front-end and back-end use **identical parsing** (same server software /
  config) so boundary interpretation can't diverge.
- Reject obfuscated `Transfer-Encoding` and malformed requests outright rather
  than tolerating them.
- Disable back-end connection reuse where feasible (mitigates blast radius but is
  not a complete fix).

---

## 9. Reporting bar (don't submit noise)

A valid report needs a **reproducible differential confirmation** of an actual
boundary disagreement, the identified variant, the front-end/back-end
fingerprint, and a concrete demonstrated impact. Do **not** report: timing blips
without differential confirmation; the mere presence of both CL and TE headers;
"possibly vulnerable" header observations; or any impact you can only show by
harming uninvolved users.
