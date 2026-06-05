---
name: custom-opaque-tokens
description: "Custom / opaque (non-JWT) bearer & session tokens — decode, find embedded creds/PII, break weak signatures, forge. Use for any long base64/base64url/hex value, delimiter-split tokens (a:b:c, a.b.c, a|b, a~b), or Authorization: Bearer / X-Auth / X-Token / session cookie whose value does NOT start with eyJ. Covers decode ladder, embedded password/role/tenant disclosure, unverified-signature replay, no-secret md5/sha forge, HMAC crack, key-selector injection, predictability."
---

# Custom / Opaque Token Attacks

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Home-grown bearer/session tokens that are **not** JWTs. The win is the same as `/jwt`: a server **accepting** a token you control with elevated/altered identity — but first you must reverse the format, because there's no standard. Same verify-vs-decode mindset: a token you can *read* is nothing; a token the server *trusts after you tamper* is everything.

## When to test
Any non-JWT value used for auth/session/access-control:
- `Authorization: Bearer <value>` where the value does **not** start with `eyJ`.
- `X-Auth`, `X-Token`, `X-Api-Key`, `Cookie: session=…`, `auth=…`, body fields.
- Long base64 / base64url / hex strings, or delimiter-split tokens: `a:b:c`, `a.b.c`, `a|b`, `a~b`, `a-b`.

If it starts with `eyJ` (or two/three dot-separated base64url JSON segments) → use `/jwt` instead.

**Scope gate:** only decode/forge tokens for accounts you're authorized to test. Never mint a token impersonating a real user/admin you don't own.

## Impact & priority
- **Embedded credential / PII disclosure** (token decodes to email/password/role/tenant) — P3 standalone, **P1 if a live password** (= ATO primitive).
- **Unverified signature** → tamper identity fields → **priv-esc / ATO** — P1/P2.
- **No-secret forge** (sig is a plain hash you can recompute) → forge any token — P1.
- **Cracked HMAC secret** → forge any token — P1/P2.
- **Predictable token** (counter/epoch/low entropy) → guess other users' sessions — P1/P2.

Priority is driven by what the controlled token *does*, not the technique.

## Decision tree (ordered, cheapest-first)
Run top-down; stop when you have a controlled-token acceptance.

1. **DECODE LADDER** — split on `: . | ~ -`. Per segment try `{base64, base64url, hex, urldecode}` and **recurse** until no further decode. Classify each segment: plaintext / numeric / timestamp / hash-shaped (16/20/32/64 hex) / random. Route binary through a file or python, **never** `echo|cut` (`cut -d:` shreds binary and real colons — use `tail -c +N` byte offsets).
2. **CREDENTIAL/PII CHECK** — any segment decoding to user / email / password / role / tenant_id is a **standalone disclosure finding AND a chain seed** → route `/information-disclosure` + `/access-control-idor`; a live password = `/authentication` ATO. **Finding an embedded credential is NOT the finish line — it is step 2 of 7.** The bigger wins (unverified sig, segment injection) are below; always run the tree to completion.
2b. **EVERY DECODED SEGMENT IS ATTACKER-CONTROLLED INPUT RE-PARSED ON EACH REQUEST.** The auth filter that validates the token decodes your segments and uses them server-side — typically in the **same DB lookup as the login endpoint**. So the identity segment (`user`/`tenant`/`id`) is its own **injection sink**: put `'` in it and look for a break (DB error) → then `admin'-- ` / `' OR '1'='1'-- ` to bypass the password check **inside the token-validation path** (a code path independent of `/login` — it can be injectable even if login is fixed). Test SQLi/XPath/LDAP in each identity segment, not just decode it.
3. **SIGNATURE PROBES** (cheapest-first): (a) tamper one byte of a **non-signature** field and replay — accepted ⇒ signature unverified (the single highest-value 1-request test); (b) strip/blank the sig segment; (c) swap in a sig from another of **your own** tokens; (d) flip a declared `alg`/`type` field down.
4. **NO-SECRET FORGE** — recompute `md5`/`sha1`/`sha256` over candidate message strings; sig length hints algo (32hex=MD5, 40=SHA1, 64=SHA256). A match ⇒ freely forgeable, no cracking.
5. **HMAC CRACK** — recover the signed-message format, convert sig b64→hex, `hashcat` generic modes 50/150/1450/1750 (`key=pass`). NOT the `+10` salt variants, NOT `16500` (JWT-only).
6. **KEY-SELECTOR INJECTION** — a field naming/indexing the verify key (`kid`/`kver`/`tenant`/`env`) → traversal-to-known-file / SQLi / weak-key selection.
7. **PREDICTABILITY** — collect 2–3 samples, diff static-vs-variable, hunt counters / epoch / low-entropy identity fields.

## Worked mini-example
Token (cookie): `dXNlcg==:cGFzczEyMw==:9d5e...`  → form is `base64(user):base64(pass):sig`.
- Decode ladder, seg 1 → `user`, seg 2 → `pass123` (**live password → ATO primitive**, P1).
- Signature probe (a): request `victim`'s token as `base64(victim):base64(any):` (empty sig) — server returns victim's account ⇒ **signature unverified + offline forgery**. Two findings, one chain.

## Minimal PoC
Keep it minimal and safe: ONE controlled token, an authorized identity, proof the server honored it (decoded password shown redacted, or a tampered-identity request returning the other account). Log token + request + response to `./_EXPLOIT/`.

```bash
# DECODE LADDER on a colon-split token (binary-safe; no echo|cut)
TOK='dXNlcg==:cGFzczEyMw==:9d5e0fa1...'
i=1; printf '%s\n' "$TOK" | tr ':.|~' '\n\n\n\n' | while IFS= read -r seg; do
  printf 'seg%d raw : %s\n' "$i" "$seg"
  printf '%s' "$seg" | base64 -d 2>/dev/null | xxd | head -3   # base64
  printf '%s' "$seg" | xxd -r -p 2>/dev/null   | xxd | head -3   # hex
  i=$((i+1))
done
```
```bash
# NO-SECRET FORGE check: is sig just a hash of the message?
MSG='user:pass123'; SIG='9d5e0fa1...'
for h in md5sum sha1sum sha256sum; do printf '%s' "$MSG" | $h; done | grep -i "$SIG" && echo "FORGEABLE: sig == plain hash"
```

## Chain for impact
A controlled opaque token is a means, not the end:
- **Embedded password/role → ATO / priv-esc** → `/authentication`, `/access-control-idor`.
- **Unverified sig / no-secret forge → forge any identity** → `/access-control-idor` for admin functions, `/authentication` for ATO.
- **Key-selector field fetches a file/URL → `/ssrf` or `/path-traversal`**.
- Prove one accepted controlled token with an elevated effect, then `/reporting`.

## Don't report as noise
- "Token is base64-decodable / readable" — encoding is not secrecy; this alone is nothing.
- A tampered token the server **rejects** — no impact, no report.
- Theoretical entropy concerns with no demonstrated guess/forge.
Only report a token the server **accepted** that grants something you shouldn't have — or a decoded **secret/PII** with real sensitivity.

## Deep reference
See **reference.md** for the full decode ladder, classification table, byte-offset binary handling, hashcat generic-mode table, and the forge walkthroughs.
- https://portswigger.net/web-security/authentication
- Cross-link: `/jwt` (verify-vs-decode mindset), `/authentication`.
