---
name: jwt
description: Attacks JSON Web Tokens (JWT) used for auth/session/claims — forges tokens to escalate privileges, bypass auth, or take over accounts via weak signature handling. Use when you see a JWT/Bearer token (eyJ... three base64url parts separated by dots), an alg header, the none algorithm, HS256/RS256 signing, jwk/jku/kid header params, a weak/guessable signing secret, or RS256→HS256 algorithm confusion. Triggers: decoded token shows role/admin/sub claims, signature not enforced, brute-forcing HMAC secret with hashcat, header injection, kid path traversal/SQLi.
---

# JWT Attacks

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Forge or tamper with JSON Web Tokens to break authentication and authorization. The win is a server **accepting** a token you control with elevated/altered claims.

## When to test
Any JWT used for auth, session, or access-control claims. Identify a JWT by three base64url segments separated by dots (`eyJ...`); the first two decode to JSON. Look in `Authorization: Bearer`, cookies, and request/response bodies.

**Scope gate:** Only forge tokens for accounts/identities you are explicitly authorized to test. Never mint a token impersonating a real user/admin you don't own.

## Impact & priority
High-signal, report-worthy:
- **Auth bypass / privilege escalation** (flip `"isAdmin":true`, change `role`) — P2, often P1.
- **Account takeover** (change `sub`/`username` to another user) — P1.
- **Forge arbitrary valid tokens** (cracked secret, none alg, jwk/jku/kid, algorithm confusion) — P1/P2.

Priority is driven by what the forged token *does*, not by the technique.

## Detection
1. Decode header + payload (base64url) — note `alg`, `kid`, `jku`, `jwk`, and claims (`sub`, `role`, `isAdmin`, `exp`).
2. **Test signature enforcement:** change a payload claim WITHOUT re-signing and replay. If accepted → signature not verified.
3. **Test none:** set `alg` to `none` (try `None`, `NONE`, `nOnE`), strip the signature, keep the trailing dot. If accepted → unsigned tokens trusted.
4. Inspect for `kid`/`jku`/`jwk` header params (injection surface).
5. If HS256, try cracking the secret (cheap, fast).

## Exploitation
- **Signature not verified:** library used `decode()` not `verify()`. Tamper any claim, send.
- **none algorithm:** `{"alg":"none"}`, empty signature, trailing dot retained. Bypass filters with mixed case / unexpected encodings.
- **Weak HMAC secret (HS256):** crack with hashcat, re-sign with the recovered secret (see PoC).
- **kid path traversal:** `"kid":"../../../../dev/null"` forces an empty/known file as the HMAC key → sign with empty string. Or point at a predictable static file whose contents you know.
- **kid SQLi:** if `kid` indexes a DB lookup for the key, inject to return an attacker-known value.
- **jwk injection:** embed your own public key in the `jwk` header, sign with your private key (Burp JWT Editor "Embedded JWK" attack).
- **jku injection:** point `jku` at a JWK Set you host; bypass host allowlists with URL parsing tricks.
- **Algorithm confusion (RS256→HS256):** sign with the server's RSA **public** key used as the HMAC secret. See reference.md for deriving the key from two tokens via `portswigger/sig2n`.

## Common bypasses
none-alg filter evasion, jku host-allowlist URL parsing tricks, kid traversal to `/dev/null`, exact-byte public-key matching for algorithm confusion. Full detail and Burp JWT Editor workflow in **reference.md**.

## Minimal PoC
Keep it minimal and safe: ONE forged token, an authorized identity, proof the server honored the elevated claim. Log to `./_EXPLOIT/`.

Forge via cracked HS256 secret (PyJWT):
```python
import jwt  # PyJWT
forged = jwt.encode({"sub":"<your-authorized-test-user>","isAdmin":True}, "secret123", algorithm="HS256")
print(forged)
```
Or none-alg (no secret needed):
```
header  = base64url({"alg":"none","typ":"JWT"})
payload = base64url({"sub":"<authorized-test-user>","isAdmin":true})
token   = header + "." + payload + "."     # note trailing dot, empty signature
```
Capture the privileged response (e.g. an admin-only endpoint returning 200 / admin data) as proof. Log token + request + response to `./_EXPLOIT/`.

## Chain for impact
A forged or elevated token is a means, not the end:
- **Tampered claims (alg confusion / `none` / cracked secret) → privilege escalation** → `/access-control-idor` for admin-only functions.
- **Forged identity → full account takeover** → corroborate via `/authentication`.
- **`jku` / `x5u` / `kid` header injection → `/ssrf`** (server fetches an attacker URL) or path traversal.
- Prove one accepted forged token with an elevated effect, then `/reporting`.

## Don't report as noise
- "JWT is decodable / claims are readable" — JWTs are **not** secret; this alone is nothing.
- Missing `exp`, no `aud`, no rotation — cosmetic without a working forgery.
- A tampered token that the server **rejects** — no impact, no report.
- Theoretical algorithm confusion you couldn't get the server to accept.
Only report a token the server **accepted** that grants something you shouldn't have.

## Deep reference
See **reference.md** for full structure, Burp JWT Editor workflow, hashcat usage, header-injection details, and the algorithm-confusion walkthrough.
- https://portswigger.net/web-security/jwt
- https://portswigger.net/web-security/jwt/algorithm-confusion
