# JWT Attacks — Deep Reference

Sources:
- https://portswigger.net/web-security/jwt
- https://portswigger.net/web-security/jwt/algorithm-confusion

Authorization note: only forge tokens for identities you are authorized to test.

## 1. JWT / JWS structure

A JWT (a JWS, in signed form) is three base64url segments joined by dots:

```
<header>.<payload>.<signature>
header   = {"alg":"HS256","typ":"JWT"}     # algorithm + metadata
payload  = {"sub":"alice","role":"user","exp":1700000000}   # claims
signature = HMAC/RSA over base64url(header) + "." + base64url(payload)
```

- base64url decode the first two parts (they are NOT encrypted, just encoded).
- The signature binds header+payload to a key. Forgery = producing a signature the server accepts (or making the server skip verification).
- `alg` is **attacker-controllable** and is read before verification — the root of most attacks.

Key claims to target: `sub`, `username`, `role`, `isAdmin`, `groups`, `scope`, `exp`.

## 2. Working with JWTs in Burp (JWT Editor)

Install **JWT Editor** from the BApp Store. Capabilities:
- Decodes/edits header and payload inline in Repeater (a "JSON Web Token" message tab appears).
- **Keys tab:** create/store RSA keys, symmetric (HMAC) keys; import JWK/PEM; export between formats.
- **Sign** button: re-sign the edited token with a chosen key + algorithm.
- Built-in attacks: **"none"** signing, **"Embedded JWK"** (jwk header injection).

Workflow: intercept a request with a JWT → edit claims in the JSON Web Token tab → Sign (or apply an attack) → forward/replay.

## 3. Flawed signature verification

### 3a. Signature not verified at all
Some code calls a `decode()`-style method (e.g. Node `jsonwebtoken.decode()`) instead of `verify()`, so no signature check happens.
Test: change one payload claim, leave signature untouched, replay. If accepted → no verification. Tamper freely.

### 3b. Accepting unsigned tokens (`alg: none`)
The `none` algorithm means "unsigned". A correct server rejects it for authenticated tokens; many don't.
- Set header `{"alg":"none","typ":"JWT"}`.
- Provide an **empty** signature but keep the **trailing dot**: `header.payload.`
- Filter bypasses: mixed/odd casing (`None`, `NONE`, `nOnE`), unexpected encodings of the `alg` value.

In JWT Editor: edit claims, then use the **"none" signing attack** to emit the token in valid form.

## 4. Brute-forcing weak HMAC secrets (HS256)

Symmetric algorithms (HS256/384/512) sign with a shared secret string. Weak/default secrets crack quickly.

```bash
hashcat -a 0 -m 16500 <jwt> <wordlist>
```

- `-m 16500` = JWT mode, `-a 0` = straight wordlist attack.
- Good wordlist of known/leaked secrets: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
- Output line: `<jwt>:<recovered-secret>`. Re-run with `--show` to redisplay a cracked result.

Once you have the secret, re-sign any tampered token (JWT Editor symmetric key, or PyJWT `jwt.encode(payload, secret, algorithm="HS256")`).

## 5. Header parameter injections

Some headers tell the server which key to use to verify — an injection surface.

### 5a. jwk (embedded public key)
`jwk` embeds a public key directly in the token header. Misconfigured servers verify against whatever key is embedded.
1. Generate your own RSA keypair.
2. Edit claims; embed your **public** key as the `jwk` header.
3. Sign with your **private** key.
JWT Editor: **"Embedded JWK"** attack automates this. Server uses your key → verifies → accepts.

### 5b. jku (JWK Set URL)
`jku` is a URL the server fetches a JWK Set from. If unrestricted, host your own JWK Set and point `jku` at it; sign with the matching private key.
Hardened servers allowlist hosts — bypass with URL-parsing discrepancies:
- `https://trusted.com@attacker.com/jwks`
- `https://attacker.com/jwks#trusted.com`
- `https://trusted.com.attacker.com/jwks`
- open redirect / SSRF on the trusted host pointing to your set.

### 5c. kid (Key ID)
`kid` identifies which key to use; often used as a filename or DB lookup → injectable.
- **Path traversal:** `"kid":"../../../../../../dev/null"`. On Linux `/dev/null` is empty, so the HMAC key is the empty string — sign your token (HS256) with secret `""`. Also try predictable static files whose bytes you know (e.g. a public CSS/JS asset) and use those bytes as the key.
- **SQL injection:** if `kid` parameterizes a DB query that returns the key, inject (e.g. `UNION SELECT` to return an attacker-known value, then sign HS256 with that value).
- **Predictable file:** if `kid` maps to a known key file on disk, use its contents as the verification key.

## 6. Algorithm confusion (RS256 → HS256, "key confusion")

The server signs/verifies with RSA (RS256, asymmetric: private key signs, public key verifies). If verification is done with an algorithm-agnostic method that trusts the `alg` header, an attacker switches `alg` to HS256. The library then treats the RSA **public key** (which is public) as the HMAC secret. Attacker signs HS256 using that public key → server verifies HS256 with the same public key → accepted. Works even with a strong RSA private key, because the public key is known.

### Step 1 — Get the public key
- Standard endpoints: `/jwks.json`, `/.well-known/jwks.json` (JWK objects with `kty`, `e`, `kid`, `n` in a `keys` array).
- If not exposed, derive it from **two** JWTs:
  ```bash
  docker run --rm -it portswigger/sig2n <token1> <token2>
  ```
  (Based on the `rsa_sign2n` project. First run pulls the image.) It calculates candidate `n` values and outputs, per candidate:
  - a base64-encoded PEM key in X.509 and PKCS1 formats, and
  - a forged JWT signed with each candidate.
  Send each forged JWT via Burp Repeater; exactly **one** is accepted → that candidate is the correct public key.

### Step 2 — Convert key to the server's exact byte form (JWT Editor)
1. Keys tab → **New RSA Key**, paste the JWK.
2. Select the **PEM** radio button; copy the X.509 PEM.
3. Decoder tab → **Base64-encode** that PEM.
4. Keys tab → **New Symmetric Key**; replace the `k` value with your base64 PEM. Save.
   Critical: every byte (including non-printing chars / trailing newline) must match the server's local copy of the public key.

### Step 3 — Forge
Edit claims, set header `alg` to **HS256**, sign with the symmetric key built from the public key. Send. Server verifies HS256 against its public key → token accepted.

## 7. Prevention (for triage / report remediation advice)
- Use maintained JWT libraries; verify with explicit allowed algorithms (don't trust the `alg` header).
- Always **verify** signatures (never `decode`-only); reject `none`.
- Pin the verification algorithm so RS256 tokens can't be verified as HS256.
- Enforce a strict host allowlist for `jku`; resolve and validate fully.
- Sanitize/parameterize `kid`; guard against path traversal and SQLi.
- Set `exp`, validate `aud`/`iss`, support revocation.
- Use strong, high-entropy HMAC secrets (not dictionary words/defaults).
