# Custom / Opaque Token Attacks — Deep Reference

Sibling mindset: `/jwt`. The difference is **there is no standard** — you reverse the format first, then apply the same verify-vs-decode tests. Cross-link `/authentication` for ATO framing.

Authorization note: only decode/forge tokens for identities you are authorized to test.

## 1. Recognising an opaque token

Not a JWT (no leading `eyJ`, not two/three dot-separated base64url-JSON segments). Common shapes:

| Shape | Example | Likely meaning |
|-------|---------|----------------|
| Single base64/base64url blob | `dXNlcjoxMjM0NTo5ZDVl…` | one container, often `field:field:sig` once decoded |
| Delimiter-split | `a:b:c`, `a.b.c`, `a\|b`, `a~b`, `a-b` | per-segment `data … sig` |
| Single long hex | `9d5e0fa1c3…` (32/40/64+) | hash, or hex-encoded container |
| Mixed | `2:1717000000:9d5e…` | `userid:issued_at:sig` |

base64url uses `-`/`_` instead of `+`/`/` and usually drops `=` padding — re-pad to a multiple of 4 before decoding (`val="${seg}$(printf '%*s' $(((4-${#seg}%4)%4)) '' | tr ' ' '=')"`).

## 2. DECODE LADDER (step 1)

Goal: split, decode every segment through every codec, and **recurse** until nothing decodes further.

1. **Split** on the delimiter set `: . | ~ -` (try each; the right one yields clean segments).
2. **Per segment**, attempt in order: `base64`, `base64url`, `hex`, `urldecode`.
3. If a decode yields more structure (another delimiter, more base64), **recurse**.
4. **Classify** each terminal segment:

| Class | Test |
|-------|------|
| plaintext | printable, dictionary-ish (`alice`, `admin`, `prod`) |
| numeric | all digits — userid / counter |
| timestamp | 10-digit (~1.7e9) epoch seconds, or 13-digit ms |
| hash-shaped | hex of length **16=MD5-trunc / 20=SHA1-trunc / 32=MD5 / 40=SHA1 / 64=SHA256** |
| random | high entropy, no decode — likely a real key/sig or CSPRNG id |

### 2a. Binary-safe handling — NEVER `echo | cut`
`cut -d:` and `echo` **corrupt** binary and break on real colons/newlines inside decoded bytes. Use byte offsets and files instead:

```bash
TOK='dXNlcg==:cGFzczEyMw==:9d5e0fa1c3b2...'
# split safely on the delimiter into an array (zsh/bash)
printf '%s' "$TOK" | tr ':.|~' '\n\n\n\n' > /tmp/segs
nl -ba /tmp/segs

# decode one segment by BYTE OFFSET, not cut, when the blob is one binary container:
#   take bytes from position N onward:
tail -c +$((OFFSET+1)) /tmp/blob.bin > /tmp/tail.bin
xxd /tmp/tail.bin | head
```

Per-segment decode attempts (each writes bytes to a file, then `xxd` to inspect — printable output ⇒ that codec is right):
```bash
decode() {  # usage: decode <segment>
  s="$1"; pad=$(( (4 - ${#s} % 4) % 4 )); p=$(printf '%*s' "$pad" '' | tr ' ' '=')
  printf '%s' "$s$p" | tr '_-' '/+' | base64 -d 2>/dev/null > /tmp/d.bin && { echo "[b64]";   xxd /tmp/d.bin | head; }
  printf '%s' "$s"    | xxd -r -p     2>/dev/null > /tmp/d.bin && [ -s /tmp/d.bin ] && { echo "[hex]"; xxd /tmp/d.bin | head; }
  printf '%s' "$s" | python3 -c 'import sys,urllib.parse as u;print(u.unquote(sys.stdin.read()))'  # urldecode
}
```
For anything gnarly (nested/binary), route through Python rather than shell:
```python
import base64, binascii
def ladder(b, depth=0):
    if depth > 6: return
    for name, fn in (("b64", lambda x: base64.b64decode(x + b"="*(-len(x)%4))),
                     ("b64url", lambda x: base64.urlsafe_b64decode(x + b"="*(-len(x)%4))),
                     ("hex", binascii.unhexlify)):
        try:
            d = fn(b)
            if d and d != b:
                print("  "*depth, name, "->", d[:80])
                for part in (d.split(b":") if b":" in d else [d]):
                    ladder(part, depth+1)
        except Exception:
            pass
ladder(b"dXNlcjpwYXNzMTIz")
```

## 3. CREDENTIAL / PII CHECK (step 2)

If any segment decodes to identity/secret material it is **two things at once**: a standalone disclosure finding *and* a chain seed.

| Decoded content | Standalone | Chain |
|-----------------|-----------|-------|
| email / username | low-med disclosure | enumeration → `/access-control-idor` |
| `role`/`isAdmin`/`group` | disclosure | tamper target for priv-esc (step 4) |
| `tenant_id`/`org` | disclosure | cross-tenant `/access-control-idor` |
| **live password** | **P1 — sensitive data exposure** | **ATO primitive → `/authentication`** |
| internal host/IP/path | info disclosure | `/ssrf`, `/path-traversal` seed |

A live password in a token is one of the highest-signal opaque-token findings — confirm it actually authenticates (one login with the recovered value, your own authorized account), redact it everywhere, and report.

## 4. SIGNATURE PROBES (step 3) — cheapest first

The token usually ends with a sig/MAC binding the data. Test enforcement before any cracking.

- **(a) Tamper one non-sig byte and replay** — change a single byte of a data field (e.g. flip `userid` 2→3), leave the sig untouched, send. **Accepted ⇒ signature unverified** (server decoded but never checked). This is the single highest-value test: one request, P1/P2 payoff, no crypto.
- **(b) Strip / blank the sig** — send `data:data:` (empty trailing sig) or drop the segment. Accepted ⇒ sig optional.
- **(c) Swap-in your own sig** — paste a sig segment from another token **you legitimately own** onto tampered data. Accepted ⇒ sig not bound to this message (sig reuse / wrong scope).
- **(d) Algo/type down-flip** — if a segment declares an algorithm or token type (`hs256`, `v2`, `signed`), flip it down (`none`, `v1`, `plain`) and blank the sig.

## 5. NO-SECRET FORGE (step 4)

Many home-grown tokens "sign" with a **plain unkeyed hash** of the data — no secret at all. If so, you forge freely.

1. Reconstruct the candidate **message** (the exact concatenation the dev hashed): try `field1:field2`, `field1field2`, with/without delimiters, raw vs base64 forms, with a trailing static string.
2. Sig length tells you the algo: `32 hex = MD5`, `40 = SHA1`, `64 = SHA256` (and 16/20 = truncated).
3. Recompute and compare:

```bash
MSG='user:pass123'; SIG='9d5e0fa1c3b2...'    # the token's sig segment, lowercased hex
for h in md5sum sha1sum sha256sum; do
  out=$(printf '%s' "$MSG" | $h | cut -d' ' -f1)   # cut here is on hex text only — safe
  echo "$h -> $out"; [ "$out" = "$SIG" ] && echo "** MATCH: sig is plain $h of MSG — FORGEABLE, no secret **"
done
```
Match ⇒ forge any token by computing the same hash over your chosen (authorized) identity. No cracking required.

## 6. HMAC CRACK (step 5)

If the sig is a **keyed** MAC (HMAC), recover the secret offline.

1. Recover the exact signed-message format (step 5.1 above).
2. Convert the sig from base64 to hex:
   ```bash
   printf '%s' "$SIG_B64" | base64 -d | xxd -p | tr -d '\n'   # -> sig_hex
   ```
3. Build the hashcat input line `sig_hex:message` and crack with the **generic HMAC** modes:

| hashcat -m | Algorithm | Notes |
|-----------|-----------|-------|
| `50`   | HMAC-MD5    | `key = $pass` |
| `150`  | HMAC-SHA1   | `key = $pass` |
| `1450` | HMAC-SHA256 | `key = $pass` |
| `1750` | HMAC-SHA512 | `key = $pass` |

```bash
echo "${SIG_HEX}:${MSG}" > /tmp/h.txt
hashcat -a 0 -m 1450 /tmp/h.txt <wordlist>
```

- Use the **`key=$pass`** modes above (50/150/1450/1750). **Do NOT** use the `+10` "salt" variants (60/160/1460/1760 — those are `key=$salt`, wrong orientation for a guessable secret), and **do NOT** use `16500` (that is JWT-only and expects the `eyJ…` wire format).
- Cracked secret ⇒ re-sign any tampered identity with `openssl dgst -sha256 -hmac "<secret>"` / `hmac.new` in Python, then replay.

## 7. KEY-SELECTOR INJECTION (step 6)

If a token field **names or indexes the verification key** (`kid`, `kver`, `keyid`, `tenant`, `env`, `region`), it's an injection surface — same family as JWT `kid`:
- **Traversal to a known/empty file:** `kid=../../../../dev/null` → key is empty string → sign with `""`. Or point at a static asset whose bytes you know and use those as the key.
- **SQLi:** if the selector parameterises a DB lookup returning the key, inject to return an attacker-known value, then sign with it.
- **Weak-key selection:** if the selector chooses among multiple keys, pick a `dev`/`test`/legacy key with a known or weak secret.

Route the file/URL-fetch variants to `/ssrf` and `/path-traversal`; the DB variant to `/sql-injection`.

## 8. PREDICTABILITY (step 7)

When there's no usable signature, the token may simply be guessable.
1. Mint **2–3 tokens** (re-login / re-issue) for your authorized account, ideally seconds apart.
2. Diff them byte-by-byte — separate **static** structure from **variable** fields.
3. Hunt:
   - **counter:** a field incrementing by 1 per issue → guess neighbours' tokens.
   - **epoch:** a timestamp field → narrow the search space to the victim's issue window.
   - **low-entropy identity:** a field that's just `userid` or `md5(userid)` → forge directly.
   - **short random:** brute-feasible entropy → estimate keyspace before claiming impact.

```bash
# diff two freshly-issued tokens to spot variable vs static regions
diff <(printf '%s' "$TOK1" | fold -w1) <(printf '%s' "$TOK2" | fold -w1) | head
```
Predictability is only a finding when you **demonstrate** guessing/forging a token that isn't yours (an authorized second test account), not from entropy hand-waving.

## 9. Worked example (full)

Cookie: `session=dXNlcg==:cGFzczEyMw==:9d5e0fa1c3b2e4f6...`

1. **Decode ladder:** split on `:` → 3 segments. Seg1 `dXNlcg==` →b64→ `user`; Seg2 `cGFzczEyMw==` →b64→ `pass123`; Seg3 = 64-char hex (SHA256-shaped sig).
2. **Credential check:** seg2 is a **live password** → P1 disclosure + ATO primitive (`/authentication`).
3. **Signature probe (b):** issue a token for your second test account `victim` as `base64(victim)::` (empty sig) → server returns victim's session ⇒ **signature unverified**. P1 ATO/forge.
4. **(No-secret forge, confirming):** `printf '%s' 'user:pass123' | sha256sum` matches seg3 ⇒ sig is just `sha256(user:pass)`, freely forgeable even if it *were* checked.

Result: one token yields a credential-disclosure finding **and** a signature-bypass/forgery chain. Report the chain (decoded password → empty/forged-sig acceptance → full ATO), redacting the recovered password, and log to `./_EXPLOIT/`.

## 10. Prevention (for triage / report remediation advice)
- Don't put secrets/PII in tokens; use opaque random identifiers backed by server-side session state (high-entropy CSPRNG).
- If self-contained, **MAC the whole token** with a strong server-only key and **verify before use** (constant-time compare) — never an unkeyed hash.
- Pin the algorithm and message format server-side; don't let token fields select the algorithm or key.
- Validate/parameterise any key-selector field; guard against traversal and SQLi.
- Bind the token to identity and add expiry + revocation.
