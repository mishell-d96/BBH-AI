---
name: essential-skills
description: "Cross-cutting: obfuscate payloads to bypass input filters/WAFs (URL/double-URL/HTML-entity/unicode/hex/octal encoding, SQL CHAR(), layering) and use a scanner to support manual testing. Use when a payload is blocked/filtered/sanitized or a WAF rejects an attack."
---

# Essential Skills — Encoding/Obfuscation & Scanner-Assisted Testing

Cross-cutting techniques used alongside the specific vuln skills (XSS, SQLi, etc.).
Encoding is a **bypass aid**, not a vulnerability. A scanner is a **breadth tool**, not a verdict.

## When to use
- A payload that *should* fire is blocked, stripped, escaped, or returns a WAF/403 page → try encoding/obfuscation.
- You want to broaden coverage of a request/parameter during focused manual testing → scanner-assisted.
- You are staring at unusual behavior and don't yet know the vuln class → identify, then route to the right skill.

## Encoding & obfuscation
Filters fail when **the decoding done during inspection differs from the decoding done by the backend/browser**. Find that gap.

- **URL encoding** — `%XX`. Some WAFs fail to URL-decode before inspecting. `<` → `%3C`.
- **Double URL encoding** — encode the `%` as `%25` (`%3C` → `%253C`). Works when the WAF decodes once but the backend decodes twice.
- **HTML entities** — named (`&colon;`), decimal (`&#58;`), hex (`&#x3a;`). Useful inside HTML contexts. Leading-zero padding (`&#00000000000058;`) defeats naive parsers.
- **XML numeric refs** — `&#x53;ELECT` decodes server-side to `SELECT` after WAF inspection.
- **Unicode escapes** — `a` → `a`; ES6 `\u{61}` with optional leading zeros `\u{00061}`. Valid in JS string/eval contexts.
- **Hex escapes** — `\x61` → `a` in JS strings; SQL `0x53454c454354` → `SELECT`.
- **Octal escapes** — `\141` → `a` in JS strings.
- **SQL CHAR()** — `CHAR(83)+CHAR(69)+...` rebuilds a blocked keyword at runtime; the literal keyword never appears.
- **Layering** — combine encodings for multi-stage decode chains, e.g. `javascript:&bsol;alert(1)` (HTML-decode `&bsol;`→`\`, then JS unicode-decode `a`→`a`).

**How to choose:** map the injection context (URL/query, HTML body, HTML attribute, JS string, SQL, XML) → that context's decoder is the one to abuse. Layer encodings to match the decode order between WAF and sink. See `reference.md` for the full set.

## Identifying unknown vulnerabilities
Real targets won't tell you the bug class. Work from behavior:
- Reflected/stored input, error messages, timing deltas, differential responses, content-type/encoding quirks → these are signals.
- Probe with benign markers first, observe how/where they surface, infer the sink, then pull in the matching skill (XSS, SQLi, SSTI, path traversal, etc.).
- A single underlying bug shows up in subtly different shapes; adapt the technique, don't pattern-match a single lab.

## Scanner-assisted manual testing
Use a scanner to triage breadth on requests your intuition flagged — never as a substitute for thinking.
- **Scan a single request** (active scan) instead of a full crawl to slash scan time and focus effort.
- **Custom insertion points** — highlight one parameter/header and scan only it; use scan-manual-insertion-point for headers/non-standard locations the scanner overlooks.
- **Non-standard structures** — for delimited values like `user=048857-carlos`, highlight just `carlos`, or define insertion points in Intruder before scanning.
- **ALWAYS manually validate** every finding end-to-end before it counts. Per CLAUDE.md: only PROVEN, impactful vulns ship.

### CLI scanner-assist (Burp is one option, not the only one)
Map intent → installed tool. Every hit is a **LEAD to hand-confirm**, never a verdict. Keep scanning **ONE insertion point, not a full crawl**.
- **Single-request breadth** — `nuclei -u <url> -tags exposure,misconfig -rl <cap>` (respect scope rate cap via `-rl`).
- **DAST triage** — `katana -u <t> | nuclei -dast` (hits are LEADS; reproduce each by hand).
- **Suspected XSS param** — `dalfox url '<url>?p=FUZZ' --skip-bav --only-poc` (`--skip-bav` drops noisy basic-checks; `--only-poc` prints just confirmed PoCs).
- **Suspected SQLi param** — `sqlmap -u '<url>' -p <param> --batch --random-agent --level 2 --risk 1`. Escalate `--level`/`--risk` only as a fallback; `--crawl --level=5 --risk=3` is noise.
- **Param discovery** — `arjun -u <url> -m GET` (arjun's `-m` takes ONE method; run `-m POST` separately for write endpoints).

## Differential-probe triage (cross-cutting)
Every injection class is confirmed by a probe **plus its NEUTRAL twin** — the control isolates the parser from coincidence and kills false positives.
- **SQLi** — break `'` vs heal `''` (broken errors/differs, healed restores baseline).
- **Path traversal** — legit-file fetch vs `../`-traversal of the same target.
- **XSS** — canary present (correct context) vs canary absent.
- **Blind** — time-delay probe vs zero-delay control, or OAST callback vs no-callback.

**"Do you have a neutral control?" must be answered before any finding enters the panel gate.** No control → not yet confirmed.

### Probe-delivery hygiene (kills false negatives)
A "not reflected / looks encoded" result is often **your shell mangling the probe**, not the server filtering it. Before concluding a sink is safe, make sure the bytes you *think* you sent actually reached the server intact.
- **Never put injection metacharacters (`< > & ' " # space`) inline in a curl URL** — the shell/URL parser eats or splits them (`&` truncates the query, `<>` get quote-stripped, `#` starts a fragment). Use **`curl -G --data-urlencode 'param=<svg onload=alert(1)>'`** for GET, plain `--data-urlencode` for POST. curl encodes the value, the server sees it whole.
- **Confirm with an echo control:** send a plain unique marker (`zq9mark`) first — if *that* reflects but the metachar payload "doesn't," the difference is delivery/encoding, not a filter. Re-send via `--data-urlencode` before believing a negative.
- **zsh reserved vars** (`status`, `path`, `pipestatus`, `argv`) are read-only — using them as loop/capture variables aborts the loop. Use `st`, `code`, etc.
- A false negative here = a missed bug. When a sink *should* reflect and doesn't, suspect the harness before the target.

### Getting an OAST host
Standardize the **OAST (out-of-band) callback as the DEFAULT blind-confirmation channel** — it is jitter-immune binary proof. **Time-delay is the FALLBACK only** and REQUIRES a paired zero-delay control repeated **3×**: report only if all 3 TRUE-probes are slow AND all 3 control-probes are fast.
- Live domain: `interactsh-client -v` (installed at `~/go/bin/interactsh-client`) — watch for DNS/HTTP hits.
- Zero-install fallback: use a public `oast.fun` / `oast.pro` host.

## Encoding quick table
| Type | Example in → out |
|------|------------------|
| URL | `%3C` → `<` |
| Double URL | `%253C` → `%3C` → `<` |
| HTML decimal | `&#58;` → `:` |
| HTML hex | `&#x3a;` → `:` |
| HTML padded | `&#000058;` → `:` |
| Unicode | `a` / `\u{61}` → `a` |
| Hex (JS) | `\x61` → `a` |
| Octal (JS) | `\141` → `a` |
| SQL hex literal | `0x53454c454354` → `SELECT` |
| SQL CHAR() | `CHAR(83)+CHAR(69)...` → `SELECT` |

(Full set with combining recipes in `reference.md`.)

## Don't
- Don't report unvalidated scanner output — that is noise and violates the doctrine.
- Don't treat "an encoding got through" as a finding; it only matters if it produces a proven, impactful vuln.
- Don't blast a target with every encoding blindly — reason about the decode chain first.

## Deep reference
See `reference.md` plus:
- https://portswigger.net/web-security/essential-skills
- https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
- https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing
