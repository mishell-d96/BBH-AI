---
name: essential-skills
description: >-
  Cross-cutting techniques for obfuscating payloads to bypass input filters/WAFs and for using a
  scanner to support (not replace) manual testing. Use when: a payload is being blocked, filtered,
  stripped, or sanitized; you suspect a WAF/firewall is rejecting an attack; you need encoding or
  obfuscation (URL encoding, double-URL encoding, HTML entities, named entities, decimal/hex
  numeric refs, unicode escapes \u, ES6 \u{}, hex \x escapes, octal escapes, SQL CHAR(), 0x hex
  literals, leading-zero tricks, mixing/layering encodings); you want to defeat a keyword or
  character blocklist; you want to reason about which decoding the target performs and in what
  order; you are supplementing manual testing with a scanner; you need custom insertion points,
  scanning a single request/parameter, or scanning non-standard data structures. Keywords: WAF
  bypass, filter bypass, blocklist evasion, encoding, obfuscation, sanitization bypass, scanner-
  assisted testing, manual validation.
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
