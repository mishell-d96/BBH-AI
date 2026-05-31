# Essential Skills — Reference

Cross-cutting techniques: obfuscation/encoding to bypass input filters and WAFs, identifying
unknown vulnerabilities from behavior, and using a scanner to support (never replace) manual
testing. Encoding is a bypass aid; a scanner is a breadth tool. Only PROVEN, impactful vulns ship.

Sources:
- https://portswigger.net/web-security/essential-skills
- https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings
- https://portswigger.net/web-security/essential-skills/using-burp-scanner-during-manual-testing

---

## 1. Core principle: decode-discrepancy

Input filters (WAFs, sanitizers, blocklists) inspect a request and then pass it on. The backend
server, database, or browser then decodes it again before using it. **A bypass exists whenever the
decoding performed during inspection differs from the decoding performed at the sink** — in type,
depth, or order.

Two questions drive every obfuscation attempt:
1. Which decoder operates at the sink (URL? HTML? JS string? SQL? XML?)
2. How many times / in what order is decoding applied between the filter and the sink?

Encode your payload so it is **opaque to the filter but valid to the sink**.

---

## 2. Encoding catalogue with concrete examples

### 2.1 URL encoding
Reserved characters become `%` + 2 hex digits.

- `<img src=x onerror=alert(1)>` → `%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`
- Bypass: a WAF that does not URL-decode (or decodes incompletely) before matching will miss the
  payload that the application server then decodes normally.
- Partial encoding (encode only the flagged characters, e.g. just `<` and `>`) is often enough and
  keeps the payload smaller.

### 2.2 Double URL encoding
Encode the percent sign itself: `%` → `%25`.

- `%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` → `%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E`
- Bypass: WAF decodes once and sees harmless literal text (`%3Cimg...`); a backend that decodes a
  second time recovers the live payload. Triple-encoding works the same way against triple decoders.

### 2.3 HTML encoding
Replace characters with HTML entities. Three forms:
- Named: `&colon;` `&lt;` `&bsol;` (`\`)
- Decimal numeric: `&#58;` → `:`
- Hex numeric: `&#x3a;` → `:`

Example (XSS in an HTML context): `<img src=x onerror="&#x61;lert(1)">` — the `a` of `alert`
is `&#x61;`, so a blocklist for the literal string `alert` does not match, yet the browser decodes
the attribute value and runs `alert(1)`.

**Leading-zero / padding trick:** numeric references tolerate arbitrary leading zeros.
`&#00000000000058;alert(1)` still decodes to `:`. Many filters truncate or fail to normalise the
padding and miss it. Trailing semicolon is sometimes optional in browsers (`&#58alert` may work).

### 2.4 XML encoding
XML parsers decode numeric character references inside element/attribute content just like HTML.

- `<storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>` — `&#x53;` → `S`,
  reconstructing `SELECT` server-side after the WAF has inspected the (apparently benign) request.
- Useful for SOAP/XML APIs and any endpoint that parses an XML body before reaching a SQL/command sink.

### 2.5 Unicode escaping (JavaScript)
- 4-digit form: `a` → `a`. Example: `eval("alert(1)")`.
- ES6 variable-length form: `\u{61}` → `a`, with optional leading zeros `\u{00000000061}`.
- Valid only where a JS string/identifier is later evaluated (e.g. inside `eval`, template sinks,
  `javascript:` URLs). Defeats blocklists matching the literal keyword.

### 2.6 Hex escaping
- JavaScript string: `\x61` → `a`. Example: `eval("\x61lert(1)")`.
- SQL hex literal: `0x53454c454354` is interpreted as the byte string `SELECT` in MySQL/MSSQL
  contexts, so the keyword never appears in clear text in the request.

### 2.7 Octal escaping (JavaScript)
- `\141` → `a`. Example: `eval("\141lert(1)")`. Same use cases as hex/unicode escapes in JS strings.

### 2.8 SQL CHAR() construction
Build a blocked keyword from character codes so the literal string is absent from the request:
- `CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)` → `SELECT` (MSSQL `+` concat)
- MySQL: `CHAR(83,69,76,69,67,84)` or `CONCAT(CHAR(83),...)`
- Oracle: `CHR(83)||CHR(69)||...`
Combine with `0x...` hex literals where string-builders are themselves filtered.

### 2.9 Combining / layering encodings
Match a multi-stage decode chain by stacking encodings in the order the sinks unwind them.

Example: `<a href="javascript:&bsol;alert(1)">`
1. Browser HTML-decodes the attribute: `&bsol;` → `\`, giving `javascript:alert(1)`.
2. The `javascript:` URL is parsed as JS; `a` unicode-decodes to `a` → `alert(1)` executes.

The order matters: encode for the **last** decoder innermost, the **first** decoder outermost.
Other useful combos:
- URL-encode an HTML-entity payload so it survives both a URL decode and an HTML parse.
- Double-URL-encode characters that a WAF normalises once but the app decodes twice.

---

## 3. Choosing encodings per parser / WAF

| Sink / context | Decoder to abuse | Go-to encodings |
|----------------|------------------|-----------------|
| URL query/path | URL decode | URL, double/triple URL |
| HTML body / text node | HTML parser | decimal/hex entities, padded entities |
| HTML attribute | HTML parser | entities (incl. named like `&bsol;`) |
| `javascript:` URL / JS string | HTML parse then JS | layered entity + `\u`/`\x`/octal |
| SQL string/keyword | SQL engine | `CHAR()`/`CHR()`, `0x` hex literal |
| XML/SOAP body | XML parser | numeric char refs `&#xNN;` |

Tactics against WAFs:
- Probe for **decode depth** by sending single/double/triple-encoded benign markers and watching
  which form reaches the app intact.
- Use **leading zeros** and optional separators to exploit lax normalisation.
- Use **partial encoding** — only obfuscate the specific characters that trip the rule.
- Mix **case** and insert **inline comments** (`/**/`, `SEL/**/ECT`) where the engine tolerates them.
- Confirm the **decode order** before layering; a wrong order produces inert garbage, not a bypass.

---

## 4. Identifying unknown vulnerabilities (methodology)

Lab exercises show one variation each; real targets present subtly different occurrences of the
same underlying bug. Work from observed behavior, not from a known label:

1. **Map inputs and sinks.** Note every place input is reflected, stored, logged, parsed, or used
   in a query/command.
2. **Send benign, distinctive markers** (e.g. a unique token) and observe where and how they
   surface — raw, encoded, in errors, in headers, in timing.
3. **Read the anomaly.** Differential responses, stack traces, encoding changes, timing deltas, and
   content-type quirks each point toward a class (XSS, SQLi, SSTI, path traversal, SSRF, deser, etc.).
4. **Form a hypothesis, then route** to the matching vuln skill and use its proven techniques —
   adapting payloads/encodings to the observed filtering.
5. **Iterate** with obfuscation from sections 2–3 when a textbook payload is blocked.

---

## 5. Using a scanner during manual testing

A scanner widens coverage on requests your judgment has flagged. It never decides what is real.

### 5.1 Scan a single request
Instead of crawling the whole site, run an **active scan on one interesting request** using default
config. This audits just that request, massively cutting scan time and letting you keep digging
manually elsewhere while the scan runs.

### 5.2 Custom insertion points
- Highlight a single parameter or value and **scan only that insertion point** to focus the audit.
- For locations the scanner ignores by default (custom headers, non-standard fields), use a
  manual-insertion-point capability/extension to mark them explicitly.

### 5.3 Non-standard data structures
The scanner handles JSON and common formats well but struggles with custom delimiters.
- For `user=048857-carlos`, highlight just the meaningful segment (`carlos`) and scan it alone.
- Or define **multiple insertion points in Intruder** within the compound value, then scan.

### 5.4 Manual-validation discipline (non-negotiable)
- Treat scanner output as **leads**, not findings. Reproduce every issue by hand, end-to-end.
- Build a **minimal, safe PoC** that proves real impact (per CLAUDE.md), then log proven exploits to
  `./_EXPLOIT/`.
- **Never submit raw scanner results.** Unvalidated findings are noise and violate the doctrine
  (impact-first, signal-over-noise, proven vulns only).
- Encoding getting past a filter is **not** itself a vulnerability — it only matters when it yields a
  proven, impactful bug at a real sink.
