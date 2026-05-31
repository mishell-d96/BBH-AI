# Path Traversal — Reference

Comprehensive technique reference for file path traversal (directory traversal / LFI).
Source: https://portswigger.net/web-security/file-path-traversal

## What it is
Path traversal (a.k.a. directory traversal) lets an attacker read arbitrary files on the
server running the application — application code and data, backend credentials, OS files —
by manipulating a parameter that is used to build a filesystem path. In some cases an
attacker can also *write* arbitrary files, leading to full server takeover.

A vulnerable endpoint typically does something like:
`https://insecure-website.com/loadImage?filename=218.png` and returns the file at
`/var/www/images/218.png`. If `filename` is not validated, `../` sequences escape the
images directory.

## Core attack
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
Resolves `/var/www/images/../../../etc/passwd` -> `/etc/passwd`. On Windows, `..\` is also
a valid traversal sequence: `..\..\..\windows\win.ini`.

## Bypass techniques

### 1. Absolute path
If the app strips traversal sequences but otherwise uses the input directly, supply an
absolute path and skip traversal entirely:
```
filename=/etc/passwd
```

### 2. Nested traversal sequences
If the app strips `../` (and `..\`) *non-recursively* — a single pass — use nested
sequences that collapse back into a valid traversal after stripping:
```
....//
....\/
```
After the inner `../` (or `..\`) is removed, `....//` becomes `../`.

### 3. URL encoding (single and double)
If the app filters the literal characters, encode them. The web server / framework may
URL-decode after the filter runs.
- Single URL encoding of `../`:
  - `%2e%2e%2f`  (`../`)
  - `..%2f`
  - `%2e%2e/`
- Double URL encoding (decoded twice along the request path):
  - `%252e%252e%252f`  -> `%2e%2e%2f` -> `../`
- Non-standard / overlong UTF-8 encodings accepted by some platforms:
  - `..%c0%af`   (overlong-encoded `/`)
  - `..%ef%bc%8f` (fullwidth solidus)
Mix and match (e.g. encode only the slash, or only the dots) to slip past partial filters.

### 4. Validation of start of path (required base folder)
Some apps require the supplied value to begin with the expected base directory. Satisfy the
check, then traverse out:
```
filename=/var/www/images/../../../etc/passwd
```

### 5. Required file extension + null byte
Some apps require the value to end in an expected extension (e.g. `.png`). On older
platforms (notably legacy PHP and some Java/C runtimes), a null byte terminates the string
at the filesystem layer, so the appended/required extension is ignored:
```
filename=../../../etc/passwd%00.png
```
The application sees a `.png` suffix; the OS opens `/etc/passwd`.

## Common obstacles (and what they look like)
- **Sequence stripping**: `../` removed -> try nested `....//`, encoding, or absolute path.
- **Recursive stripping**: nested fails -> rely on encoding / absolute path.
- **Single decode then filter, or filter then decode**: try single vs double encoding to
  land the literal `../` *after* the filter stage.
- **Allowlist / canonicalization**: input canonicalized and checked against base dir — often
  not bypassable; pivot to other params.
- **Extension enforcement**: append `%00`, or look for path-info tricks (`/etc/passwd/.`,
  appended-extension truncation) on the specific stack.
- **WAF blocking keywords** (`etc`, `passwd`): use encoding, mixed case on case-insensitive
  filesystems, or alternate target files.

## Linux vs Windows targets
- **Linux/Unix**: separator `/`, traversal `../`. Canonical proof file: `/etc/passwd`
  (world-readable; format `name:x:uid:gid:...`). Others: `/etc/hostname`, `/etc/issue`,
  app configs, `/proc/self/environ` (env vars; can aid LFI->RCE).
- **Windows**: separators `\` and `/` both work; traversal `..\` or `../`. Canonical proof:
  `C:\windows\win.ini` (sections `[fonts]`, `[extensions]`), `\windows\system.ini`.

## Chaining to RCE (LFI escalation, only where in scope)
- **Log poisoning**: inject PHP/code into a log (e.g. User-Agent into access log), then
  include the log file.
- **PHP wrappers/filters**: `php://filter/convert.base64-encode/resource=...` to exfiltrate
  source; `data://`, `expect://` where enabled.
- **Session files / uploaded files**: include attacker-controlled paths.
Treat write-primitive or RCE chains as Critical; keep PoCs minimal and safe.

## Prevention (for triage / reporting context)
Defenders should use layered defense:
1. **Avoid** passing user input to filesystem APIs where possible.
2. **Validate** against an allowlist of permitted values (ideally alphanumeric only).
3. **Canonicalize and verify**: after validation, append input to the base directory, use a
   platform filesystem API to canonicalize the resulting path, then verify the canonical
   path still starts with the expected base directory. Reject otherwise.

## Reporting
Demonstrate impact with a single clearly out-of-scope sensitive file. Note depth, exact
payload, and the defense bypassed. Avoid mass file enumeration / exfiltration.
